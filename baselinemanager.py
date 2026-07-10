"""Device baseline capture & diff for dynamic analysis.

Snapshot the device's observable state (installed packages, running processes,
network sockets, security-sensitive settings, and files in watched directories),
then diff two snapshots to see what a sample changed after install/launch. This
is the before/after technique that surfaces a dropper's payload, the C2 socket,
and banker/overlay indicators (device-admin, accessibility, notification
listeners, default SMS/dialer) in one step.

Snapshots are per-run, per-device artifacts and live in the host workspace
(workspace/baseline/<serial>_<label>.json) alongside pulled APKs and pcaps.
They are NOT knowledge cards: a persistence path that recurs across a family is
worth a KVault card, but the raw snapshot is not.

All commands run against the currently-active device (respects select_device);
the manager holds the AdbDeviceManager and reads its live `.device` each call.
This is read-only: it never changes device state, so no undo is returned.
"""

import ipaddress
import json
from pathlib import Path

from apkutils import sanitize_label

_HERE = Path(__file__).parent
DEFAULT_WORKSPACE = _HERE / "workspace"

# Linux TCP states as reported in /proc/net/tcp{,6} (hex, column 4).
_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
    "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
    "0A": "LISTEN", "0B": "CLOSING",
}
# States that indicate an outbound connection to a remote host (C2 candidates).
_OUTBOUND_STATES = {"ESTABLISHED", "SYN_SENT", "SYN_RECV", "CLOSE_WAIT",
                    "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "LAST_ACK", "CLOSING"}

# Secure settings whose change is a strong malware signal.
_WATCHED_SETTINGS = [
    ("secure", "enabled_accessibility_services"),
    ("secure", "enabled_notification_listeners"),
    ("secure", "sms_default_application"),
    ("secure", "dialer_default_application"),
    ("secure", "default_input_method"),
    ("global", "install_non_market_apps"),
]

# Default directories to inventory for dropped files (kept small; /sdcard as a
# whole is too large/noisy). Analysts can override per capture.
_DEFAULT_WATCH_DIRS = ["/data/local/tmp", "/sdcard/Download", "/sdcard/Android/data"]


def _hex_to_ip_port(hexaddr: str) -> str:
    """Convert a /proc/net 'HEXIP:HEXPORT' token to 'ip:port'."""
    try:
        ip_hex, port_hex = hexaddr.split(":")
        port = int(port_hex, 16)
        if len(ip_hex) == 8:  # IPv4, little-endian
            raw = bytes.fromhex(ip_hex)[::-1]
            ip = str(ipaddress.IPv4Address(raw))
        elif len(ip_hex) == 32:  # IPv6: 4 little-endian 32-bit words
            words = [ip_hex[i:i + 8] for i in range(0, 32, 8)]
            raw = b"".join(bytes.fromhex(w)[::-1] for w in words)
            ip = str(ipaddress.IPv6Address(raw))
        else:
            return hexaddr
        return f"{ip}:{port}"
    except (ValueError, ipaddress.AddressValueError):
        return hexaddr


class BaselineManager:
    def __init__(self, device_manager, output_dir=None) -> None:
        self.dm = device_manager
        base = Path(output_dir) if output_dir else DEFAULT_WORKSPACE
        self.dir = base / "baseline"

    # -- helpers -----------------------------------------------------------
    def _sh(self, cmd: str, timeout: float = 30) -> str:
        """Run a shell command on the active device (timeout-bounded); '' on error.

        A stuck/slow command must not hang the whole capture, so every call is
        bounded and failures degrade to an inline error marker.
        """
        try:
            return self.dm.device.shell(cmd, timeout=timeout) or ""
        except Exception as e:
            return f"<error: {e}>"

    def _serial(self) -> str:
        try:
            return self.dm.device.serial or "device"
        except Exception:
            return "device"

    def _snapshot_path(self, label: str) -> Path:
        return self.dir / f"{sanitize_label(self._serial())}_{sanitize_label(label)}.json"

    def _resolve_snapshot(self, ref: str) -> dict:
        """Load a snapshot given a label (for the active device) or a JSON path."""
        p = Path(ref)
        if p.suffix.lower() == ".json" and p.is_file():
            path = p
        else:
            path = self._snapshot_path(ref)
        if not path.is_file():
            raise RuntimeError(
                f"Baseline snapshot not found: {path}. Capture it first with "
                f"capture_baseline(label='{ref}').")
        return json.loads(path.read_text(encoding="utf-8"))

    # -- collectors --------------------------------------------------------
    def _packages(self) -> dict:
        """All packages, plus third-party packages mapped to their APK path."""
        all_pkgs = sorted(
            line[8:].strip()
            for line in self._sh("pm list packages").splitlines()
            if line.startswith("package:"))
        third_party = {}
        for line in self._sh("pm list packages -f -3").splitlines():
            line = line.strip()
            if not line.startswith("package:"):
                continue
            body = line[8:]
            # format: /path/base.apk=com.pkg
            if "=" in body:
                apk_path, pkg = body.rsplit("=", 1)
                third_party[pkg.strip()] = apk_path.strip()
        return {"all": all_pkgs, "third_party": third_party}

    def _processes(self) -> list[str]:
        """Running process names (last column of `ps -A`)."""
        names = set()
        lines = self._sh("ps -A").splitlines()
        for line in lines[1:]:  # skip header
            parts = line.split()
            if parts:
                names.add(parts[-1])
        return sorted(names)

    def _sockets(self) -> list[dict]:
        """Parse /proc/net/{tcp,tcp6,udp,udp6} into {proto,local,remote,state}."""
        out = []
        for proto in ("tcp", "tcp6", "udp", "udp6"):
            text = self._sh(f"cat /proc/net/{proto} 2>/dev/null")
            for line in text.splitlines()[1:]:  # skip header
                parts = line.split()
                if len(parts) < 4:
                    continue
                local = _hex_to_ip_port(parts[1])
                remote = _hex_to_ip_port(parts[2])
                state = _TCP_STATES.get(parts[3].upper(), parts[3]) \
                    if proto.startswith("tcp") else "-"
                out.append({"proto": proto, "local": local,
                            "remote": remote, "state": state})
        return out

    def _device_admins(self) -> list[str]:
        """Active device-admin component names (dumpsys device_policy)."""
        admins = set()
        text = self._sh("dumpsys device_policy")
        for line in text.splitlines():
            line = line.strip()
            # lines like "Admin ComponentInfo{com.pkg/com.pkg.Receiver}"
            if line.startswith("Admin ") and "ComponentInfo{" in line:
                comp = line.split("ComponentInfo{", 1)[1].rstrip("}")
                admins.add(comp.strip())
        return sorted(admins)

    def _settings(self) -> dict:
        out = {}
        for ns, key in _WATCHED_SETTINGS:
            val = self._sh(f"settings get {ns} {key}").strip()
            out[f"{ns}/{key}"] = val
        return out

    def _files(self, watch_dirs: list[str]) -> dict:
        """Inventory files under each watched directory (path -> size).

        One bounded, depth-limited, capped `find` per dir. Sizes come from the
        same command (`-exec ls`), never a per-file `stat` loop -- that was N
        round-trips and could itself time out on a large tree.
        """
        result = {}
        for d in watch_dirs:
            files = {}
            # Depth-limited + capped so a huge tree can neither hang nor flood.
            out = self._sh(
                f"find {d} -maxdepth 4 -type f 2>/dev/null | head -n 800")
            for path in out.splitlines():
                path = path.strip()
                if not path or path.startswith("<error"):
                    continue
                files[path] = ""  # presence is the signal; size omitted for speed
            result[d] = files
        return result

    # -- public API --------------------------------------------------------
    def capture_baseline(self, label: str = "pre", watch_dirs=None) -> str:
        """Snapshot the active device's state and save it to the workspace.

        Args:
            label: snapshot name (e.g. 'pre' before install, 'post' after).
            watch_dirs: directories to inventory for dropped files
                        (defaults to /data/local/tmp, /sdcard/Download,
                        /sdcard/Android/data).
        Returns a summary + the saved snapshot path (use the label in
        diff_baseline).
        """
        dirs = list(watch_dirs) if watch_dirs else list(_DEFAULT_WATCH_DIRS)
        snap = {
            "serial": self._serial(),
            "label": label,
            "device_time": self._sh("date").strip(),
            "packages": self._packages(),
            "processes": self._processes(),
            "sockets": self._sockets(),
            "device_admins": self._device_admins(),
            "settings": self._settings(),
            "watch_dirs": dirs,
            "files": self._files(dirs),
        }
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self._snapshot_path(label)
        path.write_text(json.dumps(snap, indent=2, ensure_ascii=False),
                        encoding="utf-8")

        n_files = sum(len(v) for v in snap["files"].values())
        return (
            f"Baseline '{label}' captured for {snap['serial']} "
            f"@ {snap['device_time']}\n"
            f"  packages: {len(snap['packages']['all'])} "
            f"({len(snap['packages']['third_party'])} third-party)\n"
            f"  processes: {len(snap['processes'])} | "
            f"sockets: {len(snap['sockets'])} | "
            f"device-admins: {len(snap['device_admins'])}\n"
            f"  watched files: {n_files} across {len(dirs)} dir(s)\n"
            f"  saved: {path}\n"
            f"  -> capture again after running the sample, then "
            f"diff_baseline('{label}', '<post-label>').")

    def diff_baseline(self, before: str = "pre", after: str = "post") -> str:
        """Diff two snapshots (labels for the active device, or JSON paths).

        Reports what appeared after the sample ran: new packages (dropped
        payload), new remote sockets (C2), new device-admins / accessibility /
        notification listeners / default-SMS or dialer changes (banker/overlay),
        new processes, and new files in watched directories.
        """
        b = self._resolve_snapshot(before)
        a = self._resolve_snapshot(after)
        lines = [f"Baseline diff: '{b.get('label', before)}' -> "
                 f"'{a.get('label', after)}' (device {a.get('serial', '?')})",
                 f"  {b.get('device_time', '?')}  ->  {a.get('device_time', '?')}"]

        # Packages
        b_all, a_all = set(b["packages"]["all"]), set(a["packages"]["all"])
        added_pkgs = sorted(a_all - b_all)
        removed_pkgs = sorted(b_all - a_all)
        a_tp = a["packages"]["third_party"]
        if added_pkgs:
            lines.append("\n[+] NEW PACKAGES (dropped/installed):")
            for p in added_pkgs:
                tag = f"  path={a_tp[p]}" if p in a_tp else ""
                lines.append(f"    + {p}{tag}")
        if removed_pkgs:
            lines.append("\n[-] removed packages:")
            lines += [f"    - {p}" for p in removed_pkgs]

        # Sockets — new remote endpoints are the C2 signal.
        def _remote_key(s):
            return (s["proto"], s["remote"], s["state"])

        def _is_real_remote(s):
            r = s.get("remote", "")
            host = r.rsplit(":", 1)[0] if ":" in r else r
            port = r.rsplit(":", 1)[1] if ":" in r else "0"
            return host not in ("0.0.0.0", "::", "") and port != "0"

        b_socks = {_remote_key(s) for s in b["sockets"]}
        new_remote = [s for s in a["sockets"]
                      if _remote_key(s) not in b_socks
                      and _is_real_remote(s)
                      and s["state"] in _OUTBOUND_STATES]
        new_listen = [s for s in a["sockets"]
                      if _remote_key(s) not in b_socks and s["state"] == "LISTEN"]
        if new_remote:
            lines.append("\n[+] NEW REMOTE SOCKETS (C2 candidates):")
            for s in sorted(new_remote, key=lambda s: s["remote"]):
                lines.append(f"    + {s['proto']} -> {s['remote']} ({s['state']})")
        if new_listen:
            lines.append("\n[+] NEW LISTENING SOCKETS:")
            for s in sorted(new_listen, key=lambda s: s["local"]):
                lines.append(f"    + {s['proto']} {s['local']} (LISTEN)")

        # Security-sensitive additions.
        new_admins = sorted(set(a["device_admins"]) - set(b["device_admins"]))
        if new_admins:
            lines.append("\n[+] NEW DEVICE ADMINS (persistence/anti-uninstall):")
            lines += [f"    + {c}" for c in new_admins]

        changed = []
        for key, a_val in a["settings"].items():
            b_val = b["settings"].get(key, "")
            if a_val != b_val:
                changed.append((key, b_val, a_val))
        if changed:
            lines.append("\n[+] CHANGED SECURITY SETTINGS "
                         "(accessibility/notif-listener/default SMS·dialer):")
            for key, bv, av in changed:
                lines.append(f"    ~ {key}: '{bv}' -> '{av}'")

        # Processes
        new_procs = sorted(set(a["processes"]) - set(b["processes"]))
        if new_procs:
            lines.append("\n[+] new processes:")
            lines += [f"    + {p}" for p in new_procs]

        # Files
        file_lines = []
        for d, a_files in a.get("files", {}).items():
            b_files = b.get("files", {}).get(d, {})
            added = sorted(set(a_files) - set(b_files))
            for f in added:
                size = a_files.get(f) or ""
                file_lines.append(
                    f"    + {f}" + (f" ({size} bytes)" if size else ""))
        if file_lines:
            lines.append("\n[+] NEW FILES in watched dirs (dropped payloads):")
            lines += file_lines

        if len(lines) == 2:
            lines.append("\n(no observable changes between the two snapshots)")
        return "\n".join(lines)
