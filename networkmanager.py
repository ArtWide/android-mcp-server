"""Network traffic capture via mitmproxy (mitmdump).

Runs mitmdump as a long-lived child of the (long-lived) MCP server, routes the
USB-connected device's traffic through it with `adb reverse` + a device proxy
setting, and exposes the captured flows. Reading flows uses a JSONL file written
by scripts/mitm_addon.py, so the project venv does not need the mitmproxy
package (mitmdump bundles its own).
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

_HERE = Path(__file__).parent
DEFAULT_WORKSPACE = _HERE / "workspace"
_ADDON = _HERE / "scripts" / "mitm_addon.py"

_INSTALL_HINT = (
    "mitmdump not found. Install mitmproxy (https://mitmproxy.org/) and ensure "
    "mitmdump is on PATH (e.g. C:/Program Files/mitmproxy/bin)."
)


def _discover_mitmdump() -> str | None:
    for name in ("mitmdump", "mitmdump.exe"):
        found = shutil.which(name)
        if found:
            return found
    common = [
        Path("C:/Program Files/mitmproxy/bin/mitmdump.exe"),
        Path.home() / "AppData" / "Local" / "Programs" / "mitmproxy" / "mitmdump.exe",
        Path("/usr/local/bin/mitmdump"),
    ]
    for c in common:
        if c.is_file():
            return str(c)
    return None


class NetworkCaptureManager:
    def __init__(self, device_manager, output_dir: str | None = None) -> None:
        self.device_manager = device_manager
        self.workdir = (Path(output_dir) if output_dir else DEFAULT_WORKSPACE) / "network"
        self._proc: subprocess.Popen | None = None
        self._port: int | None = None
        self._flowfile: Path | None = None

    def _serial(self) -> str:
        return self.device_manager.device.serial

    def _adb(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["adb", "-s", self._serial(), *args],
                              capture_output=True, text=True)

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start_capture(self, port: int = 8080) -> str:
        if self.is_running():
            return f"Capture already running on port {self._port}. Stop it first."

        mitmdump = _discover_mitmdump()
        if not mitmdump:
            raise RuntimeError(_INSTALL_HINT)

        self.workdir.mkdir(parents=True, exist_ok=True)
        self._flowfile = self.workdir / f"flows-{port}.jsonl"
        self._flowfile.write_text("", encoding="utf-8")  # truncate

        # adb reverse so the device reaches the host-side proxy via its localhost.
        rev = self._adb("reverse", f"tcp:{port}", f"tcp:{port}")
        if rev.returncode != 0:
            raise RuntimeError(f"adb reverse failed: {rev.stderr.strip()}")

        # Point the device's global HTTP proxy at the reversed port.
        self.device_manager.execute_adb_shell_command(
            f"settings put global http_proxy 127.0.0.1:{port}")

        env = dict(os.environ, MITM_FLOWFILE=str(self._flowfile))
        self._proc = subprocess.Popen(
            [mitmdump, "-p", str(port), "-s", str(_ADDON), "-q"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        self._port = port

        return (
            f"Network capture started on port {port} (pid {self._proc.pid}).\n"
            f"  Device proxy set to 127.0.0.1:{port} via adb reverse.\n"
            f"  Flows: {self._flowfile}\n"
            "  HTTP is captured now. For HTTPS, install the mitmproxy CA on the "
            "device (open http://mitm.it in the device browser while proxied). "
            "On non-rooted Android 7+, only apps that trust user CAs (or with "
            "frida unpinning) will be decrypted.\n"
            "  Use network_list_flows to read traffic, network_stop_capture when done."
        )

    def list_flows(self, limit: int = 50) -> str:
        if self._flowfile is None or not self._flowfile.exists():
            return "No capture file yet. Start a capture with network_start_capture."
        lines = self._flowfile.read_text(encoding="utf-8").splitlines()
        if not lines:
            return "(no flows captured yet)"
        out = []
        for line in lines[-limit:]:
            try:
                e = json.loads(line)
                out.append(
                    f"{e.get('status','-')}  {e.get('method','?')} {e.get('url','')}"
                    f"  ({e.get('resp_len',0)}B, {e.get('content_type','')})")
            except json.JSONDecodeError:
                continue
        header = f"Last {len(out)} of {len(lines)} flows:"
        return header + "\n" + "\n".join(out)

    def stop_capture(self) -> str:
        msg = []
        if self.is_running():
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            msg.append("mitmdump stopped.")
        else:
            msg.append("mitmdump was not running.")

        # Clear device proxy + adb reverse (best effort).
        try:
            self.device_manager.execute_adb_shell_command(
                "settings put global http_proxy :0")
            msg.append("Device proxy cleared.")
        except Exception:
            pass
        if self._port is not None:
            self._adb("reverse", "--remove", f"tcp:{self._port}")
        self._proc = None
        self._port = None
        return " ".join(msg)

    def status(self) -> str:
        if self.is_running():
            return (f"Capture RUNNING on port {self._port} (pid {self._proc.pid}). "
                    f"Flows file: {self._flowfile}")
        return "Capture not running."
