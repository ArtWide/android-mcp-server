"""Frida integration: dynamic instrumentation of the connected Android device.

Because the MCP server is a long-lived HTTP process, Frida sessions and their
scripts are kept alive in an in-memory registry and survive client reconnects
(the main reason for moving off per-spawn stdio). Script messages arrive on
Frida's own background thread and are buffered (thread-safely) until a client
drains them with frida_read_messages.

Like JadxManager, this does NOT require Frida at construction time; the import
is guarded so the server still runs (with ADB/JADX tools) when Frida is absent.
The frida_* tools raise a clear setup hint only when actually called.
"""

import threading
import uuid
from pathlib import Path

_PRESET_DIR = Path(__file__).parent / "frida_presets"

try:
    import frida
    _FRIDA_IMPORT_ERROR: Exception | None = None
except Exception as e:  # pragma: no cover - exercised only without frida
    frida = None
    _FRIDA_IMPORT_ERROR = e

# Cap per-session buffered messages to avoid unbounded memory growth.
MAX_BUFFERED_MESSAGES = 1000

_INSTALL_HINT = (
    "Frida is not available: {err}\n"
    "Install the host bindings (already a project dependency):\n"
    "  uv add frida frida-tools   (or: uv sync)\n"
    "The target device also needs a matching frida-server running (rooted "
    "device), or a frida-gadget-injected APK. Host frida and device "
    "frida-server major versions must match.\n"
    "See scripts/0-setup_environment.ps1 -SetupFridaServer."
)


class _Session:
    """Holds a live Frida session plus its script and buffered messages."""

    def __init__(self, session, pid: int, target: str) -> None:
        self.session = session
        self.pid = pid
        self.target = target
        self.script = None
        self.messages: list[dict] = []
        self.lock = threading.Lock()

    def on_message(self, message, data) -> None:
        # Called from Frida's thread; keep it small and thread-safe.
        with self.lock:
            if len(self.messages) >= MAX_BUFFERED_MESSAGES:
                self.messages.pop(0)
            self.messages.append(message)

    def drain(self) -> list[dict]:
        with self.lock:
            out = self.messages
            self.messages = []
            return out


class FridaManager:
    def __init__(self, device_manager) -> None:
        """
        Args:
            device_manager: an AdbDeviceManager; its selected device serial is
                used to bind Frida to the same physical device.
        """
        self.device_manager = device_manager
        self._sessions: dict[str, _Session] = {}
        self._registry_lock = threading.Lock()

    # ----- environment / device ----------------------------------------------
    @staticmethod
    def _require_frida():
        if frida is None:
            raise RuntimeError(_INSTALL_HINT.format(err=_FRIDA_IMPORT_ERROR))
        return frida

    def _device_serial(self) -> str:
        return self.device_manager.device.serial

    def _get_device(self):
        frida_mod = self._require_frida()
        try:
            return frida_mod.get_device(self._device_serial(), timeout=10)
        except Exception as e:
            raise RuntimeError(
                f"Could not reach the device via Frida ({e}). Ensure "
                f"frida-server is running on the device and versions match.")

    # ----- enumeration --------------------------------------------------------
    def list_devices(self) -> str:
        frida_mod = self._require_frida()
        devices = frida_mod.enumerate_devices()
        return "\n".join(f"{d.id}\t{d.type}\t{d.name}" for d in devices)

    def check_compatibility(self, server_path: str = "/data/local/tmp/frida-server") -> str:
        """Compare the host frida version with the device's frida-server.

        frida requires the host bindings and device frida-server to match (at
        least on the major version), so this surfaces mismatches up front
        instead of failing later on attach/spawn. Reads the device binary's
        --version directly (independent of the host), so it works even when the
        versions are incompatible.
        """
        host = getattr(frida, "__version__", None) if frida else None
        shell = self.device_manager.execute_adb_shell_command
        out = [f"Host frida (Python bindings): {host or 'NOT INSTALLED'}"]

        running = shell("ps -A 2>/dev/null | grep frida-server").strip() \
            or shell("ps 2>/dev/null | grep frida-server").strip()
        out.append(f"frida-server running on device: {'yes' if running else 'no'}")

        exists = shell(f"ls -l {server_path} 2>/dev/null").strip()
        if not exists or "No such" in exists:
            out.append(f"frida-server binary: not found at {server_path}")
            out.append("  -> push a matching build: "
                       "scripts/0-setup_environment.ps1 -SetupFridaServer")
            return "\n".join(out)

        dev_ver = shell(f"{server_path} --version 2>/dev/null").strip()
        if not dev_ver:
            out.append(f"frida-server present at {server_path} but version unreadable "
                       "(may not be executable: chmod 755).")
            return "\n".join(out)
        out.append(f"Device frida-server version: {dev_ver}")

        if host:
            host_major, dev_major = host.split(".")[0], dev_ver.split(".")[0]
            if host == dev_ver:
                out.append("Result: MATCH (exact) — good to go.")
            elif host_major == dev_major:
                out.append(f"Result: major match ({host_major}.x) but exact versions "
                           f"differ (host {host} vs device {dev_ver}). Usually OK; "
                           "exact match recommended.")
            else:
                out.append(f"Result: MISMATCH — host major {host_major} != device "
                           f"major {dev_major}. Frida will fail to connect. Either "
                           f"push frida-server {host} to the device (scripts/"
                           "1-setup_frida_server.ps1), OR pin the host frida to the "
                           f"device: set frida.version: \"{dev_ver}\" in config.yaml "
                           "(or env FRIDA_VERSION) and restart the server -- the "
                           "launcher (3-run_server.ps1 -> align_frida.py) aligns the "
                           "host to the device automatically, no manual reinstall.")
        return "\n".join(out)

    def list_processes(self) -> str:
        device = self._get_device()
        procs = sorted(device.enumerate_processes(), key=lambda p: p.name.lower())
        if not procs:
            return "No processes found."
        return "\n".join(f"{p.pid}\t{p.name}" for p in procs)

    def list_applications(self) -> str:
        device = self._get_device()
        apps = device.enumerate_applications()
        lines = []
        for a in sorted(apps, key=lambda a: a.identifier):
            pid = a.pid if a.pid else "-"
            lines.append(f"{pid}\t{a.identifier}\t{a.name}")
        if not lines:
            return "No applications found."
        return "\n".join(lines)

    # ----- sessions -----------------------------------------------------------
    def _register(self, session, pid: int, target: str) -> str:
        sess = _Session(session, pid, target)
        session_id = uuid.uuid4().hex[:12]
        with self._registry_lock:
            self._sessions[session_id] = sess
        return session_id

    def _get(self, session_id: str) -> _Session:
        with self._registry_lock:
            sess = self._sessions.get(session_id)
        if sess is None:
            raise RuntimeError(f"Unknown session_id: {session_id}")
        return sess

    def attach(self, target: str) -> str:
        """Attach to a running process by name or PID. Returns a session_id."""
        device = self._get_device()
        target_val: object = target
        if target.isdigit():
            target_val = int(target)
        try:
            session = device.attach(target_val)
        except Exception as e:
            raise RuntimeError(f"Failed to attach to '{target}': {e}")
        pid = session._impl.pid if hasattr(session, "_impl") else 0
        session_id = self._register(session, pid, str(target))
        return (f"Attached to '{target}' (session_id={session_id}). "
                f"Use frida_run_script to inject instrumentation.")

    def spawn(self, package_name: str) -> str:
        """Spawn an app suspended and attach. Returns a session_id.

        The process stays suspended until frida_run_script (which resumes it
        after loading the script) or frida_resume is called.
        """
        device = self._get_device()
        try:
            pid = device.spawn(package_name)
            session = device.attach(pid)
        except Exception as e:
            raise RuntimeError(f"Failed to spawn '{package_name}': {e}")
        session_id = self._register(session, pid, package_name)
        return (f"Spawned '{package_name}' (pid={pid}, session_id={session_id}), "
                f"suspended. Call frida_run_script to inject and resume, or "
                f"frida_resume to run without a script.")

    def run_script(self, session_id: str, script_source: str) -> str:
        """Create, hook messages on, and load a JS script in a session.

        If the session was spawned (suspended), the process is resumed after
        the script loads.
        """
        sess = self._get(session_id)
        try:
            script = sess.session.create_script(script_source)
            script.on("message", sess.on_message)
            script.load()
        except Exception as e:
            raise RuntimeError(f"Failed to load script: {e}")
        sess.script = script

        # Resume if this was a spawned (suspended) process.
        resumed = False
        if sess.pid:
            try:
                self._get_device().resume(sess.pid)
                resumed = True
            except Exception:
                # Already running (attach case) or resume not applicable.
                pass
        return (f"Script loaded in session {session_id}"
                f"{' and process resumed' if resumed else ''}. "
                f"Use frida_read_messages to read script output.")

    def run_preset(self, session_id: str, preset_name: str) -> str:
        """Load a bundled preset script (e.g. 'ssl-unpin') into a session.

        Works for both frida-server and gadget-injected (non-root) sessions.
        """
        name = preset_name if preset_name.endswith(".js") else preset_name + ".js"
        path = (_PRESET_DIR / name).resolve()
        try:
            path.relative_to(_PRESET_DIR.resolve())
        except ValueError:
            raise RuntimeError("Invalid preset name.")
        if not path.is_file():
            avail = sorted(p.stem for p in _PRESET_DIR.glob("*.js"))
            raise RuntimeError(f"Preset '{preset_name}' not found. Available: {avail}")
        return self.run_script(session_id, path.read_text(encoding="utf-8"))

    def read_messages(self, session_id: str) -> str:
        """Drain buffered messages emitted by the session's script."""
        sess = self._get(session_id)
        messages = sess.drain()
        if not messages:
            return "(no new messages)"
        lines = []
        for m in messages:
            if m.get("type") == "send":
                lines.append(f"[send] {m.get('payload')}")
            elif m.get("type") == "error":
                desc = m.get("description") or m
                lines.append(f"[error] {desc}")
            else:
                lines.append(str(m))
        return "\n".join(lines)

    def resume(self, session_id: str) -> str:
        sess = self._get(session_id)
        if not sess.pid:
            return f"Session {session_id} has no spawned pid to resume."
        self._get_device().resume(sess.pid)
        return f"Resumed pid {sess.pid} (session {session_id})."

    def list_sessions(self) -> str:
        with self._registry_lock:
            items = list(self._sessions.items())
        if not items:
            return "No active Frida sessions."
        lines = []
        for sid, s in items:
            has_script = "script" if s.script else "no-script"
            lines.append(f"{sid}\tpid={s.pid or '-'}\t{s.target}\t{has_script}")
        return "\n".join(lines)

    def detach(self, session_id: str) -> str:
        """Detach a session and drop it from the registry."""
        with self._registry_lock:
            sess = self._sessions.pop(session_id, None)
        if sess is None:
            raise RuntimeError(f"Unknown session_id: {session_id}")
        try:
            if sess.script is not None:
                sess.script.unload()
        except Exception:
            pass
        try:
            sess.session.detach()
        except Exception:
            pass
        return f"Detached session {session_id}."
