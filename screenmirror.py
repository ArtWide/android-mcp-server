"""Live device screen mirroring via scrcpy.

Launches scrcpy as a long-lived child of the (long-lived) MCP server so the
analyst sees the connected device's screen in real time in a window ON THEIR PC,
and can optionally drive it with mouse/keyboard. Note: this is a native window
on the host, not a stream inside the Claude client (MCP has no live-video
channel). Optionally records the session to an mp4 for report evidence.

Mirrors the NetworkCaptureManager subprocess pattern and always targets the
currently-active device (respects select_device).
"""

import shutil
import subprocess
import time
from pathlib import Path

_HERE = Path(__file__).parent
DEFAULT_WORKSPACE = _HERE / "workspace"

_INSTALL_HINT = (
    "scrcpy not found. Install it and ensure `scrcpy` is on PATH (or set the "
    "SCRCPY_PATH env var). Windows: `winget install Genymobile.scrcpy` or the "
    "release zip from https://github.com/Genymobile/scrcpy/releases. "
    "scripts/0-setup_environment.ps1 -SetupScrcpy also installs it."
)


def _discover_scrcpy() -> str | None:
    import os
    env = os.environ.get("SCRCPY_PATH", "").strip()
    if env:
        p = Path(env)
        if p.is_file():
            return str(p)
        if p.is_dir():
            cand = p / ("scrcpy.exe" if os.name == "nt" else "scrcpy")
            if cand.is_file():
                return str(cand)
    for name in ("scrcpy", "scrcpy.exe"):
        found = shutil.which(name)
        if found:
            return found
    common = [
        Path("C:/Program Files/scrcpy/scrcpy.exe"),
        Path.home() / "scrcpy" / "scrcpy.exe",
        Path.home() / ".android-mcp-tools" / "scrcpy" / "scrcpy.exe",
        Path("/usr/local/bin/scrcpy"),
        Path("/usr/bin/scrcpy"),
    ]
    for c in common:
        if c.is_file():
            return str(c)
    return None


class ScreenMirrorManager:
    def __init__(self, device_manager, output_dir: str | None = None) -> None:
        self.device_manager = device_manager
        self.workdir = (Path(output_dir) if output_dir else DEFAULT_WORKSPACE) / "screen"
        self._proc: subprocess.Popen | None = None
        self._serial_running: str | None = None
        self._record_path: Path | None = None
        self._logfile: Path | None = None

    def _serial(self) -> str:
        return self.device_manager.device.serial

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self, max_size: int = 0, record: bool = False,
              extra_args: list[str] | None = None) -> str:
        """Open a live scrcpy mirror of the active device on the host.

        Args:
            max_size: cap the longer screen dimension in px (0 = device native);
                      lower it (e.g. 1024) for smoother mirroring over slow links.
            record: also save the session to workspace/screen/<serial>-<ts>.mp4
                    for report evidence.
            extra_args: additional raw scrcpy flags (advanced).
        """
        if self.is_running():
            return (f"Screen mirror already running for {self._serial_running} "
                    f"(pid {self._proc.pid}). Stop it first with stop_screen_mirror.")

        scrcpy = _discover_scrcpy()
        if not scrcpy:
            raise RuntimeError(_INSTALL_HINT)

        serial = self._serial()
        self.workdir.mkdir(parents=True, exist_ok=True)
        self._logfile = self.workdir / "scrcpy.log"

        cmd = [scrcpy, "-s", serial, "--window-title", f"MCP mirror {serial}"]
        if max_size and max_size > 0:
            cmd += ["--max-size", str(int(max_size))]
        self._record_path = None
        if record:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            safe = "".join(c if c.isalnum() else "_" for c in serial)
            self._record_path = self.workdir / f"{safe}-{stamp}.mp4"
            cmd += ["--record", str(self._record_path)]
        if extra_args:
            cmd += list(extra_args)

        log = open(self._logfile, "w", encoding="utf-8")
        self._proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
        self._serial_running = serial

        # scrcpy exits immediately on failure (no display, adb/version mismatch,
        # device gone). Give it a moment, then surface the real log if it died.
        time.sleep(1.0)
        if not self.is_running():
            err = ""
            try:
                err = self._logfile.read_text(encoding="utf-8", errors="replace").strip()
            except Exception:
                pass
            code = self._proc.poll()
            self._proc = None
            self._serial_running = None
            raise RuntimeError(
                f"scrcpy exited immediately (code {code}). Device may be asleep "
                f"(try wake_device), disconnected, or scrcpy/host mismatch.\n"
                f"--- scrcpy log ---\n{err or '(no output)'}")

        rec = f"\n  Recording -> {self._record_path}" if self._record_path else ""
        return (
            f"Screen mirror started for {serial} (pid {self._proc.pid}).\n"
            f"  A scrcpy window is now open ON THE ANALYST PC showing the live "
            f"screen (mouse/keyboard control it).{rec}\n"
            f"  This is a host window, not a feed inside the Claude client.\n"
            f"  Stop with stop_screen_mirror. Log: {self._logfile}"
        )

    def stop(self) -> str:
        if not self.is_running():
            self._proc = None
            return "Screen mirror was not running."
        self._proc.terminate()
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        rec = (f" Recording saved: {self._record_path}"
               if self._record_path and self._record_path.exists() else "")
        serial = self._serial_running
        self._proc = None
        self._serial_running = None
        return f"Screen mirror stopped for {serial}.{rec}"

    def status(self) -> str:
        if self.is_running():
            rec = f", recording -> {self._record_path}" if self._record_path else ""
            return (f"Screen mirror RUNNING for {self._serial_running} "
                    f"(pid {self._proc.pid}){rec}.")
        return "Screen mirror not running."
