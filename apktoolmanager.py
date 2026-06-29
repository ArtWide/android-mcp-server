"""apktool integration: decode an APK's resources and smali for inspection.

Complements the JADX (Java) tools with decoded resources, the human-readable
AndroidManifest.xml, and smali. Like JadxManager, jadx/apktool are checked
lazily so the server runs without them; tools error with a setup hint only when
called. apktool requires a Java runtime.
"""

import os
import shutil
import subprocess
from pathlib import Path

_HERE = Path(__file__).parent
DEFAULT_WORKSPACE = _HERE / "workspace"

_INSTALL_HINT = (
    "apktool executable not found. Install apktool and either add it to PATH or "
    "set the APKTOOL_PATH environment variable (to the apktool/apktool.bat file "
    "or its directory).\n"
    "  scripts\\0-setup_environment.ps1 installs it automatically, or get it from "
    "https://apktool.org/. apktool also requires a Java runtime (JRE/JDK 11+)."
)


def _discover_apktool(override: str | None = None) -> str | None:
    candidate = override or os.environ.get("APKTOOL_PATH", "").strip()
    if candidate:
        p = Path(candidate)
        if p.is_file():
            return str(p)
        if p.is_dir():
            for name in ("apktool.bat", "apktool"):
                if (p / name).is_file():
                    return str(p / name)

    for name in ("apktool", "apktool.bat"):
        found = shutil.which(name)
        if found:
            return found

    common = [
        Path.home() / ".android-mcp-tools" / "apktool" / "apktool.bat",
        Path.home() / ".android-mcp-tools" / "apktool" / "apktool",
        Path("C:/apktool/apktool.bat"),
        Path("/usr/local/bin/apktool"),
    ]
    for c in common:
        if c.is_file():
            return str(c)
    return None


class ApktoolManager:
    def __init__(self, device_manager, apktool_path: str | None = None,
                 output_dir: str | None = None) -> None:
        self.device_manager = device_manager
        self._override = apktool_path
        self.output_dir = Path(output_dir) if output_dir else DEFAULT_WORKSPACE

    def _resolve(self) -> str:
        path = _discover_apktool(self._override)
        if not path:
            raise RuntimeError(_INSTALL_HINT)
        return path

    @staticmethod
    def _check_java() -> None:
        try:
            subprocess.run(["java", "-version"], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError(
                "Java runtime not found. apktool requires JRE/JDK 11+ on PATH.")

    def _out_dir(self, package_name: str) -> Path:
        return self.output_dir / package_name / "apktool"

    def decode(self, package_name: str) -> str:
        apktool = self._resolve()
        self._check_java()

        apk_dir = self.output_dir / package_name / "apk"
        apks = self.device_manager.pull_apk(package_name, apk_dir, include_splits=False)
        apk = apks[0]

        out = self._out_dir(package_name)
        if out.exists():
            shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True, exist_ok=True)

        cmd = [apktool, "d", str(apk), "-o", str(out), "-f"]
        try:
            # stdin=DEVNULL so the apktool.bat wrapper's trailing `pause`
            # gets EOF and never blocks the server.
            proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, timeout=600,
                                  stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"apktool timed out decoding {package_name} (>600s).")

        smali_dirs = len(list(out.glob("smali*")))
        res_exists = (out / "res").exists()
        manifest = (out / "AndroidManifest.xml").exists()
        status = "ok" if manifest else f"incomplete (exit {proc.returncode})"
        # Drop the Windows wrapper's trailing `pause` prompt from the log.
        log_lines = [l for l in (proc.stdout or "").splitlines()
                     if "Press any key" not in l]
        tail = "\n".join(log_lines[-5:])
        return (
            f"Decoded '{package_name}' with apktool\n"
            f"  APK: {apk}\n"
            f"  Output: {out}\n"
            f"  AndroidManifest.xml: {manifest}, res/: {res_exists}, smali dirs: {smali_dirs}\n"
            f"  Status: {status}\n"
            f"  apktool log (tail):\n{tail}"
        )

    def list_files(self, package_name: str, subdir: str = "") -> str:
        root = self._out_dir(package_name)
        if not root.exists():
            raise RuntimeError(
                f"'{package_name}' not decoded yet. Run apktool_decode first.")
        target = (root / subdir).resolve()
        try:
            target.relative_to(root.resolve())
        except ValueError:
            raise RuntimeError("Path escapes the decoded output directory.")
        if not target.is_dir():
            raise RuntimeError(f"Not a directory: {subdir}")

        entries = []
        for p in sorted(target.iterdir()):
            rel = p.relative_to(root).as_posix()
            entries.append(f"{rel}/" if p.is_dir() else rel)
        return "\n".join(entries) if entries else "(empty)"

    def read_file(self, package_name: str, relative_path: str) -> str:
        root = self._out_dir(package_name)
        target = (root / relative_path).resolve()
        try:
            target.relative_to(root.resolve())
        except ValueError:
            raise RuntimeError("Path escapes the decoded output directory.")
        if not target.is_file():
            raise RuntimeError(f"File not found: {relative_path}")
        with open(target, encoding="utf-8", errors="replace") as f:
            return f.read()
