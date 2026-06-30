"""JADX integration: pull APKs from the device and decompile them for static
analysis (Dex -> Java), then search/read the decompiled sources.

Unlike AdbDeviceManager, this manager does NOT fail at construction time when
jadx or Java are missing. The MCP server must stay usable for ADB tools even
without jadx installed, so the jadx/Java checks happen lazily when a tool is
actually invoked, returning a clear setup message instead of crashing.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

_HERE = Path(__file__).parent
# Decompiled output and pulled APKs live here (git-ignored).
DEFAULT_WORKSPACE = _HERE / "workspace"

_INSTALL_HINT = (
    "jadx executable not found. Install JADX and either add it to PATH or set "
    "the JADX_PATH environment variable (to the jadx/jadx.bat file or its bin "
    "directory).\n"
    "  1. Download a release: https://github.com/skylot/jadx/releases\n"
    "  2. Unzip, e.g. to C:/jadx\n"
    "  3. Set JADX_PATH=C:/jadx/bin/jadx.bat (Windows) or C:/jadx/bin/jadx\n"
    "JADX also requires a Java runtime (JRE/JDK 11+) on PATH."
)


def _discover_jadx_executable(override: str | None = None) -> str | None:
    """Locate the jadx CLI from an override, JADX_PATH, PATH, or common dirs."""
    candidates_from = override or os.environ.get("JADX_PATH", "").strip()
    if candidates_from:
        p = Path(candidates_from)
        if p.is_file():
            return str(p)
        if p.is_dir():
            for name in ("jadx.bat", "jadx"):
                candidate = p / name
                if candidate.is_file():
                    return str(candidate)
            # maybe pointed at the install root, not bin/
            for name in ("jadx.bat", "jadx"):
                candidate = p / "bin" / name
                if candidate.is_file():
                    return str(candidate)

    for name in ("jadx", "jadx.bat"):
        found = shutil.which(name)
        if found:
            return found

    common = [
        Path("C:/jadx/bin/jadx.bat"),
        Path.home() / "jadx" / "bin" / "jadx.bat",
        Path.home() / "jadx" / "bin" / "jadx",
        Path("/usr/local/bin/jadx"),
        Path("/opt/jadx/bin/jadx"),
    ]
    for candidate in common:
        if candidate.is_file():
            return str(candidate)
    return None


class JadxManager:
    def __init__(self, device_manager, jadx_path: str | None = None,
                 output_dir: str | None = None) -> None:
        """
        Args:
            device_manager: an AdbDeviceManager used to locate and pull APKs.
            jadx_path: optional explicit path to the jadx executable.
            output_dir: where pulled APKs and decompiled output are stored.
        """
        self.device_manager = device_manager
        self._jadx_override = jadx_path
        self.output_dir = Path(output_dir) if output_dir else DEFAULT_WORKSPACE

    # ----- environment checks -------------------------------------------------
    def _resolve_jadx(self) -> str:
        path = _discover_jadx_executable(self._jadx_override)
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
                "Java runtime not found. JADX requires JRE/JDK 11+ on PATH.")

    # ----- APK location -------------------------------------------------------
    def _apk_remote_paths(self, package_name: str) -> list[str]:
        """Return the on-device APK paths for a package via `pm path`."""
        output = self.device_manager.device.shell(f"pm path {package_name}")
        paths = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                paths.append(line[len("package:"):])
        return paths

    def _pull_apk(self, package_name: str, include_splits: bool) -> list[Path]:
        remote_paths = self._apk_remote_paths(package_name)
        if not remote_paths:
            raise RuntimeError(
                f"Package '{package_name}' not found on device (no APK path).")

        # base.apk first; it carries the primary dex code.
        remote_paths.sort(key=lambda p: (0 if p.endswith("base.apk") else 1, p))
        if not include_splits:
            base = [p for p in remote_paths if p.endswith("base.apk")]
            remote_paths = base or remote_paths[:1]

        apk_dir = self.output_dir / package_name / "apk"
        apk_dir.mkdir(parents=True, exist_ok=True)

        local_apks = []
        for remote in remote_paths:
            local = apk_dir / Path(remote).name
            self.device_manager.device.pull(remote, str(local))
            local_apks.append(local)
        return local_apks

    # ----- public operations --------------------------------------------------
    def decompile(self, target: str, include_splits: bool = False) -> str:
        """Decompile an APK with jadx.

        `target` is an installed package name OR a path to a local .apk file.
        Returns the workspace key to pass to jadx_search_code / jadx_read_source.
        """
        from apkutils import resolve_apk
        jadx = self._resolve_jadx()
        self._check_java()

        primary_apk, key = resolve_apk(
            self.device_manager, target, self.output_dir, include_splits)

        src_dir = self.output_dir / key / "src"
        if src_dir.exists():
            shutil.rmtree(src_dir, ignore_errors=True)
        src_dir.mkdir(parents=True, exist_ok=True)

        cmd = [jadx, str(primary_apk), "-d", str(src_dir)]
        try:
            proc = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=600, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"jadx timed out decompiling {package_name} (>600s).")

        java_files = list((src_dir / "sources").rglob("*.java")) \
            if (src_dir / "sources").exists() else list(src_dir.rglob("*.java"))

        # jadx returns non-zero on partial failures but still emits sources.
        status = "ok" if java_files else f"no sources produced (exit {proc.returncode})"
        tail = "\n".join(proc.stdout.splitlines()[-5:]) if proc.stdout else ""
        return (
            f"Decompiled '{target}' (key: {key})\n"
            f"  APK: {primary_apk}\n"
            f"  Output: {src_dir}\n"
            f"  Java files: {len(java_files)}\n"
            f"  Status: {status}\n"
            f"  Use jadx_search_code/jadx_read_source with package_name='{key}'.\n"
            f"  jadx log (tail):\n{tail}"
        )

    def list_decompiled(self) -> list[str]:
        """List packages that have already been decompiled in the workspace."""
        if not self.output_dir.exists():
            return []
        result = []
        for entry in sorted(self.output_dir.iterdir()):
            if (entry / "src").exists():
                result.append(entry.name)
        return result

    def _sources_root(self, package_name: str) -> Path:
        base = self.output_dir / package_name / "src"
        sources = base / "sources"
        return sources if sources.exists() else base

    def search_code(self, pattern: str, package_name: str,
                    max_results: int = 100) -> str:
        """Regex-search the decompiled Java sources of a package."""
        root = self._sources_root(package_name)
        if not root.exists():
            raise RuntimeError(
                f"No decompiled sources for '{package_name}'. "
                f"Run decompile first.")
        try:
            regex = re.compile(pattern)
        except re.error as e:
            raise RuntimeError(f"Invalid regex pattern: {e}")

        matches = []
        for java_file in root.rglob("*.java"):
            try:
                with open(java_file, encoding="utf-8", errors="replace") as f:
                    for lineno, line in enumerate(f, 1):
                        if regex.search(line):
                            rel = java_file.relative_to(root)
                            matches.append(
                                f"{rel}:{lineno}: {line.strip()[:200]}")
                            if len(matches) >= max_results:
                                break
            except OSError:
                continue
            if len(matches) >= max_results:
                matches.append(f"... (truncated at {max_results} matches)")
                break

        if not matches:
            return f"No matches for /{pattern}/ in '{package_name}'."
        return "\n".join(matches)

    def read_source(self, package_name: str, relative_path: str) -> str:
        """Read a single decompiled source file (path-traversal guarded)."""
        root = self._sources_root(package_name)
        target = (root / relative_path).resolve()
        try:
            target.relative_to(root.resolve())
        except ValueError:
            raise RuntimeError("Path escapes the package source directory.")
        if not target.is_file():
            raise RuntimeError(f"File not found: {relative_path}")
        with open(target, encoding="utf-8", errors="replace") as f:
            return f.read()
