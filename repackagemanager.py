"""Non-root Frida instrumentation via APK repackaging (frida-gadget injection).

The analysis devices are typically NOT rooted, so frida-server can't run. The
standard non-root approach is to inject frida-gadget into the target APK, add a
network-security-config that trusts user CAs (for mitmproxy HTTPS), rebuild, and
re-sign. This runs entirely on the MCP host (which has apktool, Java, internet
and the matching frida), then the result is installed with install_apk.

Requirements on the host (discovered lazily; clear setup hint when missing):
  - apktool + Java (already used by the apktool_* tools)
  - a frida-gadget .so matching the host frida version (auto-fetched by
    scripts/1-setup_frida_server.ps1 -SetupFridaServer)
  - a signer: uber-apk-signer.jar (preferred; single jar, auto debug key) OR
    Android build-tools apksigner + zipalign + a keystore

Known limits: apktool rebuild can fail on heavily obfuscated/packed apps, and a
packer with integrity/anti-tamper checks may reject the re-signed app. In that
case fall back to gadget script-mode (hook right after unpack) or to root-free
static-first analysis.
"""

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from apkutils import resolve_apk
from apktoolmanager import _discover_apktool

_HERE = Path(__file__).parent
DEFAULT_WORKSPACE = _HERE / "workspace"
_TOOLS = Path.home() / ".android-mcp-tools"

# lib/<abi> folder  ->  frida-gadget arch token
_ARCH_MAP = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
}

_NSC_TRUST_USER = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
"""


def _host_frida_version() -> str:
    try:
        import frida
        return frida.__version__
    except Exception:
        return ""


class RepackageManager:
    def __init__(self, device_manager, output_dir: str | None = None,
                 apktool_path: str | None = None) -> None:
        self.device_manager = device_manager
        self.workspace = Path(output_dir) if output_dir else DEFAULT_WORKSPACE
        self._apktool_override = apktool_path

    # ----- tool discovery -----------------------------------------------------
    def _apktool(self) -> str:
        path = _discover_apktool(self._apktool_override)
        if not path:
            raise RuntimeError(
                "apktool not found. Install it (scripts/0-setup_environment.ps1) "
                "or set APKTOOL_PATH.")
        return path

    @staticmethod
    def _check_java() -> None:
        try:
            subprocess.run(["java", "-version"], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("Java not found. apktool/signing require JRE/JDK 11+.")

    def _find_gadget(self, abi: str) -> str:
        arch = _ARCH_MAP.get(abi)
        if not arch:
            raise RuntimeError(f"Unsupported abi '{abi}'. "
                               f"Use one of {list(_ARCH_MAP)}.")
        # explicit override
        override = os.environ.get("FRIDA_GADGET_SO", "")
        if override and Path(override).is_file():
            return override
        ver = _host_frida_version()
        candidates = []
        if ver:
            candidates.append(_TOOLS / f"frida-gadget-{ver}-android-{arch}.so")
        # any gadget for this arch as a fallback
        candidates += sorted(_TOOLS.glob(f"frida-gadget-*-android-{arch}.so"))
        for c in candidates:
            if Path(c).is_file():
                return str(c)
        raise RuntimeError(
            f"frida-gadget .so for {arch} (frida {ver or '?'}) not found in "
            f"{_TOOLS}. Fetch it with scripts/1-setup_frida_server.ps1 "
            f"-SetupFridaServer, or set FRIDA_GADGET_SO.")

    def _find_uber_signer(self) -> str | None:
        override = os.environ.get("UBER_APK_SIGNER", "")
        if override and Path(override).is_file():
            return override
        found = sorted(_TOOLS.glob("uber-apk-signer*.jar"))
        return str(found[0]) if found else None

    # ----- helpers ------------------------------------------------------------
    @staticmethod
    def _run(cmd, cwd=None) -> str:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL)
        if p.returncode != 0:
            raise RuntimeError(
                f"command failed ({p.returncode}): {' '.join(map(str, cmd))}\n"
                f"{(p.stdout or '')[-2000:]}\n{(p.stderr or '')[-2000:]}")
        return p.stdout or ""

    def _apktool_run(self, *args, cwd=None) -> str:
        return self._run([self._apktool(), *args], cwd=cwd)

    @staticmethod
    def _resolve_application_class(decoded: Path) -> tuple[str, str] | None:
        """Return (fqcn, package) of the <application android:name>, or None."""
        manifest = (decoded / "AndroidManifest.xml").read_text(
            encoding="utf-8", errors="ignore")
        pkg_m = re.search(r'package="([^"]+)"', manifest)
        pkg = pkg_m.group(1) if pkg_m else ""
        m = re.search(r'<application[^>]*android:name="([^"]+)"', manifest)
        if not m:
            return None
        name = m.group(1)
        # Leading '.' or bare name -> relative to package.
        if name.startswith("."):
            fqcn = pkg + name
        elif "." not in name:
            fqcn = f"{pkg}.{name}"
        else:
            fqcn = name
        return fqcn, pkg

    def _inject_loadlibrary(self, decoded: Path, lib_name: str = "gadget") -> str:
        """Inject System.loadLibrary(lib_name) into the Application's <clinit>.

        The Application class runs before any activity and is where packers
        unpack, so it's the earliest reliable hook point. Falls back to an error
        (caller can try activity injection) when there is no Application class.
        """
        resolved = self._resolve_application_class(decoded)
        if not resolved:
            raise RuntimeError(
                "No <application android:name> to inject into. This app uses the "
                "default Application; inject into the launcher activity instead "
                "(not yet automated).")
        fqcn, _ = resolved
        rel = fqcn.replace(".", "/") + ".smali"

        target = None
        for d in sorted(decoded.glob("smali*")):  # multidex
            cand = d / rel
            if cand.is_file():
                target = cand
                break
        if target is None:
            raise RuntimeError(f"smali for Application not found: {rel}")

        src = target.read_text(encoding="utf-8", errors="ignore")
        load = ('    const-string v0, "%s"\n'
                '    invoke-static {v0}, Ljava/lang/System;->'
                'loadLibrary(Ljava/lang/String;)V\n') % lib_name

        if ".method static constructor <clinit>()V" in src:
            src = re.sub(
                r"(\.method static constructor <clinit>\(\)V\n(?:\s*\.locals \d+\n)?)",
                lambda mm: mm.group(1) + load, src, count=1)
        else:
            clinit = ("\n.method static constructor <clinit>()V\n    .locals 1\n"
                      + load + "    return-void\n.end method\n")
            src = src.rstrip() + "\n" + clinit
        target.write_text(src, encoding="utf-8")
        return fqcn

    @staticmethod
    def _apply_nsc(decoded: Path) -> str:
        xmldir = decoded / "res" / "xml"
        xmldir.mkdir(parents=True, exist_ok=True)
        (xmldir / "nsc_mitm.xml").write_text(_NSC_TRUST_USER, encoding="utf-8")
        man = decoded / "AndroidManifest.xml"
        s = man.read_text(encoding="utf-8", errors="ignore")
        if "android:networkSecurityConfig" in s:
            s = re.sub(r'android:networkSecurityConfig="[^"]*"',
                       'android:networkSecurityConfig="@xml/nsc_mitm"', s, count=1)
        else:
            s = s.replace("<application ",
                          '<application android:networkSecurityConfig="@xml/nsc_mitm" ', 1)
        man.write_text(s, encoding="utf-8")
        return "system+user trust (@xml/nsc_mitm)"

    def _sign(self, built: Path, out: Path) -> str:
        """Align + sign `built` -> `out`. Prefer uber-apk-signer (auto debug key)."""
        uber = self._find_uber_signer()
        if uber:
            outdir = out.parent
            self._run(["java", "-jar", uber, "--apks", str(built),
                       "--out", str(outdir), "--allowResign", "--overwrite"])
            # uber with --overwrite writes the signed apk back to `built`
            if built.resolve() != out.resolve():
                shutil.copy(built, out)
            return f"uber-apk-signer ({Path(uber).name})"

        # Fallback: zipalign + apksigner + keystore
        apksigner = os.environ.get("APKSIGNER", "")
        zipalign = os.environ.get("ZIPALIGN", "")
        keystore = os.environ.get("DEBUG_KEYSTORE", "")
        if not (apksigner and keystore):
            raise RuntimeError(
                "No signer available. Provide uber-apk-signer.jar in "
                f"{_TOOLS} (scripts/1-setup_frida_server.ps1 -SetupFridaServer), "
                "or set APKSIGNER + DEBUG_KEYSTORE (+ ZIPALIGN).")
        aligned = built.with_name("aligned.apk")
        if zipalign and Path(zipalign).is_file():
            self._run([zipalign, "-f", "-p", "4", str(built), str(aligned)])
        else:
            aligned = built
        ks_pass = os.environ.get("DEBUG_KS_PASS", "android")
        alias = os.environ.get("DEBUG_KS_ALIAS", "androiddebugkey")
        self._run([apksigner, "sign", "--ks", keystore,
                   "--ks-pass", f"pass:{ks_pass}", "--ks-key-alias", alias,
                   "--key-pass", f"pass:{ks_pass}", "--out", str(out), str(aligned)])
        return "apksigner + zipalign"

    # ----- public op ----------------------------------------------------------
    def repackage_frida(self, target: str, arch: str = "arm64-v8a",
                        trust_user_certs: bool = True, gadget_config: str = "",
                        output_path: str = "") -> str:
        """Inject frida-gadget (+ optional user-CA trust), rebuild and re-sign.

        Args:
            target: package name or path to a local .apk
            arch: device ABI (arm64-v8a / armeabi-v7a / x86_64 / x86)
            trust_user_certs: replace networkSecurityConfig to trust user CAs
            gadget_config: contents of libgadget.config.so (JSON) — e.g. to
                auto-load a script; empty = default gadget listen mode
            output_path: output APK path; default <name>-repackaged.apk
        Returns:
            A summary including the signed APK path (feed it to install_apk).
        """
        self._check_java()
        gadget = self._find_gadget(arch)
        apk, key = resolve_apk(self.device_manager, target,
                               self.workspace / "repackage_src")

        base = self.workspace / "repackage"
        base.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix=f"{key}_", dir=str(base)))
        decoded = work / "decoded"
        try:
            self._apktool_run("d", "-f", "-o", str(decoded), str(apk))

            libdir = decoded / "lib" / arch
            libdir.mkdir(parents=True, exist_ok=True)
            shutil.copy(gadget, libdir / "libgadget.so")
            if gadget_config:
                (libdir / "libgadget.config.so").write_text(
                    gadget_config, encoding="utf-8")

            entry = self._inject_loadlibrary(decoded, "gadget")
            nsc_note = self._apply_nsc(decoded) if trust_user_certs else "skipped"

            built = work / "built.apk"
            self._apktool_run("b", "-o", str(built), str(decoded))

            out = Path(output_path) if output_path else \
                (base / f"{key}-repackaged.apk")
            signer = self._sign(built, out)

            return (
                f"Repackaged '{target}' -> {out}\n"
                f"  frida-gadget: {Path(gadget).name} (lib/{arch}/libgadget.so)\n"
                f"  loadLibrary injected into: {entry}\n"
                f"  networkSecurityConfig: {nsc_note}\n"
                f"  signed with: {signer}\n"
                f"  Next: install_apk('{out}'), launch it, then frida_attach / "
                f"connect to the gadget. If it crashes, the packer may have "
                f"anti-tamper — try gadget script-mode or static-first analysis.")
        finally:
            # Keep 'decoded' out; drop only the transient build tree.
            shutil.rmtree(work, ignore_errors=True)
