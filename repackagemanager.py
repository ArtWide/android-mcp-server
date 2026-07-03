"""Non-root Frida instrumentation via APK repackaging (frida-gadget injection).

The analysis devices (e.g. SM-G986N KR) are NOT rootable, so frida-server / a
system CA can't be installed. The standard non-root path is to inject
frida-gadget into the target APK, add a network-security-config that trusts user
CAs (for mitmproxy HTTPS), rebuild and re-sign. This runs on the MCP host (which
has apktool, Java, internet and the matching frida); the result is installed
with install_apk / install_and_launch.

Requirements on the host (see check_repackage_toolchain):
  - apktool + Java (already used by the apktool_* tools)
  - a frida-gadget .so matching the host frida version
  - a signer: uber-apk-signer.jar (preferred) OR apksigner + zipalign + keystore
scripts/1-setup_frida_server.ps1 -SetupFridaServer fetches the gadget + signer.

Known limits: apktool rebuild can fail on obfuscated/packed apps, and a packer
with integrity/anti-tamper checks may reject the re-signed app. On crash/refusal
fall back to gadget script-mode (hook right after unpack) or static-first.
"""

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
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
    def _java_ok() -> bool:
        try:
            subprocess.run(["java", "-version"], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _gadget_for(self, abi: str):
        """Return (path, note). Errors if the gadget version != host frida."""
        arch = _ARCH_MAP.get(abi)
        if not arch:
            raise RuntimeError(f"Unsupported abi '{abi}'. Use one of {list(_ARCH_MAP)}.")
        ver = _host_frida_version()
        override = os.environ.get("FRIDA_GADGET_SO", "")
        if override and Path(override).is_file():
            fname = Path(override).name
            if ver and ver not in fname:
                raise RuntimeError(
                    f"FRIDA_GADGET_SO '{fname}' does not match host frida {ver}; "
                    "attach will fail. Provide the matching gadget.")
            return override, fname
        if not ver:
            raise RuntimeError("Host frida not importable; cannot verify gadget version.")
        exact = _TOOLS / f"frida-gadget-{ver}-android-{arch}.so"
        if exact.is_file():
            return str(exact), exact.name
        others = sorted(p.name for p in _TOOLS.glob(f"frida-gadget-*-android-{arch}.so"))
        raise RuntimeError(
            f"frida-gadget {ver} for {arch} not found in {_TOOLS}. "
            f"Present: {others or 'none'}. Run scripts/1-setup_frida_server.ps1 "
            f"-SetupFridaServer (fetches the matching gadget), or set FRIDA_GADGET_SO.")

    def _uber_signer(self) -> str | None:
        override = os.environ.get("UBER_APK_SIGNER", "")
        if override and Path(override).is_file():
            return override
        found = sorted(_TOOLS.glob("uber-apk-signer*.jar"))
        return str(found[0]) if found else None

    def _device_abi(self) -> str:
        try:
            return self.device_manager.execute_adb_shell_command(
                "getprop ro.product.cpu.abi").strip()
        except Exception:
            return ""

    # ----- helpers ------------------------------------------------------------
    @staticmethod
    def _run(cmd, cwd=None):
        """Return (returncode, combined_output)."""
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL)
        return p.returncode, ((p.stdout or "") + (p.stderr or ""))

    @staticmethod
    def _resolve_application_class(decoded: Path):
        manifest = (decoded / "AndroidManifest.xml").read_text(
            encoding="utf-8", errors="ignore")
        pkg_m = re.search(r'package="([^"]+)"', manifest)
        pkg = pkg_m.group(1) if pkg_m else ""
        m = re.search(r'<application[^>]*android:name="([^"]+)"', manifest)
        if not m:
            return None
        name = m.group(1)
        if name.startswith("."):
            fqcn = pkg + name
        elif "." not in name:
            fqcn = f"{pkg}.{name}"
        else:
            fqcn = name
        return fqcn, pkg

    def _inject_loadlibrary(self, decoded: Path, lib_name: str = "gadget") -> str:
        resolved = self._resolve_application_class(decoded)
        if not resolved:
            raise RuntimeError(
                "No <application android:name> to inject into (default Application). "
                "Injecting into the launcher activity is not yet automated.")
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
    def _ensure_user_trust(cfg: ET.Element) -> None:
        ta = cfg.find("trust-anchors")
        if ta is None:
            ta = ET.SubElement(cfg, "trust-anchors")
        srcs = {c.get("src") for c in ta.findall("certificates")}
        if "system" not in srcs:
            ET.SubElement(ta, "certificates", {"src": "system"})
        if "user" not in srcs:
            ET.SubElement(ta, "certificates", {"src": "user"})

    def _apply_nsc(self, decoded: Path) -> str:
        """Merge user-CA trust into the app's NSC (preserving it), or create one."""
        man = decoded / "AndroidManifest.xml"
        s = man.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r'android:networkSecurityConfig="@xml/([^"]+)"', s)
        if m:
            name = m.group(1)
            xmlpath = decoded / "res" / "xml" / f"{name}.xml"
            if xmlpath.is_file():
                try:
                    tree = ET.parse(xmlpath)
                    root = tree.getroot()
                    base = root.find("base-config")
                    if base is None:
                        base = ET.SubElement(root, "base-config")
                        base.set("cleartextTrafficPermitted", "true")
                    self._ensure_user_trust(base)
                    for dc in root.findall("domain-config"):
                        self._ensure_user_trust(dc)
                    tree.write(xmlpath, encoding="utf-8", xml_declaration=True)
                    return f"merged user CA into existing @xml/{name} (preserved)"
                except ET.ParseError:
                    xmlpath.write_text(_NSC_TRUST_USER, encoding="utf-8")
                    return f"overwrote unparseable @xml/{name}"
            xmlpath.parent.mkdir(parents=True, exist_ok=True)
            xmlpath.write_text(_NSC_TRUST_USER, encoding="utf-8")
            return f"created missing @xml/{name}"
        # none referenced: create + link
        (decoded / "res" / "xml").mkdir(parents=True, exist_ok=True)
        (decoded / "res" / "xml" / "nsc_mitm.xml").write_text(
            _NSC_TRUST_USER, encoding="utf-8")
        s = s.replace("<application ",
                      '<application android:networkSecurityConfig="@xml/nsc_mitm" ', 1)
        man.write_text(s, encoding="utf-8")
        return "created @xml/nsc_mitm and linked"

    @staticmethod
    def _cert_sha256(apk_path: Path) -> str:
        try:
            from androguard.core.apk import APK
            for c in APK(str(apk_path)).get_certificates():
                return hashlib.sha256(c.dump()).hexdigest()
        except Exception:
            pass
        return "?"

    def _sign(self, built: Path, out: Path):
        """Align + v1/v2/v3 sign built -> out. Returns (signer_note) or raises."""
        uber = self._uber_signer()
        if uber:
            rc, log = self._run(["java", "-jar", uber, "--apks", str(built),
                                 "--allowResign", "--overwrite"])
            if rc != 0:
                raise RuntimeError(f"uber-apk-signer failed:\n{log[-2000:]}")
            if built.resolve() != out.resolve():
                shutil.copy(built, out)
            return f"uber-apk-signer ({Path(uber).name}, v1+v2+v3)"

        apksigner = os.environ.get("APKSIGNER", "")
        zipalign = os.environ.get("ZIPALIGN", "")
        keystore = os.environ.get("DEBUG_KEYSTORE", "")
        if not (apksigner and keystore):
            raise RuntimeError(
                f"No signer. Put uber-apk-signer.jar in {_TOOLS} "
                "(scripts/1-setup_frida_server.ps1 -SetupFridaServer) or set "
                "APKSIGNER + DEBUG_KEYSTORE (+ ZIPALIGN).")
        aligned = built.with_name("aligned.apk")
        if zipalign and Path(zipalign).is_file():
            rc, log = self._run([zipalign, "-f", "-p", "4", str(built), str(aligned)])
            if rc != 0:
                raise RuntimeError(f"zipalign failed:\n{log[-1000:]}")
        else:
            aligned = built
        ks_pass = os.environ.get("DEBUG_KS_PASS", "android")
        alias = os.environ.get("DEBUG_KS_ALIAS", "androiddebugkey")
        rc, log = self._run([
            apksigner, "sign", "--ks", keystore, "--ks-pass", f"pass:{ks_pass}",
            "--ks-key-alias", alias, "--key-pass", f"pass:{ks_pass}",
            "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
            "--v3-signing-enabled", "true", "--out", str(out), str(aligned)])
        if rc != 0:
            raise RuntimeError(f"apksigner failed:\n{log[-2000:]}")
        return "apksigner + zipalign (v1+v2+v3)"

    # ----- diagnostics (R2) ---------------------------------------------------
    def check_toolchain(self) -> str:
        out = ["Repackaging toolchain check:"]
        # apktool + java
        apk = _discover_apktool(self._apktool_override)
        if apk:
            rc, log = self._run([apk, "--version"])
            out.append(f"  [OK] apktool: {apk} ({log.strip().splitlines()[0] if log.strip() else '?'})")
        else:
            out.append("  [MISSING] apktool -> scripts/0-setup_environment.ps1")
        out.append(f"  [{'OK' if self._java_ok() else 'MISSING'}] Java (JRE/JDK 11+)")
        # frida host + gadget
        ver = _host_frida_version()
        out.append(f"  [{'OK' if ver else 'MISSING'}] host frida bindings: {ver or 'not importable'}")
        abi = self._device_abi()
        arch = _ARCH_MAP.get(abi, "")
        if arch and ver:
            g = _TOOLS / f"frida-gadget-{ver}-android-{arch}.so"
            if g.is_file():
                out.append(f"  [OK] frida-gadget: {g.name} (matches host {ver}, active-device abi {abi})")
            else:
                present = sorted(p.name for p in _TOOLS.glob(f"frida-gadget-*-android-{arch}.so"))
                out.append(f"  [MISSING] frida-gadget {ver}/{arch} (present: {present or 'none'}) "
                           "-> scripts/1-setup_frida_server.ps1 -SetupFridaServer")
        else:
            out.append(f"  [?] frida-gadget: cannot resolve (device abi='{abi}', host frida='{ver}')")
        # signer
        uber = self._uber_signer()
        if uber:
            out.append(f"  [OK] signer: uber-apk-signer ({Path(uber).name})")
        elif os.environ.get("APKSIGNER") and os.environ.get("DEBUG_KEYSTORE"):
            out.append(f"  [OK] signer: apksigner + keystore (env)")
        else:
            out.append("  [MISSING] signer -> scripts/1-setup_frida_server.ps1 "
                       "-SetupFridaServer (uber-apk-signer)")
        return "\n".join(out)

    # ----- public op (R1) -----------------------------------------------------
    def repackage_frida(self, target: str, arch: str = "", trust_user_certs: bool = True,
                        gadget_config: str = "", output_path: str = "",
                        keep_workdir: bool = False) -> str:
        if not self._java_ok():
            return "ERROR: Java not found. apktool/signing require JRE/JDK 11+."
        if not arch:
            arch = self._device_abi() or "arm64-v8a"
        if arch not in _ARCH_MAP:
            return f"ERROR: unsupported abi '{arch}'. Use one of {list(_ARCH_MAP)}."
        try:
            gadget, gname = self._gadget_for(arch)
        except RuntimeError as e:
            return f"ERROR: {e}"

        apk, key = resolve_apk(self.device_manager, target,
                               self.workspace / "repackage_src")
        base = self.workspace / "repackage"
        base.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix=f"{key}_", dir=str(base)))
        decoded = work / "decoded"
        keep = keep_workdir
        try:
            rc, log = self._run([self._apktool(), "d", "-f", "-o", str(decoded), str(apk)])
            if rc != 0 or not (decoded / "AndroidManifest.xml").is_file():
                keep = True
                return f"ERROR: apktool decode failed (workdir kept: {work}):\n{log[-3000:]}"

            # ABI sanity: app native libs vs chosen arch
            warn = ""
            libroot = decoded / "lib"
            app_abis = [p.name for p in libroot.iterdir()] if libroot.is_dir() else []
            if app_abis and arch not in app_abis:
                warn = (f"\n  WARNING: app ships native libs for {app_abis} but not "
                        f"{arch}; gadget added under lib/{arch} (device abi={arch}). "
                        "If the app forces a different ABI this may not load.")

            libdir = decoded / "lib" / arch
            libdir.mkdir(parents=True, exist_ok=True)
            shutil.copy(gadget, libdir / "libgadget.so")
            if gadget_config:
                (libdir / "libgadget.config.so").write_text(gadget_config, encoding="utf-8")

            try:
                entry = self._inject_loadlibrary(decoded, "gadget")
            except RuntimeError as e:
                keep = True
                return f"ERROR: gadget injection failed (workdir kept: {work}): {e}"

            nsc_note = self._apply_nsc(decoded) if trust_user_certs else "skipped"

            built = work / "built.apk"
            rc, log = self._run([self._apktool(), "b", "-o", str(built), str(decoded)])
            if rc != 0 or not built.is_file():
                keep = True
                return (f"ERROR: apktool build FAILED (workdir kept: {work}).\n"
                        f"Full log:\n{log}")

            out = Path(output_path) if output_path else (base / f"{key}-repackaged.apk")
            try:
                signer = self._sign(built, out)
            except RuntimeError as e:
                keep = True
                return f"ERROR: signing failed (workdir kept: {work}): {e}"

            cert = self._cert_sha256(out)
            return (
                f"OK: repackaged '{target}' -> {out}{warn}\n"
                f"  frida-gadget: {gname} (lib/{arch}/libgadget.so)\n"
                f"  loadLibrary injected into: {entry}\n"
                f"  networkSecurityConfig: {nsc_note}\n"
                f"  signed: {signer}; signing cert SHA-256: {cert}\n"
                f"  Next: install_and_launch('{out}', '<package>') then attach the "
                f"gadget (frida_attach) + frida_run_preset(session, 'ssl-unpin'). "
                f"If it crashes/refuses to run, suspect packer anti-tamper -> "
                f"static-first or gadget script-mode.")
        finally:
            if not keep:
                shutil.rmtree(work, ignore_errors=True)
