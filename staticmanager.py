"""Static APK analysis with androguard: manifest/permissions/exported
components, signing & metadata, and a hardcoded-secret/endpoint scanner.

Pulls the package's base.apk from the device (shared workspace with the JADX
tools) and inspects it without needing root or external Java tools.
"""

import hashlib
import re
from pathlib import Path

from apkutils import resolve_apk

# androguard logs verbosely via loguru; silence it so it does not flood the
# server console / tool output.
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.disable("androguard")
except Exception:
    pass

_HERE = Path(__file__).parent
DEFAULT_WORKSPACE = _HERE / "workspace"

# (label, compiled-regex, cap) for the secret/endpoint scanner.
_SECRET_PATTERNS = [
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), 50),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}"), 50),
    ("Firebase DB URL", re.compile(r"https://[a-z0-9.-]+\.firebaseio\.com"), 50),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), 50),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), 30),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), 20),
    ("URL", re.compile(r"https?://[^\s\"'<>\\)]+"), 100),
    ("IPv4 address", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), 60),
]

_URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+")
# URL pointing at a downloadable second-stage payload.
_PAYLOAD_URL_RE = re.compile(r"https?://[^\s\"'<>\\)]+\.(?:apk|dex|jar|so)\b", re.I)

# Substrings (matched case-insensitively against dex strings) that signal
# dropper / dynamic-payload behaviour.
_DROPPER_INDICATORS = {
    "dynamic_code_loading": [
        "dexclassloader", "pathclassloader", "inmemorydexclassloader",
        "basedexclassloader", "loadclass", "defineclass", "opendexfile"],
    "reflection": [
        "getdeclaredmethod", "getdeclaredfield", "setaccessible",
        "java/lang/reflect", "java.lang.reflect"],
    "native_exec": [
        "java/lang/runtime", "getruntime", "processbuilder", "/system/bin/sh"],
    "install_apk": [
        "vnd.android.package-archive", "packageinstaller",
        "action_install_package", "installpackage"],
    "crypto_decrypt": [
        "javax/crypto", "javax.crypto", "secretkeyspec", "ivparameterspec",
        "cipher", "dofinal"],
    "anti_analysis": [
        "isdebuggerconnected", "ro.debuggable", "test-keys", "qemu",
        "goldfish", "genymotion"],
}


class StaticAnalysisManager:
    def __init__(self, device_manager, output_dir: str | None = None) -> None:
        self.device_manager = device_manager
        self.output_dir = Path(output_dir) if output_dir else DEFAULT_WORKSPACE

    # ----- apk loading --------------------------------------------------------
    # A "target" is an installed package name OR a path to a local .apk file.
    def _apk_path(self, target: str) -> Path:
        path, _ = resolve_apk(self.device_manager, target, self.output_dir)
        return path

    def _load(self, target: str):
        # Imported lazily so the server still starts if androguard is missing.
        from androguard.core.apk import APK
        return APK(str(self._apk_path(target)))

    # ----- manifest -----------------------------------------------------------
    def _exported_components(self, apk, kind: str, names: list[str]) -> list[str]:
        out = []
        for name in names:
            exported = apk.get_attribute_value(kind, "exported", name=name)
            has_filter = bool(apk.get_intent_filters(kind, name))
            if exported == "true":
                out.append(f"{name}  [exported=true]")
            elif exported is None and has_filter:
                out.append(f"{name}  [implicit via intent-filter]")
        return out

    def analyze_manifest(self, target: str) -> str:
        apk = self._load(target)

        debuggable = apk.get_attribute_value("application", "debuggable")
        allow_backup = apk.get_attribute_value("application", "allowBackup")
        cleartext = apk.get_attribute_value("application", "usesCleartextTraffic")
        nsc = apk.get_attribute_value("application", "networkSecurityConfig")

        perms = sorted(apk.get_permissions())
        dangerous = [p for p in perms if any(
            k in p for k in ("SMS", "CALL", "CONTACTS", "LOCATION", "CAMERA",
                             "RECORD_AUDIO", "STORAGE", "PHONE", "ACCOUNTS",
                             "CALENDAR", "BODY_SENSORS"))]

        exported = []
        exported += [f"activity  {c}" for c in self._exported_components(apk, "activity", apk.get_activities())]
        exported += [f"service   {c}" for c in self._exported_components(apk, "service", apk.get_services())]
        exported += [f"receiver  {c}" for c in self._exported_components(apk, "receiver", apk.get_receivers())]
        exported += [f"provider  {c}" for c in self._exported_components(apk, "provider", apk.get_providers())]

        lines = [
            f"Package: {apk.get_package()}",
            f"Version: {apk.get_androidversion_name()} ({apk.get_androidversion_code()})",
            f"SDK: min={apk.get_min_sdk_version()} target={apk.get_target_sdk_version()} max={apk.get_max_sdk_version()}",
            f"Main activity: {apk.get_main_activity()}",
            "",
            "Security flags:",
            f"  debuggable: {debuggable or 'false'}",
            f"  allowBackup: {allow_backup if allow_backup is not None else 'true (default)'}",
            f"  usesCleartextTraffic: {cleartext if cleartext is not None else 'unset'}",
            f"  networkSecurityConfig: {nsc or 'none'}",
            "",
            f"Permissions ({len(perms)}):",
        ]
        lines += [f"  {p}" for p in perms]
        if dangerous:
            lines += ["", f"Dangerous-permission highlights ({len(dangerous)}):"]
            lines += [f"  ! {p}" for p in dangerous]
        lines += ["", f"Exported components ({len(exported)}):"]
        lines += [f"  {c}" for c in exported] if exported else ["  (none)"]
        return "\n".join(lines)

    # ----- signing & metadata -------------------------------------------------
    def apk_info(self, target: str) -> str:
        path = self._apk_path(target)
        apk = self._load(target)

        sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        lines = [
            f"Package: {apk.get_package()}",
            f"Version: {apk.get_androidversion_name()} ({apk.get_androidversion_code()})",
            f"APK file: {path.name}  ({path.stat().st_size} bytes)",
            f"APK SHA-256: {sha256}",
            f"Signed: {apk.is_signed()}",
            "",
            "Signing certificates:",
        ]
        certs = apk.get_certificates()
        if not certs:
            lines.append("  (none found)")
        for i, cert in enumerate(certs, 1):
            try:
                fp = hashlib.sha256(cert.dump()).hexdigest()
                subj = cert.subject.human_friendly
                issuer = cert.issuer.human_friendly
                serial = cert.serial_number
                nb = cert["tbs_certificate"]["validity"]["not_before"].native
                na = cert["tbs_certificate"]["validity"]["not_after"].native
                lines += [
                    f"  [{i}] subject: {subj}",
                    f"      issuer:  {issuer}",
                    f"      serial:  {serial}",
                    f"      valid:   {nb}  ->  {na}",
                    f"      sha256:  {fp}",
                ]
            except Exception as e:
                lines.append(f"  [{i}] (failed to parse: {e})")
        return "\n".join(lines)

    # ----- secret / endpoint scanner -----------------------------------------
    def _dex_strings(self, apk) -> set[str]:
        from androguard.core.dex import DEX
        strings: set[str] = set()
        for dex_bytes in apk.get_all_dex():
            try:
                strings.update(DEX(dex_bytes).get_strings())
            except Exception:
                continue
        return strings

    def scan_secrets(self, target: str) -> str:
        apk = self._load(target)
        strings = self._dex_strings(apk)

        results: dict[str, set[str]] = {label: set() for label, _, _ in _SECRET_PATTERNS}
        for s in strings:
            for label, rx, _ in _SECRET_PATTERNS:
                for m in rx.findall(s):
                    results[label].add(m)

        out = [f"Scanned {len(strings)} dex strings in '{target}'", ""]
        any_found = False
        for label, _, cap in _SECRET_PATTERNS:
            hits = sorted(results[label])
            if not hits:
                continue
            any_found = True
            shown = hits[:cap]
            out.append(f"{label} ({len(hits)}):")
            out += [f"  {h}" for h in shown]
            if len(hits) > cap:
                out.append(f"  ... (+{len(hits) - cap} more)")
            out.append("")
        if not any_found:
            out.append("No matches for the configured secret/endpoint patterns.")
        return "\n".join(out).rstrip()

    # ----- dropper / dynamic-loading indicators ------------------------------
    def dropper_indicators(self, target: str) -> str:
        """Flag dropper / dynamic-payload behaviour and candidate payload URLs.

        Droppers fetch a second-stage APK/DEX and load it at runtime, then that
        payload talks to the C2. This surfaces the static signals (dynamic code
        loading, reflection, package install, crypto, anti-analysis), risky
        permissions, and URLs that look like payload downloads, so the analyst
        can pivot to dynamic capture and recurse into the payload.
        """
        apk = self._load(target)
        strings = self._dex_strings(apk)
        low = [s.lower() for s in strings]

        hits: dict[str, list[str]] = {}
        for cat, needles in _DROPPER_INDICATORS.items():
            found = sorted({n for n in needles if any(n in s for s in low)})
            if found:
                hits[cat] = found

        perms = set(apk.get_permissions())
        risky = sorted(p for p in perms if any(k in p for k in (
            "REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES", "SYSTEM_ALERT_WINDOW",
            "BIND_ACCESSIBILITY", "RECEIVE_BOOT_COMPLETED", "WRITE_EXTERNAL_STORAGE",
            "READ_SMS", "RECEIVE_SMS", "SEND_SMS")))

        payload_urls, all_urls = set(), set()
        for s in strings:
            for m in _PAYLOAD_URL_RE.findall(s):
                payload_urls.add(m if isinstance(m, str) else m[0])
            for u in _URL_RE.findall(s):
                all_urls.add(u)
        payload_urls = sorted(payload_urls)
        # URLs that aren't already flagged as payloads (candidate C2 / config).
        other_urls = sorted(set(all_urls) - set(payload_urls))[:40]

        # Weight the verdict on STRONG signals; generic indicators (reflection,
        # crypto, dynamic loading) also appear in many benign apps, so they are
        # shown as context but don't by themselves mean "dropper".
        has_install_perm = any("REQUEST_INSTALL_PACKAGES" in p for p in perms)
        strong = []
        if payload_urls:
            strong.append("candidate payload-download URL(s) (.apk/.dex/.jar/.so)")
        if has_install_perm:
            strong.append("REQUEST_INSTALL_PACKAGES permission")
        if "dynamic_code_loading" in hits and "install_apk" in hits:
            strong.append("dynamic code loading + package install APIs together")

        if payload_urls or has_install_perm:
            verdict = "HIGH"
        elif strong or "dynamic_code_loading" in hits:
            verdict = "MEDIUM"
        else:
            verdict = "LOW"

        out = [f"Dropper assessment for '{target}': likelihood {verdict}", ""]
        if strong:
            out.append("Strong signals (drive the verdict):")
            out += [f"  * {s}" for s in strong]
            out.append("")
        if hits:
            out.append("Indicators (context; reflection/crypto/dynamic-loading are "
                       "also common in benign apps):")
            for cat, found in hits.items():
                out.append(f"  {cat}: {', '.join(found)}")
            out.append("")
        if risky:
            out.append("Risky permissions:")
            out += [f"  ! {p}" for p in risky]
            out.append("")
        if payload_urls:
            out.append("Candidate payload-download URLs (.apk/.dex/.jar/.so):")
            out += [f"  -> {u}" for u in payload_urls]
            out.append("")
        if other_urls:
            out.append(f"Other URLs (candidate C2 / config, {len(other_urls)} shown):")
            out += [f"  {u}" for u in other_urls]
            out.append("")
        out.append(
            "Next: pivot to dynamic capture (install on the analysis device, "
            "network_start_capture, run the app) to catch the actual payload "
            "download + C2, then re-run these tools on the payload APK to find "
            "its C2 (recurse).")
        return "\n".join(out).rstrip()
