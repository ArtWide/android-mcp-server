"""Static APK analysis with androguard: manifest/permissions/exported
components, signing & metadata, and a hardcoded-secret/endpoint scanner.

Pulls the package's base.apk from the device (shared workspace with the JADX
tools) and inspects it without needing root or external Java tools.
"""

import hashlib
import re
from pathlib import Path

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


class StaticAnalysisManager:
    def __init__(self, device_manager, output_dir: str | None = None) -> None:
        self.device_manager = device_manager
        self.output_dir = Path(output_dir) if output_dir else DEFAULT_WORKSPACE

    # ----- apk loading --------------------------------------------------------
    def _apk_path(self, package_name: str) -> Path:
        apk_dir = self.output_dir / package_name / "apk"
        apks = self.device_manager.pull_apk(
            package_name, apk_dir, include_splits=False)
        return apks[0]

    def _load(self, package_name: str):
        # Imported lazily so the server still starts if androguard is missing.
        from androguard.core.apk import APK
        return APK(str(self._apk_path(package_name)))

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

    def analyze_manifest(self, package_name: str) -> str:
        apk = self._load(package_name)

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
    def apk_info(self, package_name: str) -> str:
        path = self._apk_path(package_name)
        apk = self._load(package_name)

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

    def scan_secrets(self, package_name: str) -> str:
        apk = self._load(package_name)
        strings = self._dex_strings(apk)

        results: dict[str, set[str]] = {label: set() for label, _, _ in _SECRET_PATTERNS}
        for s in strings:
            for label, rx, _ in _SECRET_PATTERNS:
                for m in rx.findall(s):
                    results[label].add(m)

        out = [f"Scanned {len(strings)} dex strings in '{package_name}'", ""]
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
