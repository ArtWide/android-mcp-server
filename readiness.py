"""One-shot readiness check for the whole dynamic-analysis stack.

Aggregates the state that dynamic tools depend on -- device + root, Frida
host/server version match, mitmproxy (host binary + CA), HTTPS trust on the
device, active capture, and the non-root repackaging toolchain -- into a single
checklist with [OK]/[!]/[X] markers and a fix hint for anything missing. This
complements check_repackage_toolchain (which covers only repackaging) so an
analyst can confirm the environment before installing/running a sample.

Read-only: it inspects, never changes device or host state.
"""

from pathlib import Path


def _mark(ok: bool, warn: bool = False) -> str:
    return "[OK]" if ok else ("[!] " if warn else "[X] ")


def dynamic_readiness(device_manager, frida_manager, network_manager,
                      repackage_manager, cert_source: str = "") -> str:
    lines: list[str] = []

    def section(title: str):
        lines.append(f"\n[{title}]")

    # -- device ------------------------------------------------------------
    dev = device_manager
    serial = model = sdk = rel = "?"
    try:
        serial = dev.device.serial or "?"
        model = dev.device.shell("getprop ro.product.model").strip() or "?"
        sdk = dev.device.shell("getprop ro.build.version.sdk").strip() or "?"
        rel = dev.device.shell("getprop ro.build.version.release").strip() or "?"
    except Exception as e:
        lines.append(f"[X]  device query failed: {e}")

    lines.append(
        f"Dynamic analysis readiness -- {serial} ({model}), "
        f"Android {rel} (SDK {sdk})")

    section("device")
    lines.append(f"  {_mark(serial != '?')} active device: {serial} ({model})")
    rooted = False
    try:
        rooted = dev.is_rooted()
    except Exception:
        pass
    lines.append(
        f"  {_mark(rooted, warn=True)} root: "
        + ("available (su uid=0)" if rooted
           else "NOT available -> HTTPS needs install_user_ca+repackage or ssl-unpin"))

    # -- frida -------------------------------------------------------------
    section("frida")
    try:
        report = frida_manager.check_compatibility()
        for ln in report.splitlines():
            lines.append(f"  {ln}")
    except Exception as e:
        lines.append(f"  [X]  frida check failed: {e}")

    # -- network / mitmproxy ----------------------------------------------
    section("network / mitmproxy")
    mitm = None
    try:
        from networkmanager import _discover_mitmdump
        mitm = _discover_mitmdump()
    except Exception as e:
        lines.append(f"  [X]  mitmdump discovery failed: {e}")
    lines.append(
        f"  {_mark(bool(mitm))} mitmdump on host: "
        + (mitm if mitm else "MISSING -> install mitmproxy (mitmproxy.org)"))

    host_ca = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer"
    lines.append(
        f"  {_mark(host_ca.is_file())} host CA generated: "
        + (str(host_ca) if host_ca.is_file()
           else "MISSING -> run mitmproxy once to generate ~/.mitmproxy"))
    try:
        status = network_manager.status()
        lines.append(f"  [i]  capture: {status}")
    except Exception as e:
        lines.append(f"  [!]  capture status unavailable: {e}")

    # -- HTTPS trust on device --------------------------------------------
    section("HTTPS trust (device)")
    if not host_ca.is_file():
        lines.append("  [X]  no host CA to check against (see above)")
    else:
        try:
            st = device_manager.ca_trust_status(cert_source)
            lines.append(
                f"  {_mark(st['in_system'], warn=True)} system CA ({st['filename']}): "
                + ("trusted (all apps)" if st["in_system"]
                   else "not installed -> install_system_ca (rooted, recommended)"))
            lines.append(
                f"  {_mark(st['in_user'], warn=True)} user CA: "
                + ("present" if st["in_user"]
                   else "not installed (targetSdk>=24 apps ignore user CAs)"
                        + ("" if st["rooted"] else " [user-store check needs root]")))
        except Exception as e:
            lines.append(f"  [!]  CA trust check failed: {e}")
    lines.append("  [i]  pinned apps still require frida_run_preset('ssl-unpin')")

    # -- repackage toolchain (non-root fallback) --------------------------
    section("repackage toolchain (non-root fallback)")
    try:
        tc = repackage_manager.check_toolchain()
        for ln in tc.splitlines():
            lines.append(f"  {ln}")
    except Exception as e:
        lines.append(f"  [!]  toolchain check failed: {e}")

    return "\n".join(lines)
