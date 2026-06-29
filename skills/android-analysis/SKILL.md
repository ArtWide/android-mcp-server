---
name: android-analysis
description: >-
  Analyze and automate Android devices and apps through the Android Local MCP
  server. Use when the user wants to inspect a device/app, list or pull
  packages, read permissions/manifests, decompile an APK (JADX/apktool), search
  decompiled code, scan an app for hardcoded secrets/endpoints, capture or
  inspect network traffic (mitmproxy), instrument an app at runtime (Frida),
  drive the device UI (tap/type/screenshot), or read logcat. Covers reverse
  engineering, mobile security review, app debugging, and UI automation.
---

# Android App & Device Analysis

This skill drives the **Android Local MCP** server (an ADB-based MCP) to analyze
and automate a connected Android device. Tools fall into five groups; pick the
smallest set that answers the user's question and prefer read-only inspection
before changing device state.

## When to use
Use whenever the task involves a real Android device/emulator or an installed
app: "what permissions does X request", "find hardcoded keys in this app",
"decompile this APK", "hook this function with frida", "capture the app's
traffic", "tap this button / automate this screen", "why is the app crashing"
(logcat), "is the app debuggable / who signed it", etc.

## Tools (call by exact name)

**Device control (ADB)**
- `get_packages` — list installed packages.
- `execute_adb_shell_command(command)` — run any adb shell command (powerful).
- `get_uilayout` — clickable UI elements + center coordinates of the current screen.
- `get_screenshot` — capture the screen as an image.
- `get_package_action_intents(package_name)` — intent actions an app handles.
- `get_logcat(lines, filter_spec, priority)` — recent device logs.

**Static analysis — fast overview (androguard, no root, no Java)**
- `analyze_manifest(package_name)` — permissions, **exported components**, debuggable/allowBackup/cleartext, SDK levels.
- `apk_info(package_name)` — signing certificate(s), SHA-256, version, signed state.
- `scan_secrets(package_name)` — hardcoded API keys, tokens, private keys, URLs, IPs in dex strings.

**Static analysis — deep (JADX = Java, apktool = resources/smali; need Java)**
- `jadx_decompile(package_name, include_splits)` — decompile to Java. Run **once per package** before searching/reading.
- `jadx_list_decompiled` — packages already decompiled.
- `jadx_search_code(package_name, pattern, max_results)` — regex over decompiled Java.
- `jadx_read_source(package_name, relative_path)` — read one decompiled `.java` file.
- `apktool_decode(package_name)` — decode resources + decoded AndroidManifest.xml + smali. Run **once per package** first.
- `apktool_list_files(package_name, subdir)` / `apktool_read_file(package_name, relative_path)` — browse/read decoded output.

**Dynamic instrumentation (Frida — needs frida-server running as root on device)**
- `frida_check_compatibility` — **call first**; reports host vs device frida-server version and whether it's running.
- `frida_list_devices` / `frida_list_processes` / `frida_list_applications`.
- `frida_spawn(package_name)` — start app suspended → `session_id`.
- `frida_attach(target)` — attach to a running process/PID → `session_id`.
- `frida_run_script(session_id, script_source)` — inject JS (resumes a spawned process). Emit data with `send(...)`.
- `frida_read_messages(session_id)` — drain script output. `frida_resume`, `frida_list_sessions`, `frida_detach`.

**Network capture (mitmproxy)**
- `network_start_capture(port)` — proxy the device's traffic via mitmdump (sets adb reverse + device proxy).
- `network_list_flows(limit)` — captured requests/responses. `network_stop_capture`, `network_status`.

## Workflows (recipes)

**App security triage (no root needed)**
1. `analyze_manifest(pkg)` — attack surface (exported components, dangerous perms, debuggable/cleartext).
2. `apk_info(pkg)` — who signed it, integrity hash.
3. `scan_secrets(pkg)` — hardcoded credentials/endpoints.
4. If something looks interesting, go deep: `jadx_decompile(pkg)` then `jadx_search_code(pkg, "<pattern>")` and `jadx_read_source(...)`.

**Read app code**
- `jadx_decompile(pkg)` once → `jadx_search_code(pkg, "password|http|Cipher|getString")` → `jadx_read_source(pkg, "<path from the search hit>")`.
- For resources, deep links, or smali: `apktool_decode(pkg)` → `apktool_list_files` / `apktool_read_file` (e.g. `AndroidManifest.xml`, `res/values/strings.xml`).

**UI automation**
1. `get_screenshot` + `get_uilayout` to see the screen and element coordinates.
2. `execute_adb_shell_command("input tap X Y")` / `input text "..."` / `input keyevent KEYCODE_BACK`.
3. `get_screenshot` to confirm the result. Repeat.

**Dynamic instrumentation (rooted device / emulator)**
1. `frida_check_compatibility` — if frida-server is missing or version-mismatched, tell the user to run `scripts/1-setup_frida_server.ps1` (and that the device must be rooted). Do not proceed until it's compatible and running.
2. `frida_spawn(pkg)` (early hooks) or `frida_attach(target)` (running app) → `session_id`.
3. `frida_run_script(session_id, "<JS that hooks and calls send(...)>")`.
4. Poll `frida_read_messages(session_id)`; finish with `frida_detach(session_id)`.

**Network traffic**
1. `network_start_capture(8080)`.
2. Trigger traffic in the app (often via UI automation above).
3. `network_list_flows(50)`; for HTTPS the device must trust the mitmproxy CA (open `http://mitm.it` while proxied) — non-rooted Android 7+ only decrypts apps that trust user CAs.
4. `network_stop_capture` when done (restores the device proxy).

## Important rules
- **Decompile/decode once.** Call `jadx_decompile` / `apktool_decode` a single time per package, then search/read; never re-decompile to "refresh".
- **Frida prerequisites.** Always `frida_check_compatibility` before frida work. Frida needs frida-server (root). On a non-rooted device, say so and fall back to static analysis instead of repeatedly retrying.
- **`execute_adb_shell_command` is powerful.** It runs arbitrary shell commands. For anything that changes device/app state (uninstall, clear data, settings, file deletion, `pm`/`am force-stop`), confirm with the user first. Prefer the dedicated tools over raw shell when one exists.
- **Manage output size.** Prefer `scan_secrets`/`jadx_search_code` over dumping whole files; read specific files by the paths search returns. Note `scan_secrets` IPv4 matches include some false positives (e.g. OID-like `2.5.29.37`).
- **Privacy.** Screenshots and UI dumps can expose personal data; surface only what's needed.
- **Resolve package names** with `get_packages` when the user gives an app name rather than a package id.
- **Report faithfully.** If a tool errors (unauthorized device, no frida-server, jadx/apktool not installed), relay the message and the fix (USB debugging prompt; `scripts/0-setup_environment.ps1`; `scripts/1-setup_frida_server.ps1`) instead of guessing.

## Authorization
Only analyze devices and apps the user owns or is explicitly authorized to test
(personal device, test build, sanctioned security assessment). If intent is
unclear for an invasive action (instrumentation, traffic interception, modifying
another app), confirm authorization first.
