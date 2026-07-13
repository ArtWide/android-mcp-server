# Supported MCP Tools

Canonical list of the analysis tools this MCP server exposes. Generated from the
`@mcp.tool()` registrations in `server.py`; keep it in sync when tools change.

**Total: 54 tools.** A `target` argument is an installed **package name OR a path
to a local `.apk` file** (so uploaded droppers / downloaded payloads can be
analyzed without a device). Tools operate on the **active device** — when several
are connected, pick it with `select_device`.

| Group | Count |
|------|------|
| Device control & selection | 3 |
| ADB shell / inspection / logs | 7 |
| File transfer & install | 4 |
| HTTPS CA trust | 2 |
| Dynamic-analysis readiness | 1 |
| Baseline (before/after) | 2 |
| Live screen mirror (scrcpy) | 3 |
| Static analysis (androguard) | 4 |
| JADX (Java decompile) | 4 |
| apktool (resources/smali) | 3 |
| Frida (dynamic instrumentation) | 12 |
| Non-root repackaging | 2 |
| Network capture (mitmproxy) | 5 |
| Report evidence rendering | 2 |
| **Total** | **54** |

---

## Device control & selection (3)

| Tool | Args | Description |
|------|------|-------------|
| `list_devices` | — | List connected devices (serial + model), marking the active one. |
| `select_device` | `serial` | Switch the active device all subsequent tools operate on. |
| `get_current_device` | — | Report the currently active device (serial + model). |

## ADB shell / inspection / logs (7)

| Tool | Args | Description |
|------|------|-------------|
| `get_packages` | — | List all installed packages on the device. |
| `execute_adb_shell_command` | `command`, `timeout` | Run an arbitrary device shell command, bounded by a timeout (⚠️ powerful). |
| `get_uilayout` | — | Clickable UI elements + center coordinates of the current screen. |
| `get_screenshot` | — | Capture the screen as a (compressed) PNG image. |
| `wake_device` | `unlock` | Turn the screen on and optionally dismiss the keyguard (safe no-op when awake). |
| `get_package_action_intents` | `package_name` | Non-data intent actions an app handles (Activity Resolver Table). |
| `get_logcat` | `lines`, `filter_spec`, `priority` | Dump recent, filtered logcat output. |

## File transfer & install (4)

| Tool | Args | Description |
|------|------|-------------|
| `push_file` | `local_path`, `device_path` | Host → device file push (sample APK / tool / payload). |
| `pull_file` | `device_path`, `local_path` | Device → host file pull (e.g. a dropped payload). |
| `install_apk` | `apk_path`, `reinstall`, `grant_permissions`, `downgrade` | Install a host APK (adb install). |
| `install_and_launch` | `apk_path`, `package`, `launch`, `uninstall_existing` | Remove-conflict + install + launch (for re-signed APKs). |

## HTTPS CA trust (2)

| Tool | Args | Description |
|------|------|-------------|
| `install_user_ca` | `cert_source` | Push a CA to the user store + open the install screen (non-root; final tap is manual). |
| `install_system_ca` | `cert_source` | Install a CA into the **system** trust store on a rooted device (automated, trusted by all apps; reversible tmpfs overlay). |

## Dynamic-analysis readiness (1)

| Tool | Args | Description |
|------|------|-------------|
| `check_dynamic_readiness` | `cert_source` | One-shot preflight: device + root, Frida version match, mitmproxy + CA, HTTPS trust, capture, repackaging toolchain. |

## Baseline — before/after (2)

Read-only device-state snapshots stored in the workspace (not KVault).

| Tool | Args | Description |
|------|------|-------------|
| `capture_baseline` | `label`, `watch_dirs` | Snapshot packages, processes, `/proc/net` sockets, device-admins, security settings, watched-dir files. Take `pre` and `post`. |
| `diff_baseline` | `before`, `after` | Diff two snapshots → dropped packages, new C2 sockets, device-admin / accessibility / default-SMS changes, new files. |

## Live screen mirror — scrcpy (3)

Opens a native window **on the analyst PC** (not a feed inside the Claude client). scrcpy is installed by the setup by default.

| Tool | Args | Description |
|------|------|-------------|
| `start_screen_mirror` | `max_size`, `record` | Real-time low-latency mirror of the active device (+ mouse/keyboard control); optional mp4 recording. |
| `stop_screen_mirror` | — | Stop the mirror and finalize any recording. |
| `screen_mirror_status` | — | Report whether a mirror is running. |

## Static analysis — androguard (4, no root/Java)

| Tool | Args | Description |
|------|------|-------------|
| `analyze_manifest` | `target` | Permissions, **exported components**, debuggable/allowBackup/cleartext, SDK levels. |
| `apk_info` | `target` | Signing certificate(s), SHA-256, version, signed state. |
| `scan_secrets` | `target` | Hardcoded API keys / tokens / private keys / URLs / IPs in dex strings. |
| `apk_dropper_indicators` | `target` | Dropper verdict (dynamic loading / install-APK / crypto) + candidate **payload URLs**. |

## JADX — Java decompile (4)

| Tool | Args | Description |
|------|------|-------------|
| `jadx_decompile` | `target`, `include_splits` | Decompile an APK to Java. Run **once per target** before searching/reading. |
| `jadx_list_decompiled` | — | Packages already decompiled in the workspace. |
| `jadx_search_code` | `package_name`, `pattern`, `max_results` | Regex-search decompiled Java sources. |
| `jadx_read_source` | `package_name`, `relative_path` | Read one decompiled `.java` file. |

## apktool — resources/smali (3, needs Java)

| Tool | Args | Description |
|------|------|-------------|
| `apktool_decode` | `target` | Decode resources + decoded manifest + smali. Run **once per target** first. |
| `apktool_list_files` | `package_name`, `subdir` | List files in the decoded output. |
| `apktool_read_file` | `package_name`, `relative_path` | Read one decoded file (manifest / xml / smali). |

## Frida — dynamic instrumentation (12, frida-server or gadget)

| Tool | Args | Description |
|------|------|-------------|
| `frida_check_compatibility` | `server_path` | Host frida ↔ device frida-server version match + running state (**call first**). |
| `frida_list_devices` | — | Devices visible to Frida (usb/remote/local). |
| `frida_list_processes` | — | Running processes on the device. |
| `frida_list_applications` | — | Installed applications. |
| `frida_attach` | `target` | Attach to a running process/PID → `session_id`. |
| `frida_spawn` | `package_name` | Spawn an app suspended and attach → `session_id`. |
| `frida_run_script` | `session_id`, `script_source` | Inject + load a JS instrumentation script (resumes a spawned process). |
| `frida_run_preset` | `session_id`, `preset` | Load a bundled preset (e.g. `ssl-unpin`); works with gadget too. |
| `frida_read_messages` | `session_id` | Drain `send()` / error messages from a session's script. |
| `frida_resume` | `session_id` | Resume a spawned, still-suspended process. |
| `frida_list_sessions` | — | Active Frida sessions held by the server. |
| `frida_detach` | `session_id` | Detach a session and remove it from the registry. |

## Non-root repackaging (2)

| Tool | Args | Description |
|------|------|-------------|
| `repackage_apk_frida` | `target`, `arch`, `trust_user_certs`, `gadget_config`, `output_path`, `keep_workdir` | Inject frida-gadget (Application `<clinit>`) + optional user-CA trust merge + rebuild + v1/v2/v3 re-sign. Auto-detects ABI; returns full log on failure. |
| `check_repackage_toolchain` | — | Host readiness for the above: apktool, Java, host frida, gadget `.so`, signer. |

## Network capture — mitmproxy (5)

| Tool | Args | Description |
|------|------|-------------|
| `network_start_capture` | `port` | Start mitmdump + `adb reverse` + set the device HTTP proxy. |
| `network_list_flows` | `limit` | List captured flows (method, status, URL, sizes). |
| `network_get_flow` | `index` | One flow's full detail: request/response headers + decoded body. |
| `network_stop_capture` | — | Stop capture and clear the device proxy / adb reverse. |
| `network_status` | — | Whether a capture is running. |

## Report evidence rendering (2)

House-style, deterministic PNGs for the analysis report (use these, not ad-hoc artifacts).

| Tool | Args | Description |
|------|------|-------------|
| `render_code_image` | `code`, `language`, `highlight_lines`, `annotations`, `title`, `start_line` | Annotated code snippet → light-theme PNG (red boxes + inline `//` notes). |
| `render_log_evidence` | `text`, `annotations`, `highlight_lines`, `title`, `start_line` | Log/packet evidence → dark-theme PNG with a right-side `>>` annotation column. |
