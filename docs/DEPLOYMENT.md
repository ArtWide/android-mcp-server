# Deployment & Troubleshooting

How this server is run in our environment, and the non-obvious things that cost
time to discover. Read this before re-litigating transport/connector decisions.

## Architecture summary

- The server runs over **Streamable HTTP** as a **long-lived process** so the
  ADB connection and Frida sessions survive client reconnects (stdio spawned a
  new process per client and killed long-running sessions like frida).
- Recommended deployment: **per-analyst, on the PC the device is attached to**,
  bound to `127.0.0.1`. The powerful adb/jadx/frida surface stays off the network.
- Tools: 56 total across ADB/logcat, device selection, file transfer/install,
  CA trust (user + rooted system store), a dynamic-readiness preflight, baseline
  capture/diff, live screen mirror (scrcpy), JADX, androguard static, apktool,
  Frida, non-root repackaging, mitmproxy network capture, and report-evidence
  rendering. Managers are constructed once and reused for the process lifetime.
  Full per-tool reference: [TOOLS.md](TOOLS.md).

## Running the server

```powershell
# install everything that is missing (ADB / Java / JADX / Frida host bindings)
powershell -ExecutionPolicy Bypass -File scripts\0-setup_environment.ps1

# run (defaults to streamable-http on 127.0.0.1:8000)
powershell -ExecutionPolicy Bypass -File scripts\3-run_server.ps1
```

`config.yaml` (git-ignored) controls transport/host/port/auth/TLS. Precedence:
**CLI args > env vars > config.yaml**.

> **Tool env vars.** `0-0-setup_environment.ps1` sets the `JADX_PATH` / `JAVA_HOME`
> / `APKTOOL_PATH` / `ADB_PATH` user environment variables. `3-run_server.ps1`
> loads them into its session automatically, so launching it (even from an old
> terminal) is enough; if you run `server.py` directly instead, open a fresh
> terminal first so it inherits them.

### Troubleshooting: "Failed to spawn: python" (Smart App Control)

On Windows with **Smart App Control (SAC)** on, `uv run` can fail with
`Failed to spawn: python ... 애플리케이션 제어 정책에서 이 파일을 차단했습니다 (os error 4551)`
— SAC blocks uv's *managed* Python (an unsigned exe under `%APPDATA%\uv\python`).
The project's `.venv\Scripts\python.exe` is unaffected, so `3-run_server.ps1`
runs the server with the venv interpreter directly (no `uv run`) and this is
avoided. If you still hit it during `uv sync` on a fresh machine: create the
venv from an allowed interpreter, or check SAC state at
`HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy\VerifiedAndReputablePolicyState`
(0=off, 1=on, 2=eval) and the block in Event Viewer →
`Microsoft-Windows-CodeIntegrity/Operational`. SAC is reputation-based (not an
AV exclusion), so Defender folder exclusions do not help.

## Connecting Claude — what actually works here

### The web org connector does NOT work for a local server

Adding the server via the **claude.ai org admin web console** fails:

```
Localhost URLs cannot be used because our servers cannot reach your local
machine. Provide a publicly accessible MCP server URL.
```

The org web connector is **reached by Anthropic's cloud**, so:

- `localhost` / `127.0.0.1` is rejected by design.
- A self-signed or internal-CA certificate is also useless for this path — it
  would need a **publicly trusted** cert and a **publicly reachable** host.
- This is why a tunnel or public host (which we chose not to use) would be the
  *only* way to use the web connector — not worth it for a local-device tool.

### Use Claude Desktop + mcp-remote instead (this is the working path)

Claude Desktop runs locally and reaches `127.0.0.1`. Register the server in
`claude_desktop_config.json` via the `mcp-remote` bridge.

**Automated:** `scripts\2-register_claude_desktop.ps1` discovers the config (both
the standard and the MSIX package-virtualized locations below), merges the
`Android Local MCP` entry without disturbing other settings, and writes a
timestamped backup first (`-DryRun` to preview, `-All` to update every location,
`-Port`/`-Token` to customize). Round-trip fidelity of the deep config was
verified.

**Manual:**

```json
{
  "mcpServers": {
    "Android Local MCP": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://127.0.0.1:8000/mcp"]
    }
  }
}
```

`mcp-remote` is a thin stdio↔HTTP proxy; the real HTTP server stays up
independently, so Frida sessions survive Claude Desktop restarts. No TLS needed
for localhost.

### IMPORTANT: the config file path for the Microsoft Store (MSIX) build

Our Claude Desktop is the **Microsoft Store / MSIX** build
(`...WindowsApps\Claude_..._pzs8sxrjxfjjc\`). It does **not** read
`%APPDATA%\Claude\claude_desktop_config.json`. The real file is under the
package-virtualized path:

```
%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json
```

Logs are in the `logs\` subfolder there (`mcp.log`, `mcp-server-*.log`,
`main.log`). Editing the `%APPDATA%` copy has no effect.

After editing, **fully quit** Claude Desktop (tray → Quit; closing the window
leaves it running and the config is not reloaded), then relaunch.

### Harmless console noise

On connect you'll see, in the server console:

```
GET /mcp 400
GET /.well-known/oauth-protected-resource/mcp 404
GET /.well-known/oauth-protected-resource 404
GET /.well-known/oauth-authorization-server 404
```

These are `mcp-remote`'s OAuth discovery probes + a normal 400 on a bare GET.
The server has no OAuth, so it 404s and mcp-remote falls back to no-auth. Tools
still work. Not an error.

## Device prerequisites

### USB debugging authorization (required for all ADB/Frida tools)

A device shown as `unauthorized` blocks every ADB call. On the device, accept
the "Allow USB debugging?" dialog (check "Always allow from this computer").
`adb kill-server && adb start-server && adb devices` re-triggers the prompt.
Once `device` state is reached, the running server picks it up without a restart
(ppadb reconnects by serial per call).

### Frida needs root (deferred on the current device)

`frida_*` tools need a **frida-server running as root** on the device. Our test
device **SM-G986N (Galaxy S20+, Android 13, arm64-v8a) is NOT rooted**
(`adb root` → "cannot run as root in production builds"; no `su`). So Frida is
deferred; **ADB + JADX are in use**.

To use Frida later, use a **rooted device** or an **Android emulator** (Google
APIs AVD image supports `adb root`), then push a frida-server whose **major
version matches** the host `frida` (currently 17.x). The dedicated
`scripts\1-setup_frida_server.ps1` version-checks the device and pushes the right
build (`-Start` launches it on a rooted device); confirm with the
`frida_check_compatibility` tool:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\1-setup_frida_server.ps1 -Start
# (or, as part of the full installer) scripts\0-setup_environment.ps1 -SetupFridaServer -StartFridaServer
```

Verified: `1-setup_frida_server.ps1` pushed frida-server 17.15.3 (arm64) to the
test device and `frida_check_compatibility` reported an exact version match; it
just can't be launched there (no root).

## Verified tool status (current device)

A point-in-time verification snapshot on the current device (not the full
inventory — see [TOOLS.md](TOOLS.md) for all 56 tools):

| Tool group | Status |
|------------|--------|
| ADB + logcat (6) | Working — verified (get_packages: 454 pkgs, shell commands OK) |
| Baseline capture/diff (2) | Read-only; best on a rooted device (/proc/net + app dirs fully readable) |
| JADX (4) | Working — verified end-to-end (pull APK → decompile → search) |
| androguard static (3) | Working — verified on Chrome (manifest, signing cert, secret scan); no root needed |
| apktool (3) | Needs apktool + Java (installed by 0-setup_environment.ps1); no root needed |
| Frida (10) | Deferred — device not rooted |
| mitmproxy network (4) | Needs mitmproxy; HTTPS needs the mitmproxy CA trusted on device |

### Network capture (mitmproxy) notes

`network_start_capture` runs mitmdump, sets `adb reverse tcp:PORT tcp:PORT`, and
sets the device's global HTTP proxy to `127.0.0.1:PORT`. HTTP is captured
immediately; for **HTTPS** the device must trust the mitmproxy CA. On a
**rooted** device use `install_system_ca` (automated tmpfs overlay on the system
cacerts; trusted by all apps incl. targetSdk>=24, reversible via `umount`). On
**non-rooted** Android 7+, only apps that trust user CAs (`install_user_ca` +
`repackage_apk_frida(trust_user_certs=True)`) or with frida unpinning
(`frida_run_preset('ssl-unpin')`) are decrypted. `network_stop_capture` clears
the proxy and removes the reverse. `check_dynamic_readiness` confirms whether
the CA landed and the rest of the stack is ready. Android 14+ (APEX conscrypt
store) may ignore a /system overlay — use a Magisk cert module or ssl-unpin.
