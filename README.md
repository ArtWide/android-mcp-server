# Android MCP Server

> 한국어 문서: [README_kr.md](README_kr.md)

An MCP (Model Context Protocol) server that provides programmatic control over
Android devices through ADB (Android Debug Bridge). This server exposes
various Android device management capabilities that can be accessed by MCP
clients like [Claude desktop](https://modelcontextprotocol.io/quickstart/user)
and Code editors
(e.g. [Cursor](https://docs.cursor.com/context/model-context-protocol))

## Features

- 🔧 ADB Command Execution (+ logcat)
- 📸 Device Screenshot Capture
- 🎯 UI Layout Analysis
- 📱 Device Package Management
- 🧩 JADX Static Analysis (APK → Java, code search)
- 🔎 androguard Static Analysis (manifest/permissions/exported components, signing, secret scan)
- 🧱 apktool (resource + smali decoding)
- 🧬 Frida Dynamic Instrumentation (attach/spawn, script injection, live messages)
- 🌐 mitmproxy Network Capture (device traffic proxy + flow listing)
- 📸 Baseline capture/diff (before/after device-state snapshot: dropped
  packages, C2 sockets, device-admin / accessibility / default-SMS changes)
- 🖥️ Live screen mirror (scrcpy) — watch the device screen in real time on the
  analyst PC while a sample runs, with optional session recording

56 tools total (full list: [docs/TOOLS.md](docs/TOOLS.md)). The static / JADX / apktool tools accept a `target` that is an
installed package name **or a path to a local .apk file** (so uploaded droppers
and downloaded payloads can be analyzed without a device). `apk_dropper_indicators`
assesses dropper behaviour and surfaces candidate payload-download URLs. Two
skills ship in `skills/`: **android-analysis** (tool usage) and
**malware-analysis** (dropper -> payload -> C2 methodology + KVault grounding +
report template). See [README_kr.md](README_kr.md) for the full tool tables.

> **Frida version note:** the host frida bindings and the device frida-server must
> match (at least on major version). One server process loads a single frida
> version, so devices needing different frida versions require separate MCP
> instances (own venv + port). Use `frida_check_compatibility` to detect mismatches.

## Prerequisites

- Python 3.11+
- ADB (Android Debug Bridge) installed and configured
- Android device or emulator
- (Optional) JADX + Java (JRE/JDK 11+) for the `jadx_*` tools
- (Optional) Frida host bindings + a matching device frida-server for the `frida_*` tools

### Quick start — one click (Windows)

`start.ps1` (or double-click `start.cmd`) runs the whole sequence — install
tools (if needed) → register the Claude Desktop connector → start the server:

```powershell
powershell -ExecutionPolicy Bypass -File start.ps1
# options: -Frida (push frida-server, needs root), -Port 8123, -NoServer, -SkipSetup
```

Re-running is safe (setup is skipped when already installed; the connector is
rewritten only when it changes). Or run the numbered `scripts\0..4` individually:

### One-step environment setup (Windows)

A PowerShell script checks for and installs everything the server can use —
ADB, Java, JADX, and Frida — without administrator rights:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\0-setup_environment.ps1

# also push a matching frida-server to a connected (rooted) device:
powershell -ExecutionPolicy Bypass -File scripts\0-setup_environment.ps1 -SetupFridaServer -StartFridaServer
```

It only installs what is missing and sets the `ADB_PATH` / `JAVA_HOME` /
`JADX_PATH` / `APKTOOL_PATH` user environment variables. `scripts\3-run_server.ps1`
loads these into its session automatically, so a fresh terminal is not required.

> For how this is deployed here, connecting Claude Desktop (incl. the Microsoft
> Store config-path gotcha), the web-connector limitation, and device
> prerequisites, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Installation

1. Clone the repository:

```bash
git clone https://github.com/minhalvp/android-mcp-server.git
cd android-mcp-server
```

2. Install dependencies:
This project uses [uv](https://github.com/astral-sh/uv) for project
management via various methods of
[installation](https://docs.astral.sh/uv/getting-started/installation/).

```bash
uv python install 3.11
uv sync
```

## Configuration

The server supports flexible device configuration with multiple usage scenarios.

### Device Selection Modes

**1. Automatic Selection (Recommended for single device)**

- No configuration file needed
- Automatically connects to the only connected device
- Perfect for development with a single test device

**2. Manual Device Selection**

- Use when you have multiple devices connected
- Specify exact device in configuration file

### Configuration File (Optional)

The configuration file (`config.yaml`) is **optional**. If not present, the server will automatically select the device if only one is connected.

#### For Automatic Selection

Simply ensure only one device is connected and run the server - no configuration needed!

#### For Manual Selection

1. Create a configuration file:

```bash
cp config.yaml.example config.yaml
```

2. Edit `config.yaml` and specify your device:

```yaml
device:
  name: "your-device-serial-here" # Device identifier from 'adb devices'
```

**For auto-selection**, you can use any of these methods:

```yaml
device:
  name: null              # Explicit null (recommended)
  # name: ""              # Empty string  
  # name:                 # Or leave empty/comment out
```

### Finding Your Device Serial

To find your device identifier, run:

```bash
adb devices
```

Example output:

```
List of devices attached
13b22d7f        device
emulator-5554   device
```

Use the first column value (e.g., `13b22d7f` or `emulator-5554`) as the device name.

### Usage Scenarios

| Scenario | Configuration Required | Behavior |
|----------|----------------------|----------|
| Single device connected | None | ✅ Auto-connects to the device |
| Multiple devices, want specific one | `config.yaml` with `device.name` | ✅ Connects to specified device |
| Multiple devices, no config | None | ✅ Auto-selects the first device (logs the choice) |
| No devices connected | N/A | ❌ Shows "no devices" error |

**Note**: If you have multiple devices connected and don't specify which one to use, the server auto-selects the first connected device and logs that choice (with the full device list). Set `device.name` in `config.yaml` to pick a specific device.

## Usage

An MCP client is needed to use this server. The Claude Desktop app is an example
of an MCP client. To use this server with Claude Desktop:

1. Locate your Claude Desktop configuration file:

   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

2. Add the Android MCP server configuration to the `mcpServers` section:

```json
{
  "mcpServers": {
    "android": {
      "command": "path/to/uv",
      "args": ["--directory", "path/to/android-mcp-server", "run", "server.py"]
    }
  }
}
```

Replace:

- `path/to/uv` with the actual path to your `uv` executable
- `path/to/android-mcp-server` with the absolute path to where you cloned this
repository

<https://github.com/user-attachments/assets/c45bbc17-f698-43e7-85b4-f1b39b8326a8>

### HTTP server mode (recommended)

The server runs over **Streamable HTTP** as a long-lived process. Because the
process stays up, the ADB connection is kept open across requests and
long-running sessions (e.g. `frida`) survive client reconnects — unlike stdio
mode, where the process is spawned and killed per client.

**Recommended deployment — per-analyst, local only.** Run the server on the same
PC the target device is attached to, bound to `127.0.0.1`, with Claude Desktop
on that same machine. This isolates each analyst's device and keeps the powerful
adb/jadx/frida surface off the network. This is the default.

Start the server:

```powershell
# convenience launcher (checks for a device, then runs server.py via uv):
powershell -ExecutionPolicy Bypass -File scripts\3-run_server.ps1

# or run directly:
uv run server.py                       # streamable-http on 127.0.0.1:8000
uv run server.py --host 127.0.0.1 --port 8000
```

Configure it via the `server` section of `config.yaml` (see
`config.yaml.example`):

```yaml
server:
  transport: "streamable-http"   # "stdio" or "sse" also supported
  host: "127.0.0.1"              # 0.0.0.0 only for trusted-network access
  port: 8000
  auth_token: ""                 # require "Authorization: Bearer <token>"
  # allowed_hosts:               # optional DNS-rebinding allow-list
  #   - "10.0.0.5:8000"
  # ssl_certfile: "C:/certs/android-mcp.crt"   # serve HTTPS (see below)
  # ssl_keyfile: "C:/certs/android-mcp.key"
```

Settings precedence is **CLI args > environment variables > config.yaml**.
Environment overrides: `MCP_TRANSPORT`, `MCP_HOST`, `MCP_PORT`, `MCP_AUTH_TOKEN`,
`MCP_SSL_CERTFILE`, `MCP_SSL_KEYFILE`, `MCP_SSL_KEYFILE_PASSWORD`.

Point an HTTP-capable MCP client at `http://<host>:<port>/mcp`. To keep the
original local stdio behaviour instead, run with `--transport stdio`.

#### HTTPS (required to register as a Claude org connector)

Registering the server as a Claude **organization connector** requires an
**HTTPS** URL. Provide a certificate and key and the server serves TLS directly:

```yaml
server:
  transport: "streamable-http"
  host: "0.0.0.0"                # reachable by clients on the internal network
  port: 8000
  auth_token: "a-strong-secret" # required once reachable beyond localhost
  ssl_certfile: "C:/certs/android-mcp.crt"   # PEM cert incl. intermediate chain
  ssl_keyfile: "C:/certs/android-mcp.key"    # PEM private key
  # ssl_keyfile_password: ""                  # only if the key is encrypted
```

- Use a certificate **trusted by the clients** (e.g. issued by your internal CA)
  whose SAN matches the hostname clients use (e.g. `android-mcp.corp.example`).
  A self-signed cert only works if the client trusts it; a connector reached by
  Anthropic's cloud requires a **publicly trusted** CA instead.
- The host must be reachable by whatever establishes the connector connection,
  and must have the target device attached (USB) or reachable via network ADB.
- The server now serves `https://<host>:<port>/mcp`.

> ⚠️ The server currently shares **one device across all clients**. A single
> org-wide endpoint means every user drives the same device — for multiple
> analysts/devices, run a per-device instance (separate port + `device.name`).

> ⚠️ **Security**: `execute_adb_shell_command` runs arbitrary shell commands on
> the device (and with frida, full runtime instrumentation). With the default
> `127.0.0.1` binding this surface is unreachable from the network. If you bind
> to `0.0.0.0` for a shared/in-house host, **always** set `auth_token` and
> restrict access to a trusted network. Note the server currently shares a
> single device across all clients, so a central multi-analyst host needs a
> per-device deployment.

### Available Tools

The server exposes the following tools:

```python
def get_packages() -> str:
    """
    Get all installed packages on the device.
    Returns:
        str: A list of all installed packages on the device as a string
    """
```

```python
def execute_adb_command(command: str) -> str:
    """
    Executes an ADB command and returns the output.
    Args:
        command (str): The ADB command to execute
    Returns:
        str: The output of the ADB command
    """
```

```python
def get_uilayout() -> str:
    """
    Retrieves information about clickable elements in the current UI.
    Returns a formatted string containing details about each clickable element,
    including their text, content description, bounds, and center coordinates.

    Returns:
        str: A formatted list of clickable elements with their properties
    """
```

```python
def get_screenshot() -> Image:
    """
    Takes a screenshot of the device and returns it.
    Returns:
        Image: the screenshot
    """
```

```python
def get_package_action_intents(package_name: str) -> list[str]:
    """
    Get all non-data actions from Activity Resolver Table for a package
    Args:
        package_name (str): The name of the package to get actions for
    Returns:
        list[str]: A list of all non-data actions from the Activity Resolver
        Table for the package
    """
```

### Static analysis with JADX

The server can decompile an installed app's APK to Java for static analysis,
using [JADX](https://github.com/skylot/jadx). These tools are optional — the
server runs fine without JADX installed; the `jadx_*` tools only require it when
called.

**Setup:**

1. Install a Java runtime (JRE/JDK 11+) and ensure `java` is on `PATH`.
2. Download a [JADX release](https://github.com/skylot/jadx/releases), unzip it,
   and set `JADX_PATH` (or `jadx.path` in `config.yaml`) to the `jadx`/`jadx.bat`
   executable. If `jadx` is already on `PATH`, no configuration is needed.

```yaml
jadx:
  path: "C:/jadx/bin/jadx.bat"   # or set the JADX_PATH env var
  output_dir: "workspace"         # pulled APKs + decompiled sources (git-ignored)
```

JADX tools:

```python
def jadx_decompile(package_name: str, include_splits: bool = False) -> str:
    """Pull a package's APK from the device and decompile it to Java."""

def jadx_list_decompiled() -> list[str]:
    """List packages already decompiled in the workspace."""

def jadx_search_code(package_name: str, pattern: str, max_results: int = 100) -> str:
    """Regex-search the decompiled Java sources of a package."""

def jadx_read_source(package_name: str, relative_path: str) -> str:
    """Read one decompiled Java source file."""
```

Typical flow: `jadx_decompile("com.example.app")` →
`jadx_search_code("com.example.app", "password")` →
`jadx_read_source("com.example.app", "com/example/app/LoginActivity.java")`.

### Dynamic instrumentation with Frida

The server can drive [Frida](https://frida.re/) against the device for runtime
hooking. Because the HTTP server is long-lived, **Frida sessions are kept alive
in the server and survive Claude Desktop reconnects** — this is the main reason
the server runs over HTTP rather than per-spawn stdio.

**Setup:** the host `frida` bindings are a project dependency (installed by
`uv sync` / `0-setup_environment.ps1`). The device needs a **matching-major
frida-server** running (rooted device). The dedicated
`scripts\1-setup_frida_server.ps1` checks the connected device's ABI/root, compares
its frida-server version with the host frida, and pushes the matching build
(add `-Start` to launch it on a rooted device); `0-setup_environment.ps1
-SetupFridaServer` delegates to it.

Frida tools:

```python
frida_check_compatibility()                # host frida vs device frida-server version
frida_list_devices()                       # devices visible to Frida
frida_list_processes()                      # running processes
frida_list_applications()                   # installed apps
frida_attach(target)                        # attach by name/PID -> session_id
frida_spawn(package_name)                   # spawn suspended      -> session_id
frida_run_script(session_id, script_source) # inject JS; resumes spawned procs
frida_read_messages(session_id)             # drain script send()/error output
frida_resume(session_id)                    # resume a spawned process
frida_list_sessions()                       # active sessions
frida_detach(session_id)                    # detach + drop session
```

Typical flow:

```
1. frida_spawn("com.example.app")                       -> session_id
2. frida_run_script(session_id, "<JS that calls send()>")  (injects + resumes)
3. frida_read_messages(session_id)                       (repeat to poll output)
4. frida_detach(session_id)
```

> ⚠️ **Version match**: the host frida and device frida-server **major versions
> must match**, or sessions fail to start.

## Contributing

Contributions are welcome!

## Acknowledgments

- Built with
[Model Context Protocol (MCP)](https://modelcontextprotocol.io/introduction)
