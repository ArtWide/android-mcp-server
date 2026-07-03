import argparse
import os
import sys

import yaml
from mcp.server.fastmcp import FastMCP, Image
from mcp.server.transport_security import TransportSecuritySettings

from adbdevicemanager import AdbDeviceManager
from apktoolmanager import ApktoolManager
from fridamanager import FridaManager
from imagerender import CodeImageRenderer
from jadxmanager import JadxManager
from networkmanager import NetworkCaptureManager
from staticmanager import StaticAnalysisManager

CONFIG_FILE = "config.yaml"
CONFIG_FILE_EXAMPLE = "config.yaml.example"

# Defaults for the HTTP server. These can be overridden by config.yaml,
# environment variables, or command line arguments (in increasing priority).
DEFAULT_TRANSPORT = "streamable-http"
# Bind to loopback by default: the recommended deployment is per-analyst on a
# personal PC, where the target device and Claude Desktop are on the same
# machine. This keeps the powerful adb/jadx/frida surface off the network.
# Override with host: "0.0.0.0" (+ auth_token) only for trusted-network setups.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000


def _load_config() -> dict:
    """Load config.yaml if present. The file is optional."""
    if not os.path.exists(CONFIG_FILE):
        print(
            f"Config file {CONFIG_FILE} not found, using defaults "
            "(auto-select device, streamable-http transport)")
        return {}

    try:
        with open(CONFIG_FILE) as f:
            return yaml.safe_load(f.read()) or {}
    except Exception as e:
        print(f"Error loading config file {CONFIG_FILE}: {e}", file=sys.stderr)
        print(
            f"Please check the format of your config file or recreate it from "
            f"{CONFIG_FILE_EXAMPLE}", file=sys.stderr)
        sys.exit(1)


def _resolve_device_name(config: dict) -> str | None:
    """Resolve the configured device name, or None for auto-selection."""
    device_config = config.get("device") or {}
    configured = device_config.get("name")
    if configured and str(configured).strip():
        name = str(configured).strip()
        print(f"Configured device: {name}")
        return name
    print("No device specified, will auto-select if only one device connected")
    return None


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Android MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http", "sse"],
        default=None,
        help="MCP transport to use (default: from config or streamable-http)")
    parser.add_argument("--host", default=None,
                        help="Host/IP to bind for HTTP transports")
    parser.add_argument("--port", type=int, default=None,
                        help="Port to bind for HTTP transports")
    # Ignore unknown args so the module stays importable under test runners.
    args, _ = parser.parse_known_args()
    return args


def _server_settings(config: dict, args: argparse.Namespace) -> dict:
    """Merge server settings from config, env vars, and CLI args.

    Priority (low to high): config.yaml < environment < CLI arguments.
    """
    server_config = config.get("server") or {}

    transport = (
        args.transport
        or os.environ.get("MCP_TRANSPORT")
        or server_config.get("transport")
        or DEFAULT_TRANSPORT)

    host = (
        args.host
        or os.environ.get("MCP_HOST")
        or server_config.get("host")
        or DEFAULT_HOST)

    port = (
        args.port
        or os.environ.get("MCP_PORT")
        or server_config.get("port")
        or DEFAULT_PORT)
    port = int(port)

    # Shared-secret bearer token. If empty/None, auth is disabled.
    auth_token = (
        os.environ.get("MCP_AUTH_TOKEN")
        or server_config.get("auth_token")
        or "")
    auth_token = str(auth_token).strip()

    # Hosts allowed in the Host header (DNS-rebinding protection). When empty
    # and we bind to a non-loopback address, we can't enumerate every valid
    # Host header, so protection is disabled and we rely on the bearer token
    # plus network-level binding instead.
    allowed_hosts = server_config.get("allowed_hosts") or []

    # TLS: serve HTTPS directly when both a certificate and key are provided.
    # Use a cert trusted by the clients (e.g. your internal CA).
    ssl_certfile = (
        os.environ.get("MCP_SSL_CERTFILE")
        or server_config.get("ssl_certfile")
        or "")
    ssl_keyfile = (
        os.environ.get("MCP_SSL_KEYFILE")
        or server_config.get("ssl_keyfile")
        or "")
    ssl_keyfile_password = (
        os.environ.get("MCP_SSL_KEYFILE_PASSWORD")
        or server_config.get("ssl_keyfile_password")
        or "")

    return {
        "transport": transport,
        "host": host,
        "port": port,
        "auth_token": auth_token,
        "allowed_hosts": list(allowed_hosts),
        "ssl_certfile": str(ssl_certfile).strip(),
        "ssl_keyfile": str(ssl_keyfile).strip(),
        "ssl_keyfile_password": str(ssl_keyfile_password),
    }


class TokenAuthMiddleware:
    """Pure-ASGI middleware enforcing a shared bearer token on HTTP requests.

    Implemented as raw ASGI (not BaseHTTPMiddleware) so it does not buffer the
    streaming responses used by the streamable-http / SSE transports. Non-HTTP
    scopes (lifespan, websocket) are passed straight through.
    """

    def __init__(self, app, token: str) -> None:
        self.app = app
        self.expected = f"Bearer {token}"

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        authorization = headers.get(b"authorization", b"").decode("latin-1")
        if authorization != self.expected:
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", b"Bearer"),
                ],
            })
            await send({
                "type": "http.response.body",
                "body": b'{"error":"unauthorized"}',
            })
            return

        await self.app(scope, receive, send)


# Load configuration and resolve runtime settings.
_config = _load_config()
_args = _parse_args()
_settings = _server_settings(_config, _args)
device_name = _resolve_device_name(_config)

# Configure DNS-rebinding protection for the HTTP transports.
if _settings["allowed_hosts"]:
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=_settings["allowed_hosts"],
        allowed_origins=_settings["allowed_hosts"],
    )
else:
    # No explicit allow-list: disable Host-header protection and rely on the
    # bearer token + network binding. (Loopback-only setups are still safe.)
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False)

# Initialize MCP and device manager.
# AdbDeviceManager auto-selects the device when device_name is None. The
# manager is created once and reused for the lifetime of the process, so the
# ADB connection stays alive across requests (unlike per-spawn stdio usage).
mcp = FastMCP(
    "android",
    host=_settings["host"],
    port=_settings["port"],
    transport_security=transport_security,
)
deviceManager = AdbDeviceManager(device_name)

# JADX static-analysis manager. Constructed lazily-tolerant: it does not require
# jadx/Java at startup, only when a jadx_* tool is actually called.
_jadx_config = _config.get("jadx") or {}
jadxManager = JadxManager(
    deviceManager,
    jadx_path=os.environ.get("JADX_PATH") or _jadx_config.get("path") or None,
    output_dir=_jadx_config.get("output_dir") or None,
)

# Frida dynamic-instrumentation manager. Keeps sessions alive in-process across
# requests; tolerant of frida being absent until a frida_* tool is called.
fridaManager = FridaManager(deviceManager)

# Static analysis (androguard), apktool, and network capture (mitmproxy). All
# share the JADX workspace dir and tolerate their external tools being absent.
_workspace = _jadx_config.get("output_dir") or None
staticManager = StaticAnalysisManager(deviceManager, output_dir=_workspace)
_apktool_config = _config.get("apktool") or {}
apktoolManager = ApktoolManager(
    deviceManager,
    apktool_path=os.environ.get("APKTOOL_PATH") or _apktool_config.get("path") or None,
    output_dir=_workspace,
)
networkManager = NetworkCaptureManager(deviceManager, output_dir=_workspace)
codeRenderer = CodeImageRenderer(output_dir=_workspace)


@mcp.tool()
def list_devices() -> str:
    """List connected devices (serial + model), marking the active one.

    When several devices are connected, show these to the analyst and let them
    choose, then call select_device — instead of silently using the first.
    Returns:
        str: One line per device as 'serial\\tmodel' ('<- active' marks the current one)
    """
    return deviceManager.list_devices()


@mcp.tool()
def select_device(serial: str) -> str:
    """Switch the active device that all subsequent tools operate on.
    Args:
        serial (str): The device serial from list_devices
    Returns:
        str: Confirmation of the new active device
    """
    return deviceManager.select_device(serial)


@mcp.tool()
def get_current_device() -> str:
    """Report the currently active device (serial + model).
    Returns:
        str: The active device
    """
    return deviceManager.get_current_device()


@mcp.tool()
def get_packages() -> str:
    """
    Get all installed packages on the device
    Returns:
        str: A list of all installed packages on the device as a string
    """
    result = deviceManager.get_packages()
    return result


@mcp.tool()
def execute_adb_shell_command(command: str) -> str:
    """Executes an ADB command and returns the output or an error.
    Args:
        command (str): The ADB shell command to execute
    Returns:
        str: The output of the ADB command
    """
    result = deviceManager.execute_adb_shell_command(command)
    return result


@mcp.tool()
def get_uilayout() -> str:
    """
    Retrieves information about clickable elements in the current UI.
    Returns a formatted string containing details about each clickable element,
    including its text, content description, bounds, and center coordinates.

    Returns:
        str: A formatted list of clickable elements with their properties
    """
    result = deviceManager.get_uilayout()
    return result


@mcp.tool()
def get_screenshot() -> Image:
    """Takes a screenshot of the device and returns it.
    Returns:
        Image: the screenshot
    """
    try:
        path = deviceManager.take_screenshot()
        return Image(path=path)
    except Exception as e:
        raise RuntimeError(f"Failed to capture screenshot: {e}") from e


@mcp.tool()
def get_package_action_intents(package_name: str) -> list[str]:
    """
    Get all non-data actions from Activity Resolver Table for a package
    Args:
        package_name (str): The name of the package to get actions for
    Returns:
        list[str]: A list of all non-data actions from the Activity Resolver Table for the package
    """
    result = deviceManager.get_package_action_intents(package_name)
    return result


@mcp.tool()
def jadx_decompile(target: str, include_splits: bool = False) -> str:
    """Decompile an APK to Java with JADX.

    Run this once per target before using jadx_search_code / jadx_read_source;
    those take the 'key' reported here (it equals the package name for installed
    apps, or the file stem for an .apk file).
    Args:
        target (str): An installed package name OR a path to a local .apk file
        include_splits (bool): Also include split APKs (default: base.apk only)
    Returns:
        str: A summary including the workspace key and decompiled file count
    """
    return jadxManager.decompile(target, include_splits=include_splits)


@mcp.tool()
def jadx_list_decompiled() -> list[str]:
    """List packages already decompiled in the workspace.
    Returns:
        list[str]: Package names that have decompiled sources available
    """
    return jadxManager.list_decompiled()


@mcp.tool()
def jadx_search_code(package_name: str, pattern: str, max_results: int = 100) -> str:
    """Regex-search the decompiled Java sources of a previously decompiled package.
    Args:
        package_name (str): The decompiled package to search
        pattern (str): A Python regular expression
        max_results (int): Maximum number of matching lines to return
    Returns:
        str: Matches formatted as 'relative/path.java:line: snippet'
    """
    return jadxManager.search_code(pattern, package_name, max_results=max_results)


@mcp.tool()
def jadx_read_source(package_name: str, relative_path: str) -> str:
    """Read one decompiled Java source file from a decompiled package.
    Args:
        package_name (str): The decompiled package
        relative_path (str): Path to the .java file relative to the sources root
                             (as shown by jadx_search_code)
    Returns:
        str: The full contents of the source file
    """
    return jadxManager.read_source(package_name, relative_path)


@mcp.tool()
def frida_list_devices() -> str:
    """List devices visible to Frida (usb/remote/local).
    Returns:
        str: One line per device as 'id\\ttype\\tname'
    """
    return fridaManager.list_devices()


@mcp.tool()
def frida_check_compatibility(server_path: str = "/data/local/tmp/frida-server") -> str:
    """Check that the host frida version matches the device's frida-server.

    Reports the host frida version, whether frida-server is running, the device
    frida-server version, and whether they are compatible. Use this first when
    Frida attach/spawn fails.
    Args:
        server_path (str): Path to frida-server on the device
    Returns:
        str: A version/compatibility report
    """
    return fridaManager.check_compatibility(server_path)


@mcp.tool()
def frida_list_processes() -> str:
    """List running processes on the device via Frida.
    Returns:
        str: One line per process as 'pid\\tname'
    """
    return fridaManager.list_processes()


@mcp.tool()
def frida_list_applications() -> str:
    """List installed applications on the device via Frida.
    Returns:
        str: One line per app as 'pid\\tidentifier\\tname' (pid '-' if not running)
    """
    return fridaManager.list_applications()


@mcp.tool()
def frida_attach(target: str) -> str:
    """Attach Frida to a running process by name or PID.

    The session is kept alive in the server. Inject code with frida_run_script.
    Args:
        target (str): Process name (e.g. 'com.example.app') or PID
    Returns:
        str: Confirmation including the session_id to use in later calls
    """
    return fridaManager.attach(target)


@mcp.tool()
def frida_spawn(package_name: str) -> str:
    """Spawn an app suspended and attach Frida to it.

    Use this to hook early startup. The process stays suspended until
    frida_run_script (which resumes after loading) or frida_resume.
    Args:
        package_name (str): The app package to spawn (e.g. 'com.example.app')
    Returns:
        str: Confirmation including the session_id and pid
    """
    return fridaManager.spawn(package_name)


@mcp.tool()
def frida_run_script(session_id: str, script_source: str) -> str:
    """Inject and load a Frida JavaScript instrumentation script into a session.

    Emit data from the script with send(...); read it back with
    frida_read_messages. If the session was spawned, the process is resumed
    after the script loads.
    Args:
        session_id (str): A session_id from frida_attach or frida_spawn
        script_source (str): Frida JavaScript source to load
    Returns:
        str: Load status
    """
    return fridaManager.run_script(session_id, script_source)


@mcp.tool()
def frida_read_messages(session_id: str) -> str:
    """Drain buffered messages emitted by a session's script (send()/errors).
    Args:
        session_id (str): A session_id with a loaded script
    Returns:
        str: The buffered messages, or a notice if there are none
    """
    return fridaManager.read_messages(session_id)


@mcp.tool()
def frida_resume(session_id: str) -> str:
    """Resume a spawned, still-suspended process without injecting a script.
    Args:
        session_id (str): A session_id from frida_spawn
    Returns:
        str: Resume status
    """
    return fridaManager.resume(session_id)


@mcp.tool()
def frida_list_sessions() -> str:
    """List active Frida sessions held by the server.
    Returns:
        str: One line per session as 'session_id\\tpid\\ttarget\\tscript-state'
    """
    return fridaManager.list_sessions()


@mcp.tool()
def frida_detach(session_id: str) -> str:
    """Detach a Frida session and remove it from the server registry.
    Args:
        session_id (str): The session to detach
    Returns:
        str: Detach status
    """
    return fridaManager.detach(session_id)


@mcp.tool()
def get_logcat(lines: int = 200, filter_spec: str = "", priority: str = "") -> str:
    """Dump recent logcat output from the device.
    Args:
        lines (int): Number of most-recent lines to return
        filter_spec (str): Optional tag filter, e.g. 'ActivityManager:I *:S'
        priority (str): Optional minimum priority for all tags (V/D/I/W/E/F)
    Returns:
        str: The logcat output
    """
    return deviceManager.get_logcat(lines=lines, filter_spec=filter_spec, priority=priority)


@mcp.tool()
def push_file(local_path: str, device_path: str) -> str:
    """Push a file from the host to the device (e.g. a sample APK, tool, or payload).
    Args:
        local_path (str): Path to the file on the host
        device_path (str): Destination path on the device (e.g. /data/local/tmp/x.apk)
    Returns:
        str: Confirmation with the byte count
    """
    return deviceManager.push_file(local_path, device_path)


@mcp.tool()
def pull_file(device_path: str, local_path: str = "") -> str:
    """Pull a file from the device to the host (e.g. a dropped payload to analyze).
    Args:
        device_path (str): Path to the file on the device
        local_path (str): Host destination; defaults to workspace/pulled/<name>
    Returns:
        str: Confirmation with the local path and byte count
    """
    return deviceManager.pull_file(device_path, local_path)


@mcp.tool()
def install_apk(apk_path: str, reinstall: bool = False,
                grant_permissions: bool = False, downgrade: bool = False) -> str:
    """Install a host APK onto the device (adb install).
    Args:
        apk_path (str): Path to the .apk file on the host
        reinstall (bool): Keep data and reinstall (-r)
        grant_permissions (bool): Grant all runtime permissions (-g)
        downgrade (bool): Allow version downgrade (-d)
    Returns:
        str: Install result
    """
    return deviceManager.install_apk(
        apk_path, reinstall=reinstall,
        grant_permissions=grant_permissions, downgrade=downgrade)


@mcp.tool()
def analyze_manifest(target: str) -> str:
    """Static analysis of an APK's manifest: permissions, exported components,
    debuggable/allowBackup/cleartext flags, and SDK levels (via androguard).
    Args:
        target (str): An installed package name OR a path to a local .apk file
    Returns:
        str: A formatted manifest/permission/attack-surface summary
    """
    return staticManager.analyze_manifest(target)


@mcp.tool()
def apk_info(target: str) -> str:
    """APK signing and metadata: signing certificates, SHA-256, version, sign state.
    Args:
        target (str): An installed package name OR a path to a local .apk file
    Returns:
        str: Signing certificate details and APK hashes
    """
    return staticManager.apk_info(target)


@mcp.tool()
def scan_secrets(target: str) -> str:
    """Scan an APK's dex strings for hardcoded secrets and endpoints
    (API keys, tokens, private keys, URLs, IPs).
    Args:
        target (str): An installed package name OR a path to a local .apk file
    Returns:
        str: Categorized matches found in the app's code strings
    """
    return staticManager.scan_secrets(target)


@mcp.tool()
def apk_dropper_indicators(target: str) -> str:
    """Assess whether an APK is a dropper and surface payload-download URLs.

    Flags dynamic code loading, reflection, package-install, crypto and
    anti-analysis indicators, risky permissions, and URLs that look like
    second-stage payloads — the starting point for dropper -> payload -> C2
    analysis.
    Args:
        target (str): An installed package name OR a path to a local .apk file
    Returns:
        str: Dropper likelihood, indicators, risky permissions, candidate URLs
    """
    return staticManager.dropper_indicators(target)


@mcp.tool()
def apktool_decode(target: str) -> str:
    """Decode an APK with apktool (resources + decoded manifest + smali).
    Run once per target before apktool_list_files / apktool_read_file (which take
    the 'key' reported here).
    Args:
        target (str): An installed package name OR a path to a local .apk file
    Returns:
        str: A summary including the workspace key and output directory
    """
    return apktoolManager.decode(target)


@mcp.tool()
def apktool_list_files(package_name: str, subdir: str = "") -> str:
    """List files in a package's apktool-decoded output.
    Args:
        package_name (str): A previously decoded package
        subdir (str): Optional subdirectory (e.g. 'res/values', 'smali')
    Returns:
        str: Directory listing relative to the decoded root
    """
    return apktoolManager.list_files(package_name, subdir=subdir)


@mcp.tool()
def apktool_read_file(package_name: str, relative_path: str) -> str:
    """Read one file from a package's apktool-decoded output (manifest, xml, smali).
    Args:
        package_name (str): A previously decoded package
        relative_path (str): Path relative to the decoded root
                             (e.g. 'AndroidManifest.xml')
    Returns:
        str: The file contents
    """
    return apktoolManager.read_file(package_name, relative_path)


@mcp.tool()
def render_code_image(
    code: str,
    language: str = "java",
    highlight_lines: list[int] | None = None,
    annotations: list[dict] | None = None,
    title: str = "",
    start_line: int = 1,
) -> Image:
    """Render a code snippet to an annotated PNG for the analysis report.

    Produces a syntax-highlighted, line-numbered image with red boxes around the
    problematic lines and green Korean inline comments explaining *why* the code
    is malicious. You decide what to box and what the Korean explanation says;
    this tool only draws them in the house style.

    Args:
        code (str): The source snippet (e.g. from jadx_read_source). Keep it
            focused — a class/method, not a whole file.
        language (str): pygments lexer name (java, xml, kotlin, text, ...).
        highlight_lines (list[int]): 1-based line numbers (relative to the
            snippet) to box in red; consecutive numbers merge into one box.
        annotations (list[dict]): [{"line": int, "text": "<한국어 설명>"}] drawn
            as green `// ...` comments at the end of that line.
        title (str): Optional caption drawn above the code (e.g. class path).
        start_line (int): Number shown for the first line (when the snippet
            starts partway through a file).
    Returns:
        Image: the rendered PNG
    """
    path = codeRenderer.render_code_image(
        code, language=language, highlight_lines=highlight_lines,
        annotations=annotations, title=title, start_line=start_line)
    return Image(path=path)


@mcp.tool()
def network_start_capture(port: int = 8080) -> str:
    """Start capturing the device's network traffic via mitmproxy.

    Routes the device's HTTP(S) traffic through mitmdump using adb reverse and a
    device proxy setting. HTTPS requires the mitmproxy CA trusted on the device.
    Args:
        port (int): Proxy port (default 8080)
    Returns:
        str: Capture status and next-step guidance
    """
    return networkManager.start_capture(port=port)


@mcp.tool()
def network_list_flows(limit: int = 50) -> str:
    """List recently captured network flows (method, status, URL, sizes).
    Args:
        limit (int): Maximum number of most-recent flows to return
    Returns:
        str: One line per captured request/response
    """
    return networkManager.list_flows(limit=limit)


@mcp.tool()
def network_get_flow(index: int) -> str:
    """Get one captured flow's full detail: request/response headers and body.

    Use the 1-based index shown in network_list_flows ([n] markers). Bodies are
    decoded (charset-aware) and size-capped; binary bodies are returned base64.
    Args:
        index (int): 1-based flow index from network_list_flows
    Returns:
        str: Request line, headers, and decoded body for the request and response
    """
    return networkManager.get_flow(index)


@mcp.tool()
def network_stop_capture() -> str:
    """Stop the network capture and clear the device proxy / adb reverse.
    Returns:
        str: Stop status
    """
    return networkManager.stop_capture()


@mcp.tool()
def network_status() -> str:
    """Report whether a network capture is currently running.
    Returns:
        str: Capture status
    """
    return networkManager.status()


def _run_http(transport: str) -> None:
    """Run an HTTP transport, optionally wrapped with token auth."""
    import uvicorn

    if transport == "sse":
        app = mcp.sse_app()
        path = _settings.get("sse_path", "/sse")
    else:
        app = mcp.streamable_http_app()
        path = "/mcp"

    token = _settings["auth_token"]
    if token:
        app = TokenAuthMiddleware(app, token)
        print("Bearer token authentication: ENABLED")
    else:
        print("Bearer token authentication: DISABLED (no auth_token configured)")

    # TLS: enable HTTPS when both a certificate and key are configured.
    uvicorn_kwargs: dict = {}
    certfile = _settings.get("ssl_certfile")
    keyfile = _settings.get("ssl_keyfile")
    if certfile and keyfile:
        for label, p in (("ssl_certfile", certfile), ("ssl_keyfile", keyfile)):
            if not os.path.isfile(p):
                print(f"TLS {label} not found: {p}", file=sys.stderr)
                sys.exit(1)
        uvicorn_kwargs["ssl_certfile"] = certfile
        uvicorn_kwargs["ssl_keyfile"] = keyfile
        if _settings.get("ssl_keyfile_password"):
            uvicorn_kwargs["ssl_keyfile_password"] = _settings["ssl_keyfile_password"]
        scheme = "https"
    elif certfile or keyfile:
        print("TLS requires BOTH ssl_certfile and ssl_keyfile; ignoring partial "
              "TLS config and serving plain HTTP.", file=sys.stderr)
        scheme = "http"
    else:
        scheme = "http"

    host, port = _settings["host"], _settings["port"]
    print(f"Starting Android MCP Server ({transport}) on {scheme}://{host}:{port}{path}")
    uvicorn.run(app, host=host, port=port, log_level="info", **uvicorn_kwargs)


if __name__ == "__main__":
    transport = _settings["transport"]
    if transport == "stdio":
        print("Starting Android MCP Server (stdio)")
        mcp.run(transport="stdio")
    else:
        _run_http(transport)
