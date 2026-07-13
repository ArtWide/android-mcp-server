<#
.SYNOPSIS
    Run the Android MCP Server. Use after scripts\0-setup_environment.ps1.

.DESCRIPTION
    Verifies a device is connected, then launches server.py via uv. By default
    the server listens on 127.0.0.1:8000 (streamable-http). Any extra arguments
    are passed straight through to server.py.

.PARAMETER BindHost
    Bind address override (passes --host to server.py). Named BindHost because
    $Host is a reserved PowerShell variable.

.PARAMETER Port
    Port override (passes --port to server.py).

.PARAMETER Transport
    Transport override: streamable-http (default), stdio, or sse.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\3-run_server.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\3-run_server.ps1 -Port 8123

.EXAMPLE
    # expose on the internal network (set auth_token in config.yaml first):
    powershell -ExecutionPolicy Bypass -File scripts\3-run_server.ps1 -BindHost 0.0.0.0
#>

[CmdletBinding()]
param(
    [string]$BindHost,
    [int]$Port,
    [ValidateSet("streamable-http", "stdio", "sse")]
    [string]$Transport,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Passthrough
)

$ErrorActionPreference = "Stop"
$RepoDir = Split-Path $PSScriptRoot -Parent

# Load tool env vars from user scope into this session so the server discovers
# jadx/apktool/java/adb even when launched from a terminal opened before
# 0-setup_environment.ps1 ran (avoids the "restart in a new terminal" gotcha).
foreach ($name in @("JAVA_HOME", "JADX_PATH", "APKTOOL_PATH", "ADB_PATH", "SCRCPY_PATH")) {
    $val = [Environment]::GetEnvironmentVariable($name, "User")
    if ($val) { Set-Item -Path "Env:$name" -Value $val }
}
# Ensure java + adb (+ scrcpy's dir) are on PATH for this session.
$pathAdds = @()
if ($env:JAVA_HOME)   { $pathAdds += (Join-Path $env:JAVA_HOME "bin") }
if ($env:ADB_PATH)    { $pathAdds += $env:ADB_PATH }
if ($env:SCRCPY_PATH) { $pathAdds += (Split-Path $env:SCRCPY_PATH -Parent) }
if ($pathAdds.Count -gt 0) { $env:PATH = ($pathAdds -join ";") + ";" + $env:PATH }

$venvPy = Join-Path $RepoDir ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy) -and -not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "No .venv and uv not found. Install uv and run 'uv sync': https://docs.astral.sh/uv/" -ForegroundColor Red
    exit 1
}

# Best-effort device check (non-fatal; server.py reports clearly too).
if (Get-Command adb -ErrorAction SilentlyContinue) {
    $devices = @((& adb devices) -split "`n" | Where-Object { $_ -match "\tdevice$" })
    if (-not $devices) {
        Write-Host "[!] No authorized device detected (adb devices)." -ForegroundColor Yellow
        Write-Host "    Connect a device and accept the USB debugging prompt." -ForegroundColor Yellow
    } else {
        $serial = ($devices[0] -split "\t")[0]
        Write-Host "[OK] Device connected: $serial" -ForegroundColor Green
    }
} else {
    Write-Host "[!] adb not found. Run scripts\0-setup_environment.ps1 first." -ForegroundColor Yellow
}

$serverArgs = @()
if ($Transport) { $serverArgs += @("--transport", $Transport) }
if ($BindHost)  { $serverArgs += @("--host", $BindHost) }
if ($Port)      { $serverArgs += @("--port", $Port) }
if ($Passthrough) { $serverArgs += $Passthrough }

Push-Location $RepoDir
try {
    if (Test-Path $venvPy) {
        # Run the project venv Python directly. `uv run` spawns uv's *managed*
        # Python (under %APPDATA%\uv\python), which Windows Smart App Control
        # blocks on some machines ("Failed to spawn: python", os error 4551);
        # the venv interpreter is unaffected.
        Write-Host "`nStarting: .venv\Scripts\python.exe server.py $($serverArgs -join ' ')" -ForegroundColor Cyan
        & $venvPy server.py @serverArgs
    } else {
        Write-Host "`n.venv not found - falling back to 'uv run' (run 'uv sync' first if this is blocked)." -ForegroundColor Yellow
        & uv run server.py @serverArgs
    }
} finally {
    Pop-Location
}
