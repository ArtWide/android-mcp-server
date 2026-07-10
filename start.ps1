<#
.SYNOPSIS
    One-click setup + run for the Android MCP Server.

.DESCRIPTION
    Runs the numbered scripts in scripts\ in order:
      0  install tools (skipped if already installed)        0-setup_environment.ps1
      1  (optional) push frida-server to the device          1-setup_frida_server.ps1
      2  register the Claude Desktop connector (idempotent)   2-register_claude_desktop.ps1
      3  start the MCP server (runs in the foreground)        3-run_server.ps1

    Re-running is safe: setup is skipped when tools are already present and the
    connector is only rewritten when it changes. The server step blocks until
    you press Ctrl+C.

.PARAMETER Frida
    Also run frida-server setup (step 1). Needs a rooted device.

.PARAMETER ForceSetup
    Run tool installation (step 0) even if it looks already done.

.PARAMETER SkipSetup
    Skip tool installation (step 0).

.PARAMETER SkipRegister
    Skip Claude Desktop registration (step 2).

.PARAMETER NoServer
    Do setup/register only; do not start the server (step 3).

.PARAMETER Port
    Server port (passed to registration and the server). Default 8000.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File start.ps1

.EXAMPLE
    # first run on a rooted device, custom port:
    powershell -ExecutionPolicy Bypass -File start.ps1 -Frida -Port 8123
#>

[CmdletBinding()]
param(
    [switch]$Frida,
    [switch]$ForceSetup,
    [switch]$SkipSetup,
    [switch]$SkipRegister,
    [switch]$NoServer,
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"
$RepoDir = $PSScriptRoot
$Scripts = Join-Path $RepoDir "scripts"

function Banner($n, $t) {
    Write-Host ""
    Write-Host ("===== [{0}] {1} " -f $n, $t).PadRight(64, "=") -ForegroundColor Magenta
}
function Invoke-Step([string]$file, [string[]]$stepArgs) {
    $path = Join-Path $Scripts $file
    if (-not (Test-Path $path)) { throw "Missing script: $path" }
    & powershell -NoProfile -ExecutionPolicy Bypass -File $path @stepArgs
    if ($LASTEXITCODE -ne 0) { throw "$file failed (exit code $LASTEXITCODE)" }
}
function Test-SetupDone {
    $jadx = [Environment]::GetEnvironmentVariable("JADX_PATH", "User")
    $java = [Environment]::GetEnvironmentVariable("JAVA_HOME", "User")
    $hasAdb = [bool](Get-Command adb -ErrorAction SilentlyContinue) -or
              [bool][Environment]::GetEnvironmentVariable("ADB_PATH", "User")
    return ($jadx -and (Test-Path $jadx) -and $java -and (Test-Path $java) -and $hasAdb)
}

Write-Host "Android MCP Server - one-click setup & run" -ForegroundColor Cyan
Write-Host "Repo: $RepoDir"

# Pre-step: ensure the project venv exists.
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "uv not found on PATH. Install uv first: https://docs.astral.sh/uv/" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path (Join-Path $RepoDir ".venv"))) {
    Banner "sync" "Creating project environment (uv sync)"
    Push-Location $RepoDir
    try { & uv sync } finally { Pop-Location }
}

# Step 0: install tools.
if ($SkipSetup) {
    Banner 0 "Skipping tool installation (-SkipSetup)"
} elseif (-not $ForceSetup -and (Test-SetupDone)) {
    Banner 0 "Tools already installed - skipping (use -ForceSetup to redo)"
} else {
    Banner 0 "Installing tools (ADB / Java / JADX / apktool / Frida)"
    $a = @()
    if ($Frida) { $a = @("-SetupFridaServer") }
    Invoke-Step "0-setup_environment.ps1" $a
}

# Step 1: frida-server (optional).
if ($Frida) {
    Banner 1 "Setting up frida-server on the device"
    Invoke-Step "1-setup_frida_server.ps1" @("-Start")
} else {
    Banner 1 "Skipping frida-server (pass -Frida to enable; needs root)"
}

# Step 2: register Claude Desktop connector.
if ($SkipRegister) {
    Banner 2 "Skipping Claude Desktop registration (-SkipRegister)"
} else {
    Banner 2 "Registering Claude Desktop connector"
    Invoke-Step "2-register_claude_desktop.ps1" @("-Port", "$Port")
}

# Install every skill the repo ships (skills/<name>/SKILL.md) into the global
# Claude Code skills folder (~/.claude/skills/<name>). Always overwrites from the
# repo source, so re-running the installer after a repo update refreshes the
# standard skills regardless of which file changed. The destination is recreated
# each time so files removed from a skill don't linger.
Banner "skill" "Installing Claude Code skills (overwrite from repo)"
$skillsRoot = Join-Path $RepoDir "skills"
if (Test-Path $skillsRoot) {
    Get-ChildItem $skillsRoot -Directory | ForEach-Object {
        if (-not (Test-Path (Join-Path $_.FullName "SKILL.md"))) { return }
        $dest = Join-Path $env:USERPROFILE ".claude\skills\$($_.Name)"
        if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        Copy-Item -Path (Join-Path $_.FullName "*") -Destination $dest -Recurse -Force
        Write-Host "    [OK] $($_.Name): installed/updated" -ForegroundColor Green
    }
} else {
    Write-Host "    [!] No skills/ directory found at $skillsRoot" -ForegroundColor Yellow
}

# Step 3: run the server (foreground).
if ($NoServer) {
    Banner 3 "Setup complete (-NoServer). Start later with scripts\3-run_server.ps1"
    Write-Host "`nDone." -ForegroundColor Green
} else {
    Banner 3 "Starting the MCP server (Ctrl+C to stop)"
    Invoke-Step "3-run_server.ps1" @("-Port", "$Port")
}
