<#
.SYNOPSIS
    Check the connected device and install a matching frida-server.

.DESCRIPTION
    Reads the host frida version from the project venv, detects the device ABI
    and root state, compares with any frida-server already on the device, and
    pushes the matching frida-server build when it is missing or the version
    differs. Optionally starts it (needs root).

    The host frida and device frida-server versions must match, so this always
    targets the host's frida version. Run it once per device (or after changing
    the host frida version).

.PARAMETER Start
    After pushing, start frida-server on the device (requires root / su).

.PARAMETER ServerPath
    Device path for the frida-server binary (default /data/local/tmp/frida-server).

.PARAMETER Force
    Re-download and push even if the device already has the matching version.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\1-setup_frida_server.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\1-setup_frida_server.ps1 -Start
#>

[CmdletBinding()]
param(
    [switch]$Start,
    [string]$ServerPath = "/data/local/tmp/frida-server",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    [OK] $m" -ForegroundColor Green }
function Write-Warn($m) { Write-Host "    [!] $m" -ForegroundColor Yellow }

$RepoDir = Split-Path $PSScriptRoot -Parent
$VenvPython = Join-Path $RepoDir ".venv\Scripts\python.exe"
$dlDir = Join-Path $RepoDir "workspace\frida-server"
New-Item -ItemType Directory -Force -Path $dlDir | Out-Null

# Ensure adb is reachable (load ADB_PATH from user scope if needed).
if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    $adbPath = [Environment]::GetEnvironmentVariable("ADB_PATH", "User")
    if ($adbPath) { $env:PATH = "$adbPath;$env:PATH" }
}
if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    Write-Host "adb not found. Run scripts\0-setup_environment.ps1 first." -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $VenvPython)) {
    Write-Host "Project venv not found ($VenvPython). Run 'uv sync' first." -ForegroundColor Red
    exit 1
}

function Get-FridaArch($abi) {
    switch -Wildcard ($abi) {
        "arm64-v8a" { return "arm64" }
        "armeabi*"  { return "arm" }
        "x86_64"    { return "x86_64" }
        "x86"       { return "x86" }
        default     { return $null }
    }
}

# --- host frida version -----------------------------------------------------
Write-Step "Reading host frida version"
try { $hostVer = (& $VenvPython -c "import frida;print(frida.__version__)").Trim() }
catch { Write-Host "frida not installed in the venv. Run 'uv sync'." -ForegroundColor Red; exit 1 }
Write-Ok "Host frida (Python bindings): $hostVer"

# --- device ------------------------------------------------------------------
Write-Step "Inspecting device"
$devLines = @((& adb devices) -split "`n" | Where-Object { $_ -match "\tdevice$" })
if (-not $devLines) {
    Write-Host "No authorized device. Connect one and accept USB debugging." -ForegroundColor Red
    exit 1
}
$serial = ($devLines[0] -split "\t")[0]
$abi = (& adb -s $serial shell getprop ro.product.cpu.abi).Trim()
$arch = Get-FridaArch $abi
Write-Ok "device=$serial  abi=$abi  arch=$arch"
if (-not $arch) { Write-Host "Unsupported abi '$abi'." -ForegroundColor Red; exit 1 }

# root?
$suId = (& adb -s $serial shell "su -c id 2>/dev/null") | Out-String
$rooted = $suId -match "uid=0"
Write-Ok ("root (su) available: " + $(if ($rooted) { "yes" } else { "no" }))

# --- existing frida-server on device ----------------------------------------
Write-Step "Checking existing frida-server on device"
$exists = (& adb -s $serial shell "ls $ServerPath 2>/dev/null") | Out-String
$deviceVer = ""
if ($exists -and $exists -notmatch "No such") {
    $deviceVer = ((& adb -s $serial shell "$ServerPath --version 2>/dev/null") | Out-String).Trim()
}
if ($deviceVer) { Write-Ok "Device frida-server: $deviceVer ($ServerPath)" }
else { Write-Warn "No usable frida-server found at $ServerPath" }

$needPush = $true
if ($deviceVer -eq $hostVer -and -not $Force) {
    Write-Ok "Device frida-server already matches host ($hostVer). Skipping download."
    $needPush = $false
} elseif ($deviceVer -and $deviceVer -ne $hostVer) {
    Write-Warn "Version mismatch (device $deviceVer vs host $hostVer) -> will replace."
}

# --- download + push ---------------------------------------------------------
if ($needPush) {
    $xzName = "frida-server-$hostVer-android-$arch.xz"
    $xzUrl = "https://github.com/frida/frida/releases/download/$hostVer/$xzName"
    $xzPath = Join-Path $dlDir $xzName
    $binPath = Join-Path $dlDir "frida-server-$hostVer-android-$arch"
    Write-Step "Downloading matching frida-server"
    Write-Host "    $xzUrl"
    Invoke-WebRequest -UseBasicParsing -Uri $xzUrl -OutFile $xzPath
    & $VenvPython -c "import lzma,shutil,sys; f=lzma.open(sys.argv[1]); o=open(sys.argv[2],'wb'); shutil.copyfileobj(f,o); o.close(); f.close()" $xzPath $binPath

    Write-Step "Pushing to device"
    & adb -s $serial push $binPath $ServerPath | Out-Null
    & adb -s $serial shell "chmod 755 $ServerPath"
    Write-Ok "frida-server $hostVer pushed to $ServerPath (arch $arch)"
}

# --- start (optional) --------------------------------------------------------
if ($Start) {
    Write-Step "Starting frida-server"
    if (-not $rooted) {
        Write-Warn "Device is not rooted (no su) -> cannot start frida-server."
        Write-Warn "Use a rooted device / emulator, or a frida-gadget-injected APK."
    } else {
        # Launch detached so this script does not block on the device shell.
        Start-Process -FilePath "adb" -WindowStyle Hidden -ArgumentList @(
            "-s", $serial, "shell", "su -c 'nohup $ServerPath >/dev/null 2>&1 &'")
        Start-Sleep -Seconds 2
        $running = (& adb -s $serial shell "ps -A 2>/dev/null | grep frida-server") | Out-String
        if ($running.Trim()) { Write-Ok "frida-server is running. Verify: frida-ps -U" }
        else { Write-Warn "frida-server did not appear running. Check manually: adb shell su -c '$ServerPath &'" }
    }
}

Write-Host "`nDone. Tip: in the MCP, call frida_check_compatibility to confirm." -ForegroundColor Green
