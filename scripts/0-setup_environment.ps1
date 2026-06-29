<#
.SYNOPSIS
    Check for and install everything the Android MCP Server needs:
    ADB (platform-tools), Java (JRE), JADX, and Frida (host bindings).
    Optionally pushes a matching frida-server to a connected device.
    No administrator rights required.

.DESCRIPTION
    For each tool the script first checks whether it is already available and
    only installs what is missing. User-scope environment variables
    (ADB_PATH, JAVA_HOME, JADX_PATH) and the user PATH are updated so the MCP
    server can discover the tools.

.PARAMETER InstallDir
    Where portable tools are installed. Default: %USERPROFILE%\.android-mcp-tools

.PARAMETER JavaFeatureVersion
    Java major version to install when needed. Default: 17 (LTS).

.PARAMETER SetupFridaServer
    Also download the matching frida-server for the connected device's
    architecture and push it to /data/local/tmp (device must be authorized).

.PARAMETER StartFridaServer
    After pushing, attempt to start frida-server via `su -c` (rooted device).

.PARAMETER Skip
    One or more of: Adb, Java, Jadx, Frida  (skip those steps).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\setup_environment.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\setup_environment.ps1 -SetupFridaServer -StartFridaServer
#>

[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:USERPROFILE ".android-mcp-tools"),
    [int]$JavaFeatureVersion = 17,
    [switch]$SetupFridaServer,
    [switch]$StartFridaServer,
    # Comma/space-separated list of steps to skip: Adb, Java, Jadx, Apktool, Frida
    # (a string so it works reliably when this script is invoked via -File).
    [string]$Skip = ""
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$SkipList = @($Skip -split '[,\s]+' | Where-Object { $_ })
$validSkip = @("Adb", "Java", "Jadx", "Apktool", "Frida")
foreach ($s in $SkipList) {
    if ($validSkip -notcontains $s) {
        Write-Host "Unknown -Skip value '$s'. Valid: $($validSkip -join ', ')" -ForegroundColor Red
        exit 1
    }
}

function Write-Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    [OK] $m" -ForegroundColor Green }
function Write-Warn($m) { Write-Host "    [!] $m" -ForegroundColor Yellow }
function Has-Command($n) { return [bool](Get-Command $n -ErrorAction SilentlyContinue) }

$RepoDir = Split-Path $PSScriptRoot -Parent
$VenvPython = Join-Path $RepoDir ".venv\Scripts\python.exe"
$summary = [ordered]@{}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$downloadDir = Join-Path $InstallDir "_downloads"
New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null

function Add-UserPath($dir) {
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($userPath -notlike "*$dir*") {
        $newPath = if ($userPath) { "$dir;$userPath" } else { $dir }
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
    }
    $env:PATH = "$dir;$env:PATH"
}

# ===========================================================================
# 1. ADB (platform-tools)
# ===========================================================================
if ($SkipList -contains "Adb") {
    Write-Step "Skipping ADB"
} elseif (Has-Command "adb") {
    Write-Step "ADB already installed"
    Write-Ok ((& adb version 2>&1 | Select-Object -First 1))
    $summary["ADB"] = "already present"
} else {
    Write-Step "Installing Android platform-tools (ADB)"
    $ptZip = Join-Path $downloadDir "platform-tools.zip"
    Invoke-WebRequest -UseBasicParsing `
        -Uri "https://dl.google.com/android/repository/platform-tools-latest-windows.zip" `
        -OutFile $ptZip
    if (Test-Path (Join-Path $InstallDir "platform-tools")) {
        Remove-Item -Recurse -Force (Join-Path $InstallDir "platform-tools")
    }
    Expand-Archive -Path $ptZip -DestinationPath $InstallDir -Force
    $ptDir = Join-Path $InstallDir "platform-tools"
    [Environment]::SetEnvironmentVariable("ADB_PATH", $ptDir, "User")
    $env:ADB_PATH = $ptDir
    Add-UserPath $ptDir
    Write-Ok "platform-tools at $ptDir (ADB_PATH set)"
    $summary["ADB"] = "installed -> $ptDir"
}

# ===========================================================================
# 2. Java (JRE)
# ===========================================================================
function Get-JavaMajor {
    if (-not (Has-Command "java")) { return 0 }
    try { $o = & java -version 2>&1 | Out-String } catch { return 0 }
    if ($o -match 'version "1\.(\d+)') { return [int]$Matches[1] }
    if ($o -match 'version "(\d+)')    { return [int]$Matches[1] }
    return 0
}

$javaHome = $null
if ($SkipList -contains "Java") {
    Write-Step "Skipping Java"
} else {
    $jmajor = Get-JavaMajor
    if ($jmajor -ge 11) {
        Write-Step "Java already installed (major $jmajor)"
        $summary["Java"] = "already present (major $jmajor)"
    } else {
        Write-Step "Installing portable Temurin JRE $JavaFeatureVersion"
        $jreZip = Join-Path $downloadDir "temurin-jre.zip"
        Invoke-WebRequest -UseBasicParsing `
            -Uri "https://api.adoptium.net/v3/binary/latest/$JavaFeatureVersion/ga/windows/x64/jre/hotspot/normal/eclipse" `
            -OutFile $jreZip
        $jreExtract = Join-Path $InstallDir "jre"
        if (Test-Path $jreExtract) { Remove-Item -Recurse -Force $jreExtract }
        Expand-Archive -Path $jreZip -DestinationPath $jreExtract -Force
        $jreRoot = Get-ChildItem -Path $jreExtract -Directory | Select-Object -First 1
        if (-not $jreRoot) { throw "Could not locate extracted JRE under $jreExtract" }
        $javaHome = $jreRoot.FullName
        [Environment]::SetEnvironmentVariable("JAVA_HOME", $javaHome, "User")
        $env:JAVA_HOME = $javaHome
        Add-UserPath (Join-Path $javaHome "bin")
        Write-Ok "JRE at $javaHome (JAVA_HOME set)"
        $summary["Java"] = "installed -> $javaHome"
    }
}

# ===========================================================================
# 3. JADX
# ===========================================================================
if ($SkipList -contains "Jadx") {
    Write-Step "Skipping JADX"
} elseif ($env:JADX_PATH -and (Test-Path $env:JADX_PATH)) {
    Write-Step "JADX already configured: $env:JADX_PATH"
    $summary["JADX"] = "already present"
} elseif (Has-Command "jadx") {
    Write-Step "JADX already on PATH"
    $summary["JADX"] = "already on PATH"
} else {
    Write-Step "Installing latest JADX"
    $release = Invoke-RestMethod -UseBasicParsing `
        -Uri "https://api.github.com/repos/skylot/jadx/releases/latest" `
        -Headers @{ "User-Agent" = "android-mcp-installer" }
    $asset = $release.assets |
        Where-Object { $_.name -match '^jadx-\d.*\.zip$' -and $_.name -notmatch 'gui' } |
        Select-Object -First 1
    if (-not $asset) { throw "No jadx-*.zip asset found in latest release." }
    $jadxZip = Join-Path $downloadDir $asset.name
    Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile $jadxZip
    $jadxDir = Join-Path $InstallDir "jadx"
    if (Test-Path $jadxDir) { Remove-Item -Recurse -Force $jadxDir }
    Expand-Archive -Path $jadxZip -DestinationPath $jadxDir -Force
    $jadxBat = Get-ChildItem -Path $jadxDir -Recurse -Filter "jadx.bat" | Select-Object -First 1
    if (-not $jadxBat) { throw "jadx.bat not found after extraction." }
    [Environment]::SetEnvironmentVariable("JADX_PATH", $jadxBat.FullName, "User")
    $env:JADX_PATH = $jadxBat.FullName
    Write-Ok "JADX $($release.tag_name) at $($jadxBat.FullName) (JADX_PATH set)"
    $summary["JADX"] = "installed $($release.tag_name)"
}

# ===========================================================================
# 3b. apktool (resources + smali decoding)
# ===========================================================================
if ($SkipList -contains "Apktool") {
    Write-Step "Skipping apktool"
} elseif ($env:APKTOOL_PATH -and (Test-Path $env:APKTOOL_PATH)) {
    Write-Step "apktool already configured: $env:APKTOOL_PATH"
    $summary["apktool"] = "already present"
} elseif (Has-Command "apktool") {
    Write-Step "apktool already on PATH"
    $summary["apktool"] = "already on PATH"
} else {
    Write-Step "Installing apktool"
    $apktoolDir = Join-Path $InstallDir "apktool"
    New-Item -ItemType Directory -Force -Path $apktoolDir | Out-Null
    # Latest jar from GitHub releases
    $rel = Invoke-RestMethod -UseBasicParsing `
        -Uri "https://api.github.com/repos/iBotPeaches/Apktool/releases/latest" `
        -Headers @{ "User-Agent" = "android-mcp-installer" }
    $jarAsset = $rel.assets | Where-Object { $_.name -match '^apktool_.*\.jar$' } | Select-Object -First 1
    if (-not $jarAsset) { throw "No apktool_*.jar asset in latest release." }
    Invoke-WebRequest -UseBasicParsing -Uri $jarAsset.browser_download_url `
        -OutFile (Join-Path $apktoolDir "apktool.jar")
    # Windows wrapper script
    Invoke-WebRequest -UseBasicParsing `
        -Uri "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat" `
        -OutFile (Join-Path $apktoolDir "apktool.bat")
    $apktoolBat = Join-Path $apktoolDir "apktool.bat"
    [Environment]::SetEnvironmentVariable("APKTOOL_PATH", $apktoolBat, "User")
    $env:APKTOOL_PATH = $apktoolBat
    Write-Ok "apktool $($rel.tag_name) at $apktoolBat (APKTOOL_PATH set)"
    $summary["apktool"] = "installed $($rel.tag_name)"
}

# ===========================================================================
# 4. Frida (host bindings, into the project venv)
# ===========================================================================
if ($SkipList -contains "Frida") {
    Write-Step "Skipping Frida"
} else {
    Write-Step "Ensuring Frida host bindings in the project venv"
    $fridaOk = $false
    if (Test-Path $VenvPython) {
        try { & $VenvPython -c "import frida" 2>$null; if ($LASTEXITCODE -eq 0) { $fridaOk = $true } } catch {}
    }
    if ($fridaOk) {
        $fv = & $VenvPython -c "import frida;print(frida.__version__)"
        Write-Ok "frida already installed (host $fv)"
        $summary["Frida"] = "already present (host $fv)"
    } else {
        if (Has-Command "uv") {
            Write-Host "    Running 'uv sync' in $RepoDir"
            Push-Location $RepoDir
            try { & uv sync } finally { Pop-Location }
        } elseif (Test-Path $VenvPython) {
            Write-Host "    Running pip install frida frida-tools"
            & $VenvPython -m pip install frida frida-tools
        } else {
            throw "No uv and no project venv found. Run 'uv sync' in $RepoDir first."
        }
        $fv = & $VenvPython -c "import frida;print(frida.__version__)"
        Write-Ok "frida installed (host $fv)"
        $summary["Frida"] = "installed (host $fv)"
    }
}

# ===========================================================================
# 5. (optional) frida-server on the device
# ===========================================================================
# Delegated to 1-setup_frida_server.ps1 (version-checks host vs device, then
# pushes the matching build). Keeps a single source of truth.
if ($SetupFridaServer) {
    Write-Step "Setting up frida-server on the device"
    & (Join-Path $PSScriptRoot "1-setup_frida_server.ps1") -Start:$StartFridaServer
    $summary["frida-server"] = "via 1-setup_frida_server.ps1"
}

# ===========================================================================
# 6. mitmproxy (network capture) - presence check only
# ===========================================================================
Write-Step "Checking mitmproxy (network capture)"
if (Has-Command "mitmdump") {
    Write-Ok "mitmdump found"
    $summary["mitmproxy"] = "already present"
} else {
    Write-Warn "mitmdump not found. For network_* tools install mitmproxy: winget install mitmproxy"
    $summary["mitmproxy"] = "NOT installed (optional)"
}

# ===========================================================================
# Summary
# ===========================================================================
Write-Step "Summary"
foreach ($k in $summary.Keys) { Write-Host ("    {0,-14}: {1}" -f $k, $summary[$k]) }

Write-Host "`nDone." -ForegroundColor Green
Write-Host "Open a NEW terminal (or restart the MCP server) so updated" -ForegroundColor Green
Write-Host "environment variables (ADB_PATH / JAVA_HOME / JADX_PATH) take effect." -ForegroundColor Green
