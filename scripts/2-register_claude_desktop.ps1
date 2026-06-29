<#
.SYNOPSIS
    Find the local Claude Desktop config and add the Android Local MCP server.

.DESCRIPTION
    Discovers claude_desktop_config.json in both the standard location and the
    Microsoft Store (MSIX) package-virtualized location, then merges an
    mcp-remote entry for this server into mcpServers without disturbing other
    settings. A timestamped backup is written before any change.

    After running, FULLY quit Claude Desktop (tray icon -> Quit; closing the
    window leaves it running) and relaunch so the config is reloaded.

.PARAMETER Port
    Server port for the MCP URL (default 8000 -> http://127.0.0.1:8000/mcp).

.PARAMETER Url
    Full MCP URL override (takes precedence over -Port).

.PARAMETER Name
    mcpServers key to add/update (default "Android Local MCP").

.PARAMETER Token
    Optional bearer token; adds an Authorization header to the mcp-remote call.

.PARAMETER All
    Update every discovered config (default: only the primary, MSIX preferred).

.PARAMETER DryRun
    Show what would change without writing.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\2-register_claude_desktop.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\2-register_claude_desktop.ps1 -Port 8123 -All
#>

[CmdletBinding()]
param(
    [int]$Port = 8000,
    [string]$Url,
    [string]$Name = "Android Local MCP",
    [string]$Token,
    [switch]$All,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Write-Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    [OK] $m" -ForegroundColor Green }
function Write-Warn($m) { Write-Host "    [!] $m" -ForegroundColor Yellow }

if (-not $Url) { $Url = "http://127.0.0.1:$Port/mcp" }

# --- discover candidate config paths (MSIX first) ---------------------------
$candidates = @()
$pkgRoot = Join-Path $env:LOCALAPPDATA "Packages"
if (Test-Path $pkgRoot) {
    Get-ChildItem $pkgRoot -Directory -Filter "Claude_*" -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Join-Path $_.FullName "LocalCache\Roaming\Claude\claude_desktop_config.json"
        $candidates += [PSCustomObject]@{ Path = $p; Kind = "MSIX/Store" }
    }
}
$candidates += [PSCustomObject]@{
    Path = (Join-Path $env:APPDATA "Claude\claude_desktop_config.json"); Kind = "Standard"
}

Write-Step "Discovering Claude Desktop config locations"
foreach ($c in $candidates) {
    $state = if (Test-Path $c.Path) { "EXISTS" }
             elseif (Test-Path (Split-Path $c.Path)) { "dir present (no file yet)" }
             else { "not present" }
    Write-Host ("    [{0,-11}] {1}  ({2})" -f $c.Kind, $c.Path, $state)
}

# --- choose target(s) -------------------------------------------------------
$existing = @($candidates | Where-Object { Test-Path $_.Path })
if ($existing.Count -gt 0) {
    $targets = if ($All) { $existing } else { @($existing[0]) }
} else {
    # No config yet: create in the first candidate whose parent dir exists.
    $creatable = @($candidates | Where-Object { Test-Path (Split-Path $_.Path) })
    if ($creatable.Count -eq 0) {
        Write-Host "No Claude Desktop config or data directory found. Is Claude Desktop installed and run at least once?" -ForegroundColor Red
        exit 1
    }
    $targets = @($creatable[0])
    Write-Warn "No existing config; will create: $($targets[0].Path)"
}

# --- build the server entry -------------------------------------------------
$serverArgs = @("-y", "mcp-remote", $Url)
if ($Token) { $serverArgs += @("--header", "Authorization: Bearer $Token") }
$entry = [PSCustomObject]@{ command = "npx"; args = $serverArgs }

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

foreach ($t in $targets) {
    Write-Step "Updating $($t.Kind): $($t.Path)"

    if (Test-Path $t.Path) {
        try {
            $config = Get-Content $t.Path -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch {
            Write-Host "    Existing config is not valid JSON: $_" -ForegroundColor Red
            continue
        }
    } else {
        New-Item -ItemType Directory -Force -Path (Split-Path $t.Path) | Out-Null
        $config = [PSCustomObject]@{}
    }
    if ($null -eq $config) { $config = [PSCustomObject]@{} }

    # Ensure mcpServers exists.
    if (-not ($config.PSObject.Properties.Name -contains "mcpServers")) {
        $config | Add-Member -NotePropertyName "mcpServers" -NotePropertyValue ([PSCustomObject]@{})
    }

    $existed = $config.mcpServers.PSObject.Properties.Name -contains $Name
    if ($existed) {
        $config.mcpServers.$Name = $entry
    } else {
        $config.mcpServers | Add-Member -NotePropertyName $Name -NotePropertyValue $entry
    }

    $json = $config | ConvertTo-Json -Depth 64

    if ($DryRun) {
        $action = if ($existed) { "update" } else { "add" }
        Write-Warn "DryRun: would $action '$Name' -> $Url"
        Write-Host $json
        continue
    }

    # Idempotent: if the on-disk config already matches, skip (no backup spam).
    $current = ""
    if (Test-Path $t.Path) {
        try { $current = (Get-Content $t.Path -Raw -Encoding UTF8 | ConvertFrom-Json | ConvertTo-Json -Depth 64) } catch { $current = "" }
    }
    if ($current -eq $json) {
        Write-Ok "'$Name' already up to date (no change)."
        continue
    }

    # Backup, then write (UTF-8 without BOM).
    if (Test-Path $t.Path) {
        $bak = "$($t.Path).$(Get-Date -Format yyyyMMdd-HHmmss).bak"
        Copy-Item $t.Path $bak -Force
        Write-Ok "Backup: $bak"
    }
    [System.IO.File]::WriteAllText($t.Path, $json, $utf8NoBom)
    Write-Ok ("{0} '{1}' -> {2}" -f $(if ($existed) { "Updated" } else { "Added" }), $Name, $Url)
}

if (-not $DryRun) {
    Write-Host "`nDone. Now FULLY quit Claude Desktop (tray -> Quit) and relaunch" -ForegroundColor Green
    Write-Host "so it reloads the config, then check for the '$Name' tools." -ForegroundColor Green
}
