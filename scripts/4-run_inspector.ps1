# Android MCP Server - MCP Inspector launcher (for debugging tools)

$RepoDir = Split-Path $PSScriptRoot -Parent

# Load tool env vars from user scope so the inspected server finds
# jadx/apktool/java/adb (same as 3-run_server.ps1).
foreach ($name in @("JAVA_HOME", "JADX_PATH", "APKTOOL_PATH", "ADB_PATH")) {
    $val = [Environment]::GetEnvironmentVariable($name, "User")
    if ($val) { Set-Item -Path "Env:$name" -Value $val }
}
$pathAdds = @()
if ($env:JAVA_HOME) { $pathAdds += (Join-Path $env:JAVA_HOME "bin") }
if ($env:ADB_PATH)  { $pathAdds += $env:ADB_PATH }
$pathAdds += "C:\Users\user\platform-tools"
$env:PATH = ($pathAdds -join ";") + ";" + $env:PATH

npx @modelcontextprotocol/inspector uv --directory $RepoDir run server.py
