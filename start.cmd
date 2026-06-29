@echo off
REM One-click launcher: double-click this file in Explorer.
REM Runs setup (if needed) -> register Claude Desktop -> start the server.
REM Pass-through args work too, e.g.: start.cmd -Frida -Port 8123
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*
pause
