@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0CreateDebugReport.ps1"
echo.
pause
