@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0EnableCrashDumps.ps1" -NoPause %*
echo.
pause
