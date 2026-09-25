@echo off
setlocal
echo [*] Requesting UAC elevation to register scheduled tasks...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \""%~dp0install_tasks.ps1\""' -Verb RunAs"
endlocal
