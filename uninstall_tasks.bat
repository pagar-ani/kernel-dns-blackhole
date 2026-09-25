@echo off
setlocal
echo [*] Uninstalling Kernel Blackhole and YogaDNS scheduled tasks...

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Requesting UAC elevation...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"%~dpnx0\"' -Verb RunAs"
    exit /b
)

schtasks /delete /tn "Kernel_Blackhole_Engine" /f >nul 2>&1
schtasks /delete /tn "YogaDNS_Sinkhole_Update" /f >nul 2>&1

echo [+] Scheduled tasks removed cleanly.
endlocal
