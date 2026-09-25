@echo off
REM Enterprise Network Blackhole Orchestrator (Kernel TCPIP Route Matrix)

:: STRICT UAC ELEVATION CHECK
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] ERROR: Execution denied. Mandatory Administrative Token missing.
    echo [*] Requesting dynamic UAC Elevation...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"%~dpnx0\"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

SET LOGFILE="%~dp0blackhole_engine.log"

echo ======================================================== >> %LOGFILE%
echo [%DATE% %TIME%] [*] Blackhole Sequence Initiated... >> %LOGFILE%

echo [*] Executing Native IP Radix Optimization...
python optimized_ingestion.py

echo [*] Injecting Mathematical Blackhole Routes...
powershell -NoProfile -ExecutionPolicy Bypass -Command "& { Start-Transcript -Path '%~dp0ps1_injection.log' -Append; & '%~dp0deploy_blackhole.ps1'; Stop-Transcript }"

echo [%DATE% %TIME%] [+] Enterprise Orchestration Sequence Complete. >> %LOGFILE%
echo [+] Blackhole injection complete.
