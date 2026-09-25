@echo off
REM Enterprise Kernel Blackhole Runner
cd /d "%~dp0"

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Requesting Administrative Privileges for Kernel Blackhole...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"%~dpnx0\"' -Verb RunAs"
    exit /b
)

echo [*] Resolving and collapsing Radix IP feeds...
python optimized_ingestion.py

echo [*] Injecting volatile RAM routes into TCPIP.sys...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy_blackhole.ps1"

echo [+] Blackhole deployment cycle complete.
