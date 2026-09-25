$ErrorActionPreference = "Stop"

# Ensure script is running with administrative privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Administrative token required to register Layer 3 Kernel Blackhole task." -ForegroundColor Yellow
    Write-Host "[*] Requesting UAC elevation..."
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$workDir = $PSScriptRoot

Write-Host "[*] Registering Scheduled Tasks from: $workDir" -ForegroundColor Cyan

# 1. Kernel Blackhole Task (Runs at Startup and every 3 days with Highest Privileges)
$blackholeBat = Join-Path $workDir "update_blackhole.bat"
$action1 = New-ScheduledTaskAction -Execute $blackholeBat -WorkingDirectory $workDir
$triggerStartup = New-ScheduledTaskTrigger -AtStartup
$trigger3Days = New-ScheduledTaskTrigger -Daily -DaysInterval 3 -At 02:00
$settings1 = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal1 = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest

Register-ScheduledTask -TaskName "Kernel_Blackhole_Engine" -Action $action1 -Trigger @($triggerStartup, $trigger3Days) -Settings $settings1 -Principal $principal1 -Force | Out-Null
Write-Host "[+] Task 'Kernel_Blackhole_Engine' registered (Runs at boot + every 3 days with Highest Privileges)." -ForegroundColor Green

# 2. YogaDNS Sinkhole Update Task (Runs weekly every Sunday at 02:00 as current user)
$sinkholeBat = Join-Path $workDir "update_sinkhole.bat"
$action2 = New-ScheduledTaskAction -Execute $sinkholeBat -WorkingDirectory $workDir
$triggerWeekly = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 02:00
$settings2 = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0

Register-ScheduledTask -TaskName "YogaDNS_Sinkhole_Update" -Action $action2 -Trigger $triggerWeekly -Settings $settings2 -Force | Out-Null
Write-Host "[+] Task 'YogaDNS_Sinkhole_Update' registered (Runs Sundays at 02:00)." -ForegroundColor Green

Write-Host "`n[+] All scheduling matrices armed successfully." -ForegroundColor Green
