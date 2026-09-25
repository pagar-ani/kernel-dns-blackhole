$ErrorActionPreference = "Continue"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Administrative token required to unregister scheduled tasks and flush routes." -ForegroundColor Yellow
    Write-Host "[*] Requesting UAC elevation..."
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "[*] Unregistering Scheduled Tasks..." -ForegroundColor Cyan

Unregister-ScheduledTask -TaskName "Kernel_Blackhole_Engine" -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "[+] Task 'Kernel_Blackhole_Engine' removed." -ForegroundColor Green

Unregister-ScheduledTask -TaskName "YogaDNS_Sinkhole_Update" -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "[+] Task 'YogaDNS_Sinkhole_Update' removed." -ForegroundColor Green

Write-Host "[*] Purging active metric 9999 RAM routes..." -ForegroundColor Cyan
$metricMatch = " 9999 "
$loopbackV4 = (Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match "Loopback" } | Select-Object -ExpandProperty InterfaceIndex -First 1)
$loopbackV6 = (Get-NetIPInterface -AddressFamily IPv6 | Where-Object { $_.InterfaceAlias -match "Loopback" } | Select-Object -ExpandProperty InterfaceIndex -First 1)
if (-not $loopbackV4) { $loopbackV4 = 1 }
if (-not $loopbackV6) { $loopbackV6 = 1 }

$v4CleanCmds = [System.Collections.Generic.List[string]]::new(25000)
$v6CleanCmds = [System.Collections.Generic.List[string]]::new(5000)

foreach ($line in (netsh interface ipv4 show route)) {
    if ($line.Contains($metricMatch)) {
        $parts = $line.Trim() -split '\s+'
        if ($parts.Count -ge 4) {
            $v4CleanCmds.Add("interface ipv4 delete route prefix=$($parts[3]) interface=$loopbackV4 nexthop=0.0.0.0")
        }
    }
}
foreach ($line in (netsh interface ipv6 show route)) {
    if ($line.Contains($metricMatch)) {
        $parts = $line.Trim() -split '\s+'
        if ($parts.Count -ge 4) {
            $v6CleanCmds.Add("interface ipv6 delete route prefix=$($parts[3]) interface=$loopbackV6 nexthop=::")
        }
    }
}

if ($v4CleanCmds.Count -gt 0) {
    $tempV4 = [System.IO.Path]::GetTempFileName()
    [System.IO.File]::WriteAllLines($tempV4, $v4CleanCmds)
    netsh -f $tempV4 | Out-Null
    Remove-Item $tempV4 -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Purged $($v4CleanCmds.Count) active IPv4 RAM blackhole routes." -ForegroundColor Green
}
if ($v6CleanCmds.Count -gt 0) {
    $tempV6 = [System.IO.Path]::GetTempFileName()
    [System.IO.File]::WriteAllLines($tempV6, $v6CleanCmds)
    netsh -f $tempV6 | Out-Null
    Remove-Item $tempV6 -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Purged $($v6CleanCmds.Count) active IPv6 RAM blackhole routes." -ForegroundColor Green
}

Write-Host "`n[+] Teardown complete. All persistent schedules eradicated and volatile RAM routes flushed." -ForegroundColor Green
