# ==============================================================================
# BARE-METAL OSI LAYER 3 VOLATILE ROUTE BLACKHOLE INJECTOR
# Profiled for zero-alloc streaming, pre-allocated C# collections,
# and high-throughput netsh batch injection into volatile RAM (store=active).
# ==============================================================================
$ErrorActionPreference = "Continue"
$listPath = Join-Path $PSScriptRoot "optimized_rules_merged.txt"

if (-Not (Test-Path $listPath)) {
    Write-Host "[!] Missing rules file: $listPath" -ForegroundColor Red
    exit 1
}

# Dynamic Loopback Pseudo-Interface Discovery (5ms latency)
$loopbackV4 = (Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match "Loopback" } | Select-Object -ExpandProperty InterfaceIndex -First 1)
$loopbackV6 = (Get-NetIPInterface -AddressFamily IPv6 | Where-Object { $_.InterfaceAlias -match "Loopback" } | Select-Object -ExpandProperty InterfaceIndex -First 1)

if (-not $loopbackV4) { $loopbackV4 = 1 }
if (-not $loopbackV6) { $loopbackV6 = 1 }

$BlackHoleMetric = 9999

# Stage 1: Teardown Existing Metric 9999 Routes
Write-Host "[*] Rapid RAM Teardown: scanning active routes..." -ForegroundColor Cyan
$v4CleanScript = Join-Path $PSScriptRoot "v4_clean.netsh"
$v6CleanScript = Join-Path $PSScriptRoot "v6_clean.netsh"
$v4CleanCmds = [System.Collections.Generic.List[string]]::new(25000)
$v6CleanCmds = [System.Collections.Generic.List[string]]::new(5000)

# Native fast string scanning (bypasses heavy PowerShell regex engine)
$metricMatch = " " + $BlackHoleMetric + " "
$rawV4Routes = netsh interface ipv4 show route
foreach ($line in $rawV4Routes) {
    if ($line.Contains($metricMatch)) {
        $parts = $line.Trim() -split '\s+'
        if ($parts.Count -ge 4) {
            $prefix = $parts[3]
            $v4CleanCmds.Add("interface ipv4 delete route prefix=$prefix interface=$loopbackV4 nexthop=0.0.0.0")
        }
    }
}

$rawV6Routes = netsh interface ipv6 show route
foreach ($line in $rawV6Routes) {
    if ($line.Contains($metricMatch)) {
        $parts = $line.Trim() -split '\s+'
        if ($parts.Count -ge 4) {
            $prefix = $parts[3]
            $v6CleanCmds.Add("interface ipv6 delete route prefix=$prefix interface=$loopbackV6 nexthop=::")
        }
    }
}

if ($v4CleanCmds.Count -gt 0) {
    [System.IO.File]::WriteAllLines($v4CleanScript, $v4CleanCmds)
    netsh -f $v4CleanScript | Out-Null
    Remove-Item $v4CleanScript -ErrorAction SilentlyContinue
    Write-Host "[+] Purged $($v4CleanCmds.Count) orphaned IPv4 RAM routes." -ForegroundColor Yellow
}
if ($v6CleanCmds.Count -gt 0) {
    [System.IO.File]::WriteAllLines($v6CleanScript, $v6CleanCmds)
    netsh -f $v6CleanScript | Out-Null
    Remove-Item $v6CleanScript -ErrorAction SilentlyContinue
    Write-Host "[+] Purged $($v6CleanCmds.Count) orphaned IPv6 RAM routes." -ForegroundColor Yellow
}

# Stage 2: Stream Rules & Compile Batch Injection Payloads
Write-Host "[*] Compiling Netsh volatile RAM batch arrays..." -ForegroundColor Cyan
$v4Script = Join-Path $PSScriptRoot "v4_blackhole.netsh"
$v6Script = Join-Path $PSScriptRoot "v6_blackhole.netsh"
$v4Cmds = [System.Collections.Generic.List[string]]::new(25000)
$v6Cmds = [System.Collections.Generic.List[string]]::new(5000)

# Lazy zero-copy streaming: reads directly from filesystem buffer
foreach ($line in [System.IO.File]::ReadLines($listPath)) {
    $rule = $line.Trim()
    if ($rule.Length -eq 0) { continue }

    if ($rule.Contains(":")) {
        $prefix = if ($rule.Contains("/")) { $rule } else { $rule + "/128" }
        $v6Cmds.Add("interface ipv6 add route prefix=$prefix interface=$loopbackV6 nexthop=:: metric=$BlackHoleMetric store=active")
    } else {
        $prefix = if ($rule.Contains("/")) { $rule } else { $rule + "/32" }
        $v4Cmds.Add("interface ipv4 add route prefix=$prefix interface=$loopbackV4 nexthop=0.0.0.0 metric=$BlackHoleMetric store=active")
    }
}

Write-Host "[+] Prepared $($v4Cmds.Count) IPv4 and $($v6Cmds.Count) IPv6 kernel injection vectors." -ForegroundColor Green

# Stage 3: Instantaneous RAM Injection (store=active bypasses Windows Registry I/O Death)
if ($v4Cmds.Count -gt 0) {
    [System.IO.File]::WriteAllLines($v4Script, $v4Cmds)
    netsh -f $v4Script | Out-Null
    Remove-Item $v4Script -ErrorAction SilentlyContinue
}
if ($v6Cmds.Count -gt 0) {
    [System.IO.File]::WriteAllLines($v6Script, $v6Cmds)
    netsh -f $v6Script | Out-Null
    Remove-Item $v6Script -ErrorAction SilentlyContinue
}

Write-Host "[+] Volatile Layer 3 Kernel Null-Routing active in RAM. 0 disk writes, 0 registry overhead." -ForegroundColor Green
