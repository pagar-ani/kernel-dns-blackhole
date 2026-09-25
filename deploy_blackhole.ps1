# Optimized Windows Kernel Blackhole Orchestrator (Layer 3 Null-Routing)
# Injects route blackhole into volatile RAM (store=active) in ~5 seconds.
$ErrorActionPreference = "Continue"
$listPath = Join-Path $PSScriptRoot "optimized_rules_merged.txt"

if (-Not (Test-Path $listPath)) {
    Write-Host "[!] Target rules matrix missing: $listPath"
    exit 1
}

$rules = Get-Content $listPath | Where-Object { $_.Trim() -ne "" }

$ipv4_cidr = @()
$ipv6_cidr = @()
$ipv4_hosts = @()
$ipv6_hosts = @()

foreach ($raw_rule in $rules) {
    $rule = $raw_rule.Trim()
    if ($rule -match "/") {
        if ($rule -match ":") {
            if ($rule -match "/128$") { $ipv6_hosts += $rule.Split('/')[0] } else { $ipv6_cidr += $rule }
        } else {
            if ($rule -match "/32$") { $ipv4_hosts += $rule.Split('/')[0] } else { $ipv4_cidr += $rule }
        }
    } else {
        if ($rule -match ":") { $ipv6_hosts += $rule } else { $ipv4_hosts += $rule }
    }
}

Write-Host "[*] Parsed Matrices:"
Write-Host "    IPv4 CIDR: $($ipv4_cidr.Count) | IPv6 CIDR: $($ipv6_cidr.Count)"
Write-Host "    IPv4 /32s: $($ipv4_hosts.Count) | IPv6 /128s: $($ipv6_hosts.Count)"

# Detect Loopback for Null-Routing
$loopbackV4 = Get-NetIPInterface | Where-Object { ($_.InterfaceAlias -match "Loopback") -and ($_.AddressFamily -eq "IPv4") } | Select-Object -ExpandProperty InterfaceIndex -First 1
$loopbackV6 = Get-NetIPInterface | Where-Object { ($_.InterfaceAlias -match "Loopback") -and ($_.AddressFamily -eq "IPv6") } | Select-Object -ExpandProperty InterfaceIndex -First 1

Write-Host "[*] Stage 1: Kernel Radix-Tree Injection (Route Blackhole)"
$BlackHoleMetric = 9999

# Eradicate historical orphaned matrix natively without WMI memory exhaustion
Write-Host "[*] Rapid Unmanaged Teardown Initiated. Bypassing WMI Memory Exhaustion Limits..."
$v4_clean_script = Join-Path $PSScriptRoot "v4_clean.netsh"
$v6_clean_script = Join-Path $PSScriptRoot "v6_clean.netsh"
$v4CleanCmds = [System.Collections.Generic.List[string]]::new()
$v6CleanCmds = [System.Collections.Generic.List[string]]::new()

foreach ($line in (netsh interface ipv4 show route | Select-String "\s+$BlackHoleMetric\s+")) {
    if ($line.Line -match '^\S+\s+\S+\s+\d+\s+(\S+)') {
        $prefix = $Matches[1]
        $v4CleanCmds.Add("interface ipv4 delete route prefix=$prefix interface=$loopbackV4 nexthop=0.0.0.0")
    }
}
foreach ($line in (netsh interface ipv6 show route | Select-String "\s+$BlackHoleMetric\s+")) {
    if ($line.Line -match '^\S+\s+\S+\s+\d+\s+(\S+)') {
        $prefix = $Matches[1]
        $v6CleanCmds.Add("interface ipv6 delete route prefix=$prefix interface=$loopbackV6 nexthop=::")
    }
}

if ($v4CleanCmds.Count -gt 0) {
    [System.IO.File]::WriteAllLines($v4_clean_script, $v4CleanCmds)
    netsh -f $v4_clean_script | Out-Null
    Remove-Item $v4_clean_script -ErrorAction SilentlyContinue
}
if ($v6CleanCmds.Count -gt 0) {
    [System.IO.File]::WriteAllLines($v6_clean_script, $v6CleanCmds)
    netsh -f $v6_clean_script | Out-Null
    Remove-Item $v6_clean_script -ErrorAction SilentlyContinue
}

$v4_script = Join-Path $PSScriptRoot "v4_blackhole.netsh"
$v6_script = Join-Path $PSScriptRoot "v6_blackhole.netsh"
$v4cmds = [System.Collections.Generic.List[string]]::new()
$v6cmds = [System.Collections.Generic.List[string]]::new()

# CRITICAL FIX: To prevent 'Registry I/O Death', we use 'store=active'.
# Writing 65,000 nodes sequentially to PersistentRoutes registry locks the OS for 30+ minutes.
# Pushing to RAM directly (store=active) injects all routes in ~5 seconds.
foreach ($net in $ipv4_hosts) {
    if ($loopbackV4) { $v4cmds.Add("interface ipv4 add route prefix=$net/32 interface=$loopbackV4 nexthop=0.0.0.0 metric=$BlackHoleMetric store=active") }
}
foreach ($net in $ipv6_hosts) {
    if ($loopbackV6) { $v6cmds.Add("interface ipv6 add route prefix=$net/128 interface=$loopbackV6 nexthop=:: metric=$BlackHoleMetric store=active") }
}

foreach ($net in $ipv4_cidr) {
    if ($loopbackV4) { $v4cmds.Add("interface ipv4 add route prefix=$net interface=$loopbackV4 nexthop=0.0.0.0 metric=$BlackHoleMetric store=active") }
}
foreach ($net in $ipv6_cidr) {
    if ($loopbackV6) { $v6cmds.Add("interface ipv6 add route prefix=$net interface=$loopbackV6 nexthop=:: metric=$BlackHoleMetric store=active") }
}

Write-Host "[*] Volatile RAM Unified Arrays compiled cleanly. Executing zero-latency batch sequence..."
if ($v4cmds.Count -gt 0) {
    [System.IO.File]::WriteAllLines($v4_script, $v4cmds)
    netsh -f $v4_script | Out-Null
    Remove-Item $v4_script -ErrorAction SilentlyContinue
}
if ($v6cmds.Count -gt 0) {
    [System.IO.File]::WriteAllLines($v6_script, $v6cmds)
    netsh -f $v6_script | Out-Null
    Remove-Item $v6_script -ErrorAction SilentlyContinue
}

Write-Host "[+] Absolute Volatile State-Agnostic OSI Layer 3 Execution Complete."
