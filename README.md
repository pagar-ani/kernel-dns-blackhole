# kernel-dns-blackhole

Zero-leak dual-DNS routing engine and Layer 3 kernel blackhole for Windows 10/11.

Combines state-aware Layer 7 DNS filtering (YogaDNS) with bare-metal Layer 3 route null-routing (`TCPIP.sys`). Built to solve two critical Windows networking failures:
1. **Corporate DNS Leaks**: Automatically switches between internal corporate DNS (when WireGuard is UP) and encrypted Cloudflare DoH (when WireGuard is DOWN), with zero query leakage over public Wi-Fi.
2. **DNS & Firewall Lockups**: Compresses 3.6 million domain blocklists to bypass Windows `dnscache` CPU saturation, and injects 65,000+ malicious IP routes into kernel RAM in ~5 seconds without freezing the Windows Registry.

---

### Core Architecture

```
[Inbound Application Traffic / DNS Query]
                  │
                  ▼
┌────────────────────────────────────────────────────────┐
│ Layer 7: The Sinkhole (optimized_hosts.txt)            │
│ Is domain in 3.6M blocklist?                           │
└────────────────────────────────────────────────────────┘
         │ YES                           │ NO
         ▼                               ▼
   [Drop to 0.0.0.0]    ┌────────────────────────────────────────────────┐
                        │ Layer 7: NDIS WireGuard Interface Gate         │
                        │ Is WireGuard Interface UP?                     │
                        └────────────────────────────────────────────────┘
                                 │ YES                           │ NO (Interface Down)
                                 ▼                               ▼
                        [Corporate-Pool]                ┌────────────────────────────────┐
                        (Internal Plain UDP)            │ Fallback / Public Resolver     │
                        (No leaks outside tunnel)       │ Cloudflare Security DoH        │
                                                        └────────────────────────────────┘

───────────────────────────────────────────────────────────────────────────
Layer 3: Kernel Radix Blackhole (TCPIP.sys)
Outbound IP packets targeting known C2/botnet ranges are null-routed directly
to Loopback (0.0.0.0 / ::) via volatile kernel routing table (store=active).
───────────────────────────────────────────────────────────────────────────
```

---

### Why this is required itself?

- **The Hosts File Failure**: Windows DNS client (`svchost.exe/dnscache`) is single-threaded. Pointing `hosts` to 90MB lists causes 100% CPU lockups and high DNS latency.
- **The WireGuard DNS Leak Problem**: Windows Smart Multi-Homed Name Resolution sends DNS queries out of *all* active physical adapters simultaneously. Corporate hostnames routinely leak over untrusted local Wi-Fi.
- **Why Acrylic / DNSCrypt Fail**: Neither resolver tracks dynamic NDIS interface changes when `Wintun` (WireGuard) adapters fluctuate.
- **Why Simplewall / Software Firewalls Fail**: Application-layer WFP rules can be bypassed or overridden by driver weighting collisions. Layer 3 kernel null-routing drops packets inside the OS network stack itself before socket inspection.

---

### Key Technical Mechanisms

#### 1. Conditional Dual-DNS Switching (No Leaks)
In `Configuration.template.xml`, YogaDNS uses:
```xml
<Settings ignore_rule_if_interface_down="1" ... />
```
- **Rule 01 (Sinkhole)**: Checks `optimized_hosts.txt`. If domain matches, immediately returns `0.0.0.0`.
- **Rule 02 (WireGuard Tunnel)**: Bound to your WireGuard adapter name (`interface_id="YOUR_WG_INTERFACE"`). Routes to `Corporate-Pool` (`10.0.0.1`).
  - **When WireGuard is UP**: Rule 02 matches. All queries go securely through the corporate tunnel.
  - **When WireGuard is DOWN**: YogaDNS detects interface is offline, **automatically skips Rule 02**, and drops into Rule 03.
- **Rule 03 (Public Failover)**: Default catch-all rule pointing to `Public-Pool` (Cloudflare DoH `1.0.0.2` & `2606:4700:4700::1112`).
  - Corporate DNS is never queried over public Wi-Fi. Zero leakage.

#### 2. The 9-Domain-Per-Line Scaling Trick (`optimizer.py`)
Standard Windows caching resolvers support up to 9 domain aliases mapped per line:
```text
0.0.0.0 d1.com d2.com d3.com d4.com d5.com d6.com d7.com d8.com d9.com
```
This reduces flat file size from **92 MB down to ~3.6 MB**, shrinking memory ingestion time by 90%.

#### 3. Bypassing Windows Registry I/O Death (`store=active`)
Writing 65,000 persistent routes to `HKLM\...\PersistentRoutes` takes 30+ minutes and freezes Windows disk I/O.
`deploy_blackhole.ps1` injects routes using `store=active`:
- Writes directly to volatile kernel RAM in **~5 seconds**.
- An automated startup task (`Kernel_Blackhole_Engine`) re-injects the RAM table at boot cleanly.

#### 4. Bypassing WMI Memory Exhaustion
Tearing down 65,000 routes using PowerShell `Remove-NetRoute` exhausts WMI/CLR object heaps, hanging the terminal for minutes.
Our engine parses `netsh interface ipv4 show route` with Metric `9999` and executes flat batch teardown scripts in under 2 seconds.

---

### Step-by-Step Setup Guide

#### Prerequisites
1. Windows 10 or 11 (64-bit).
2. Python 3.x installed and added to PATH.
3. [YogaDNS (Free Basic Tier)](https://yogadns.com/download/) installed.

---

#### Step 1: Configure YogaDNS Profile
1. Open `Configuration.template.xml`.
2. Replace `YOUR_WIREGUARD_INTERFACE_NAME` with your actual WireGuard adapter name (e.g. `wg0` or tunnel name from WireGuard GUI).
   - *To find your interface name in PowerShell*: `Get-NetIPInterface | Where-Object { $_.InterfaceAlias -like "*wireguard*" }`
3. Replace `10.0.0.1` and `fd00::1` with your internal corporate DNS IPs.
4. Import the file into YogaDNS: **YogaDNS -> File -> Import Configuration** (or copy to `%APPDATA%\YogaDNS\Configuration.xml`).

---

#### Step 2: Ingest Feeds & Build Initial Matrices
Open terminal in the project directory and run:

1. **Compile Domain Sinkhole (3.6M domains)**:
   ```cmd
   update_sinkhole.bat
   ```
   *Pulls 16 threat lists from `lst.txt`, builds `optimized_hosts.txt`, copies to YogaDNS AppData, and triggers zero-downtime proxy reload.*

2. **Compile Kernel IP Blackhole (Run as Administrator)**:
   ```cmd
   update_blackhole.bat
   ```
   *Fetches high-confidence C2/malware IP feeds from `ips.txt`, collapses subnets via Radix trees, and injects Layer 3 null-routes into kernel RAM.*

---

#### Step 3: Enable Startup & Autonomous Updates (One-Click)
Run `install_tasks.bat` (requests UAC elevation):
```cmd
install_tasks.bat
```
This registers two native Windows Scheduled Tasks:
1. **`Kernel_Blackhole_Engine`**: Runs at system boot (`-AtStartup`) + every 3 days under `NT AUTHORITY\SYSTEM` (rebuilds volatile RAM blackhole).
2. **`YogaDNS_Sinkhole_Update`**: Runs every Sunday at 02:00 to refresh threat lists and hot-reload YogaDNS.

To remove scheduled tasks at any time:
```cmd
uninstall_tasks.bat
```

---

### How to Test & Verify

1. **Test Failover (WireGuard Disconnected)**:
   - Disconnect WireGuard.
   - Open YogaDNS Real-Time Log window at the bottom of the GUI.
   - Open browser and visit `dnsleaktest.com`.
   - Result: Queries map deterministically to **Rule 03 (Cloudflare DoH)**. Zero corporate DNS queries sent.
2. **Test Tunnel (WireGuard Connected)**:
   - Connect WireGuard.
   - Query an internal corporate hostname.
   - Result: Queries map to **Rule 02 (Corporate-Pool)** via interface hook.
3. **Test L3 Null-Route**:
   - Run in terminal: `netsh interface ipv4 show route | findstr "9999"`
   - Result: Shows thousands of malicious subnets pointed to Loopback with Metric 9999.

---

### Boundary Conditions & Technical Invariants

1. **Never enable TCP or DNSSEC for Corporate Pools**: Internal DNS servers often reject TCP fallback or lack DNSSEC trust chains. Enabling them will cause severe latency timeouts and broken internal resolution.
2. **Immutable Whitelist**: `optimized_ingestion.py` hardcodes an immutable whitelist (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, etc.) to prevent contaminated threat feeds from ever null-routing upstream DNS infrastructure.

---

### License
MIT. Do the needful and deploy responsibly.
