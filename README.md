# kernel-dns-blackhole

Dual-tier Windows endpoint security architecture combining bare-metal Layer 3 Kernel RAM null-routing (`TCPIP.sys`) with state-aware Layer 7 DNS filtering (YogaDNS) and deterministic WireGuard failover.

Engineered to resolve two systemic networking limitations on Windows 10/11:
1. **Corporate DNS Telemetry Leaks**: Windows Smart Multi-Homed Name Resolution broadcasting internal queries across unencrypted public physical adapters whenever VPN interfaces fluctuate.
2. **Resolver & Kernel Lockups**: Multi-megabyte flat `hosts` files driving Windows `dnscache` to 100% single-core saturation, and persistent route registry bloat causing 30-minute disk I/O freezes.

---

### Architectural Design

```
[Inbound Application Traffic / DNS Query]
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ TIER 1: WINDOWS KERNEL RAM BLACKHOLE (Layer 3 - TCPIP.sys)                  │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Ingests high-confidence malicious botnet & C2 IP subnets from threat feeds. │
│ • Stored entirely in volatile RAM (store=active) — Zero registry I/O bloat. │
│ • Compiles and injects 65,000+ routes in ~5 seconds via native netsh.       │
│ • Packets dropped at kernel routing boundary before socket inspection.      │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ TIER 2: YOGADNS STATEFUL DOMAIN SINKHOLE (Layer 7 - WFP Proxy)              │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Intercepts 4.4+ million tracking, advertising, and phishing domains.       │
│ • Deduplicates 16 threat feeds into unified 9-domain-per-line DNS scaling.   │
│ • Zero CPU saturation: completely bypasses Windows dnscache bottlenecks.    │
│ • Zero-downtime hot reload via direct AppData hosts cache synchronization.  │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ THE MASTER SWITCH: WIREGUARD AUTO-FAILOVER (Zero-Leak)                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ • WireGuard Active   ──► Routes to <YOUR_CORPORATE_DNS_IP> inside tunnel.   │
│ • WireGuard Inactive ──► Auto-diverts to Cloudflare Security DoH (1.0.0.2). │
│ • Corporate hostnames never touch public Wi-Fi or local ISP gateways.       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Threat Intelligence Taxonomy & Transparency

To ensure strict operational safety and prevent service disruption, threat ingestion is strictly bifurcated between Layer 3 and Layer 7:

#### 1. Tier 1: Layer 3 IP Blackhole Feeds (`ips.txt`)
*Architectural Rationale*: Multi-tenant CDNs (Cloudflare, AWS, Fastly) host both benign services and advertising endpoints on shared edge IPs. Null-routing an IP address associated with an advertising server would inadvertently break access to legitimate infrastructure. Therefore, **Layer 3 null-routing is strictly restricted to verified malicious C2 and botnet infrastructure**:

| Threat Provider | Feed Purpose | Target Threat Vector |
| :--- | :--- | :--- |
| **GreenSnow** | Global Brute-Force Feeds | Automated SSH/RDP brute-force and port scanners |
| **Emerging Threats (Block)** | Firewall Rule Drops | Verified botnet controllers, malware drop sites |
| **Emerging Threats (Compromised)** | Compromised Hosts | Host infrastructure actively participating in attacks |
| **Binary Defense Systems** | Banlist Feed | Live reconnaissance and exploitation IP ranges |
| **stamparm/ipsum (Level 3)** | Multi-Source Intelligence | High-confidence threats cited across $\ge 3$ blacklists |
| **Malware-Filter (Phishing)** | Abuse.ch / Gitlab Feed | Dedicated active phishing hosting servers |
| **Malware-Filter (URLhaus)** | Abuse.ch Telemetry | Infrastructure distributing verified malware payloads |
| **abuse.ch (Feodo Tracker)** | Botnet C2 IP Blocklist | Active banking trojan and botnet command-and-control servers |
| **abuse.ch (SSLBL)** | Malicious SSL Blacklist | Attacker-controlled SSL/TLS certificates and C2 infrastructure |

*Safeguard*: An immutable hardcoded whitelist protects core upstream infrastructure (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, etc.) from accidental inclusion.

#### 2. Tier 2: Layer 7 Domain Feeds (`lst.txt`)
Domain-level blocking provides fine-grained control without collateral network damage. Ingests 4.4+ million unique domains across 16 established threat lists:

| Feed Source | Primary Focus |
| :--- | :--- |
| **1Hosts (Xtra)** | Aggressive tracking, telemetry, scam, and malware domains |
| **CombinedPrivacyBlockLists** | Windows telemetry and third-party advertising tracking |
| **Dan Pollock (someonewhocares)** | Curated anti-malware and commercial tracking sinks |
| **Frogeye (1st & Multi-party)** | Third-party analytics beacons and data brokers |
| **HaGeZi (Multi TIF & Ultimate)** | Extensive threat intelligence and telemetry aggregation |
| **Bundy01 Meta Blocklists** | Consolidated dual-stack IPv4/IPv6 domain blocklists |
| **Pi-hole Core Blocklist** | General advertisement networks and IoT telemetry |
| **PhishDestroy** | Zero-day credential harvesting and credential fraud |
| **DurableNapkin Scam List** | Fraudulent web domains, investment scams, and malvertising |
| **StevenBlack Unified** | Comprehensive baseline protection across ads and malware |
| **Th3M3 Malware List** | Cryptominers, banking trojans, and ransomware endpoints |
| **iam-py-test Anti-Malware** | Fast-cycling emerging zero-day malware distribution domains |
| **URLhaus (abuse.ch)** | Validated active malware distribution domains |

---

### Deterministic WireGuard Switching (Zero-Leak)

In [`Configuration.template.xml`](Configuration.template.xml), the engine enables:
```xml
<Settings ignore_rule_if_interface_down="1" ... />
```

Rules execute strictly sequentially from top to bottom:

| Order | Rule Name | Trigger Condition | Engine Action | Target Resolver |
| :--- | :--- | :--- | :--- | :--- |
| **01** | `01-Sinkhole` | Domain matches `optimized_hosts.txt` | **Block** | Returns `0.0.0.0` immediately |
| **02** | `02-WireGuard-Corporate` | WireGuard NDIS Adapter is **UP** | **Process** | `<YOUR_CORPORATE_DNS_IP>` (Inside Tunnel) |
| **03** | `03-Default-Failover` | WireGuard NDIS Adapter is **DOWN** | **Process** | Cloudflare Security DoH (`1.0.0.2`) |

When the WireGuard tunnel drops, YogaDNS detects the missing NDIS adapter handle, **instantly skips Rule 02**, and evaluates Rule 03. Internal corporate hostnames are never transmitted across the local physical adapter.

---

### Deployment Protocol

#### 1. Prerequisites
- Windows 10 or 11 (64-bit).
- Python 3.x installed with `python` available on system PATH.
- [YogaDNS (Free Basic Tier)](https://yogadns.com/download/) installed.

#### 2. Profile Configuration
1. Open `Configuration.template.xml` in an editor.
2. Set `YOUR_WIREGUARD_INTERFACE_NAME` to your WireGuard adapter name (e.g., `wg0` or tunnel label).
   - *Query via PowerShell*: `Get-NetIPInterface | Where-Object { $_.InterfaceAlias -like "*wireguard*" }`
3. Set `YOUR_CORPORATE_DNS_IPV4` and `YOUR_CORPORATE_DNS_IPV6` to your internal corporate resolver addresses.
4. Import into YogaDNS: **YogaDNS -> File -> Import Configuration** (or copy directly to `%APPDATA%\YogaDNS\Configuration.xml`).

#### 3. Compile Feeds
Open terminal in project root:

1. **Compile Domain Sinkhole (Tier 2)**:
   ```cmd
   update_sinkhole.bat
   ```
   *Fetches 16 domain lists, compresses via 9-domain chunking, writes to `%APPDATA%\YogaDNS\optimized_hosts.txt`, and triggers silent zero-downtime reload.*

2. **Inject Kernel RAM Blackhole (Tier 1)**:
   Right-click and select **Run as Administrator**:
   ```cmd
   update_blackhole.bat
   ```
   *Ingests C2 IP lists, collapses subnets via Radix trees, and deploys Layer 3 null-routes to volatile kernel RAM in ~5 seconds.*

#### 4. Enable Automated Startup & Reboot Survival
Double-click:
```cmd
install_tasks.bat
```
*(Or right-click and select **Run as Administrator**).*

##### How Reboot Survival Works with Volatile RAM (`store=active`):
- **Why Volatile RAM?**: Standard Windows routing persists entries into the Windows Registry (`HKLM\...\PersistentRoutes`). Sequentially committing 21,000+ routes to disk causes severe **Registry I/O Death**, locking the operating system for 30+ minutes during boot. To ensure instantaneous ~2 second deployment with zero disk wear, all routes are pushed directly to `TCPIP.sys` volatile memory using `store=active`.
- **The Reboot Invariant**: Because volatile RAM routes intentionally vanish when the machine powers down or reboots, `install_tasks.ps1` establishes a **triple-trigger defense matrix** in Windows Task Scheduler so you never have to re-arm manually:
  1. **Boot Trigger (`-AtStartup`)**: Executes `update_blackhole.bat` during the early Windows kernel boot phase, re-injecting all 21,000+ null-routes into RAM before application network traffic commences.
  2. **Logon Trigger (`-AtLogOn`)**: Redundantly re-arms routes immediately upon administrative user logon (protecting against Fast Startup, hybrid sleep resume, and delayed network adapter initialization).
  3. **Periodic Maintenance (`-Daily -DaysInterval 3`)**: Executes every 72 hours at 02:00 to pull the latest upstream C2 IP lists, recalculate Radix trees, and hot-reload RAM routes.
- **YogaDNS Autostart**: Configured in `HKCU\...\Run` (`/AutoRun`) to mount WFP network drivers at logon and bind to `%APPDATA%\YogaDNS\optimized_hosts.txt`. The companion task **`YogaDNS_Sinkhole_Update`** refreshes the 4.4M+ domain blocklist every Sunday at 02:00 with zero downtime.

---

### Teardown Protocol (Clean Removal)

To completely remove all routing entries and automated background schedules:

1. Right-click and select **Run as Administrator**:
   ```cmd
   uninstall_tasks.bat
   ```
   *Terminates running engines and unregisters scheduled tasks from Windows Task Scheduler.*
2. Reset or remove YogaDNS: Open YogaDNS $\to$ **File** $\to$ **Reset to Defaults** (or uninstall via Windows Settings).
3. To flush all volatile kernel null-routes immediately without restarting:
   ```powershell
   Restart-Service -Name "Tcpip" -Force
   ```
   *(Or simply reboot the machine; all `store=active` routes clear automatically on power cycle).*

---

### Operational Verification

1. **Verify WireGuard Failover**:
   - Disconnect WireGuard. Check the YogaDNS live execution log at the bottom of the interface $\to$ requests route to **Rule 03 (Cloudflare DoH)**.
   - Connect WireGuard $\to$ requests map strictly to **Rule 02 (Corporate-Pool)**.
2. **Verify Kernel Blackhole Injection**:
   - Query the routing table for the custom allocation metric:
     ```cmd
     netsh interface ipv4 show route | findstr "9999"
     ```
   - Confirms thousands of malicious subnets pointed to Loopback with Metric `9999`.

---

### Architectural Invariants

1. **UDP Exclusivity on Corporate Pools**: Internal resolvers must remain configured for plain UDP (`plain_use_tcp="0"`). Enabling TCP fallback or DNSSEC on internal split-horizon systems induces severe handshake timeouts.
2. **Volatile RAM Storage (`store=active`)**: Routes are written exclusively to kernel memory to prevent Windows Registry disk thrashing.
3. **WMI Bypass**: Teardown parsing relies on flat `netsh` script generation to prevent CLR/WMI memory allocation exhaustion.

---

### License
Licensed under the [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE).

**Commercial Restriction**: Free for personal, non-commercial, and open-source deployment. Any commercial use, proprietary redistribution, commercial integration, or enterprise re-selling requires explicit prior written permission.
