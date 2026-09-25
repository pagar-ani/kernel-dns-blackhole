# kernel-dns-blackhole

Dual-tier endpoint defense for Windows 10/11: Bare-metal Layer 3 Kernel RAM blackhole + Layer 7 state-aware DNS sinkhole with automatic WireGuard failover.

Built to solve two stubborn Windows networking headaches:
1. **Corporate DNS Leaks**: Windows leaking internal DNS queries across public Wi-Fi when VPN drops.
2. **DNS & Firewall Freezes**: Multi-megabyte `hosts` files causing 100% CPU lockups, and massive firewall rule imports freezing disk I/O.

---

### The Two-Tier Defense Architecture

Unlike basic DNS switchers or flat hosts blockers, this ecosystem runs two distinct physical layers:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ TIER 1: WINDOWS KERNEL RAM BLACKHOLE (Layer 3 - TCPIP.sys)                  │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Ingests 65,000+ malicious botnet & C2 IP subnets from threat feeds.       │
│ • STORED 100% IN VOLATILE RAM (store=active) — Zero disk writes!            │
│ • Injects in ~5 seconds flat (avoids the 30-minute Windows Registry lockup).│
│ • Packets dropped at Layer 3 kernel routing before socket/firewall inspection.│
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ TIER 2: YOGADNS STATEFUL DOMAIN SINKHOLE (Layer 7 - WFP Proxy)              │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Blocks 3.6 million tracking, ad, and malware domains at Layer 7.          │
│ • Compresses 92 MB blocklist to ~3.6 MB via the 9-domain-per-line trick.    │
│ • Zero CPU saturation: completely bypasses Windows dnscache lockup.         │
│ • Zero-downtime hot reload via YogaDNS -reload without dropping connections. │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ THE MASTER SWITCH: WIREGUARD AUTO-FAILOVER (Zero-Leak)                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ • WireGuard UP   ──► Queries route to <YOUR_CORPORATE_DNS_IP> in tunnel.    │
│ • WireGuard DOWN ──► Auto-switches to Cloudflare DoH (1.0.0.2).             │
│ • Corporate hostnames NEVER touch public Wi-Fi or local ISP adapters.       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Why this is required itself?

- **The Hosts File Mess**: Windows DNS cache service (`dnscache`) is single-threaded. Pointing it to a massive 90MB hosts file locks CPU at 100% and spikes ping latency.
- **The Windows VPN Leak**: Windows Smart Multi-Homed Name Resolution sends queries out of *all* network adapters simultaneously. The moment your WireGuard tunnel fluctuates, internal corporate hostnames leak right onto public Wi-Fi.
- **Why Acrylic and DNSCrypt Fail**: Neither tracks the dynamic NDIS adapter states of transient WireGuard (`Wintun`) interfaces.
- **The Registry I/O Death**: Writing 65,000 routes persistently into `HKLM\...\PersistentRoutes` takes 30+ minutes and grinds Windows disk I/O to a dead stop. Our Tier 1 engine uses `store=active` to push directly into volatile kernel RAM in 5 seconds.

---

### How the WireGuard Auto-Switching Works

In `Configuration.template.xml`, YogaDNS uses:
```xml
<Settings ignore_rule_if_interface_down="1" ... />
```

The rules execute strictly from top to bottom:

| Order | Rule Name | Condition | Action | Target Destination |
| :--- | :--- | :--- | :--- | :--- |
| **01** | `01-Sinkhole` | Domain matches `optimized_hosts.txt` | **Block** | Returns `0.0.0.0` immediately |
| **02** | `02-WireGuard-Corporate` | WireGuard adapter is **UP** | **Process** | `<YOUR_CORPORATE_DNS_IP>` (Inside Tunnel) |
| **03** | `03-Default-Failover` | WireGuard adapter is **DOWN** | **Process** | Cloudflare Security DoH (`1.0.0.2`) |

When you disconnect WireGuard, YogaDNS detects the interface is down, **skips Rule 02 completely**, and falls straight through to Rule 03. Your corporate DNS is never queried over public Wi-Fi.

---

### Quick Setup (5 Steps)

#### 1. Prerequisites
- Windows 10 or 11 (64-bit).
- Python 3.x installed (make sure "Add Python to PATH" is checked).
- [YogaDNS (Free Basic Tier)](https://yogadns.com/download/) installed.

#### 2. Configure Your YogaDNS Profile
1. Open `Configuration.template.xml` in Notepad.
2. Replace `YOUR_WIREGUARD_INTERFACE_NAME` with your actual WireGuard adapter name (e.g. `wg0` or tunnel name from WireGuard GUI).
3. Replace `YOUR_CORPORATE_DNS_IPV4` with your internal corporate DNS IP.
4. Import into YogaDNS: **File -> Import Configuration** (or copy to `%APPDATA%\YogaDNS\Configuration.xml`).

#### 3. Build Domain Sinkhole (Tier 2)
Double-click:
```cmd
update_sinkhole.bat
```
*Parses 16 threat feeds from `lst.txt`, deduplicates 3.6M domains, chunks 9 domains per line into `optimized_hosts.txt`, copies to YogaDNS AppData, and triggers silent reload.*

#### 4. Inject Kernel RAM Blackhole (Tier 1)
Right-click and select **Run as Administrator**:
```cmd
update_blackhole.bat
```
*Pulls malicious botnet/C2 IPs from `ips.txt`, collapses subnets via Radix trees, and injects Layer 3 null-routes straight into volatile kernel RAM in ~5 seconds.*

#### 5. Arm Automatic Startup
Double-click:
```cmd
install_tasks.bat
```
Registers two native Windows Scheduled Tasks:
- **`Kernel_Blackhole_Engine`**: Runs on Windows boot (`-AtStartup`) + every 3 days under `SYSTEM` (re-injects RAM blackhole table).
- **`YogaDNS_Sinkhole_Update`**: Runs every Sunday at 02:00 to refresh domain blocklists and hot-reload YogaDNS.

*(To uninstall scheduled tasks at any time, run `uninstall_tasks.bat`).*

---

### How to Test

1. **Verify WireGuard Failover**:
   - Disconnect WireGuard. Check YogaDNS log at the bottom of the window $\to$ queries map to **Rule 03 (Cloudflare DoH)**.
   - Connect WireGuard $\to$ queries immediately map to **Rule 02 (Corporate-Pool)**.
2. **Verify Kernel RAM Blackhole**:
   - Run in terminal:
     ```cmd
     netsh interface ipv4 show route | findstr "9999"
     ```
   - Shows thousands of malicious CIDRs null-routed to Loopback with Metric 9999.

---

### Technical Invariants

1. **Keep Corporate DNS on Plain UDP**: Never enable TCP or DNSSEC for internal corporate pools. Internal DNS servers often reject TCP fallback or lack external DNSSEC chains, leading to heavy timeout penalties.
2. **Immutable Whitelist Guard**: `optimized_ingestion.py` hardcodes an immutable whitelist (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, etc.) so contaminated threat lists never null-route upstream DNS resolvers.

---

### License
MIT. Do the needful and deploy responsibly.
