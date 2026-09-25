# Enterprise Endpoint Security Architecture: Zero-Trust Nomadic Profile

> [!IMPORTANT]  
> This architecture overrides standard OS DNS handling. Do not alter routing tables or proxy logic gates without understanding the Layer 3 / Layer 7 split described below.

---

## 1. Overview & Problem Formulation

Deploying flat threat-block lists directly into the Windows DNS Client (`svchost.exe / dnscache`) via legacy `hosts` files causes:
1. **CPU Saturation**: Windows DNS Client is single-threaded when parsing multi-megabyte `hosts` files; 90+ MB lists cause permanent 100% CPU lockups.
2. **DNS Leakage across Interfaces**: Multi-homed Windows endpoints with WireGuard (`Wintun`) interfaces leak corporate DNS requests across public physical Wi-Fi/Ethernet adapters via Windows Smart Multi-Homed Name Resolution.
3. **WFP Bypass**: Third-party application firewalls (Simplewall, Windows Firewall) can be bypassed by driver priority conflicts or application-level socket hooks.

This ecosystem resolves these issues using a two-tier hybrid defense:
- **Tier 1 (Layer 3) - Windows Kernel RAM Blackhole (`TCPIP.sys`)**: Outbound malicious IP null-routing directly inside the Windows kernel network stack via `store=active` volatile RAM routing (zero disk writes, zero registry bloat).
- **Tier 2 (Layer 7) - Stateful Domain Interceptor (YogaDNS Basic)**: Stateful conditional routing that binds to `Wintun` NDIS states and sinkholes 3.6M domains via `optimized_hosts.txt` using 9-domain chunking.

---

## 2. Threat Deduplication & DNS Scaling Engine (`optimizer.py`)

Standard Windows DNS resolvers bottleneck when reading flat domain lists. We deploy a concurrent Python engine to ingest, deduplicate, and compress 16 discrete threat lists (`lst.txt`).

- **ThreadPool Concurrency**: Asynchronously streams feeds and extracts domains into memory.
- **$O(1)$ Hash Set Deduplication**: Deduplicates ~3.6 million domains down to unique records.
- **The 9-Domain-Per-Line DNS Scaling Trick**:
  Standard DNS client implementations support up to 9 domain aliases mapped to a single IP per line:
  ```text
  0.0.0.0 d1.com d2.com d3.com d4.com d5.com d6.com d7.com d8.com d9.com
  ```
  This reduces file size by **~90%**, shrinking a 90MB flat file down to ~3.6MB, enabling instantaneous memory parsing by resolvers.
- **Zero-Downtime Hot Reload**:
  The script propagates `optimized_hosts.txt` to `%APPDATA%\YogaDNS\` and invokes `YogaDNS.exe -reload`. The proxy engine re-reads the payload into memory with zero packet drops.

---

## 3. Stateful Dual-DNS Routing Engine (YogaDNS Configuration)

YogaDNS enforces strict top-to-bottom rule execution. Open-source resolvers (`Acrylic`, `DNSCrypt`) fail in this role because they cannot monitor dynamic NDIS interface registration events from transient `Wintun` drivers.

### The Master Switch: `ignore_rule_if_interface_down="1"`
This attribute in `Configuration.xml` controls the conditional failover:
- When a rule is bound to an interface name (`interface_id_type="name"`), YogaDNS continuously queries the OS NDIS adapter table.
- If the interface is disconnected, YogaDNS **bypasses the rule entirely** and falls through to the next gate.

### Logic Gate Hierarchy:

```
[Incoming DNS Query from Application]
                  │
                  ▼
┌────────────────────────────────────────────────────────┐
│ Tier 01: The Sinkhole (optimized_hosts.txt)            │
│ Is domain in 3.6M blocklist?                           │
└────────────────────────────────────────────────────────┘
         │ YES                           │ NO
         ▼                               ▼
   [Drop to 0.0.0.0]    ┌────────────────────────────────────────────────┐
                        │ Tier 02: NDIS WireGuard Hook                   │
                        │ Is WireGuard Interface UP?                     │
                        └────────────────────────────────────────────────┘
                                 │ YES                           │ NO (Interface Down)
                                 ▼                               ▼
                        [Corporate-Pool]                ┌────────────────────────────────┐
                        (Internal Plain UDP)            │ Tier 03: Public Failover       │
                        (No DNS leak outside tunnel)    │ Cloudflare Security DoH        │
                                                        └────────────────────────────────┘
```

### Server Pool Definitions:
1. **Corporate-Pool**:
   - `<YOUR_CORPORATE_DNS_IPV4>` (Plain UDP) / `<YOUR_CORPORATE_DNS_IPV6>` (Plain UDP).
   - > [!WARNING]  
     > **Never enable TCP or DNSSEC for internal corporate pools**. It introduces heavy RTT handshake penalties and triggers trust-chain validation failures on internal split-horizon zones.
2. **Public-Pool**:
   - Cloudflare Security DoH (`1.0.0.2` & `2606:4700:4700::1112` via `/dns-query`).
   - Upstream malware/phishing drops with DNS-over-HTTPS encryption over public Wi-Fi.

---

## 4. Layer 3 Kernel Blackhole (`TCPIP.sys` Null-Routing)

To eliminate dependency on software application firewalls, high-confidence malicious botnet/C2 IPs (`ips.txt`) are null-routed directly into the Windows TCP/IP driver.

### Mechanistic Innovations:
1. **Immutable Whitelist Guard**:
   Threat feeds frequently get poisoned or inadvertently list public root DNS infrastructure. An immutable hardcoded whitelist (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, etc.) checks all candidate subnets via `ipaddress.overlaps()` before compilation.
2. **Radix Tree Subnet Collapse**:
   Uses `ipaddress.collapse_addresses()` to merge overlapping single IPs and ranges into contiguous CIDR blocks, minimizing kernel route table size.
3. **Bypassing WMI / PowerShell Memory Exhaustion**:
   Previous approaches using `Remove-NetRoute` for 65,000 routes exhaust WMI/CLR memory and freeze the OS for 3+ minutes.
   `deploy_blackhole.ps1` parses `netsh interface ipv4 show route` text output with Metric `9999`, generates flat `v4_clean.netsh` scripts, and tears down stale routes in <2 seconds.
4. **Bypassing Windows "Registry I/O Death" (`store=active` in RAM)**:
   Standard persistent route injection writes to `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes`. Writing 65,000 keys sequentially causes massive disk I/O lockups lasting 30+ minutes.
   Adding `store=active` writes routes directly to volatile kernel RAM in **~5 seconds** with **zero disk writes**.
5. **Reboot Persistence via Task Scheduler**:
   Because `store=active` routes are cleared on reboot, the `Kernel_Blackhole_Engine` task runs `-AtStartup` under `NT AUTHORITY\SYSTEM` to rebuild the RAM routing table before user login completes.
