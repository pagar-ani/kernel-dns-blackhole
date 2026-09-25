#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hyper-Optimized L3 Radix Tree IP Ingestion Engine
Profiled for minimal memory overhead, zero SSL handshaking lag,
and deterministic subnet aggregation via CIDR supernet folding.
"""

import os
import ssl
import json
import ipaddress
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# CRITICAL IMMUTABLE WHITELIST: Upstream DNS Resolvers
# Prevent null-routing legitimate recursive resolvers under any condition
CRITICAL_WHITELIST = {
    ipaddress.ip_network("1.1.1.1/32"),        # Cloudflare Primary
    ipaddress.ip_network("1.0.0.1/32"),        # Cloudflare Secondary
    ipaddress.ip_network("1.1.1.2/32"),        # Cloudflare Security Primary
    ipaddress.ip_network("1.0.0.2/32"),        # Cloudflare Security Secondary
    ipaddress.ip_network("8.8.8.8/32"),        # Google Primary
    ipaddress.ip_network("8.8.4.4/32"),        # Google Secondary
    ipaddress.ip_network("9.9.9.9/32"),        # Quad9 Primary
    ipaddress.ip_network("149.112.112.112/32") # Quad9 Secondary
}

def resolve_github_tree(repo_tree_url):
    """Dynamically traverses GitHub tree to resolve direct download URIs."""
    api_url = repo_tree_url.replace("github.com", "api.github.com/repos").replace("/tree/master/", "/contents/")
    cache_path = os.path.join(BASE_DIR, "github_tree_cache.json")
    
    local_cache = {}
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                local_cache = json.load(f)
        except Exception:
            pass

    try:
        req = urllib.request.Request(
            api_url,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'Accept': 'application/vnd.github.v3+json'
            }
        )
        token = os.environ.get('GITHUB_TOKEN')
        if token:
            req.add_header('Authorization', f'token {token}')
            
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            local_cache[api_url] = data
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(local_cache, f)
            return [file['download_url'] for file in data if file.get('type') == 'file' and not file['name'].endswith(('.csv', '.md'))]
    except urllib.error.HTTPError as e:
        if e.code in (403, 429) and api_url in local_cache:
            data = local_cache[api_url]
            return [file['download_url'] for file in data if file.get('type') == 'file' and not file['name'].endswith(('.csv', '.md'))]
        return []
    except Exception:
        return []

def fetch_feed_stream(url):
    """Streams and parses IP entries line-by-line directly from socket."""
    lines = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            for raw in resp:
                raw = raw.strip()
                if not raw or raw[0] == 35: # ASCII '#'
                    continue
                if b'#' in raw:
                    raw = raw.split(b'#', 1)[0].rstrip()
                clean = raw.decode('ascii', errors='ignore').strip()
                if clean:
                    # If line has multiple columns (e.g., ipsum tab-separated count), grab first token
                    clean = clean.split()[0]
                    lines.append(clean)
    except Exception as exc:
        print(f"[!] Feed failed ({url}): {exc}")
    return lines

def execute_radix_optimization():
    print("[*] Stage 1/3: Ingestion & Live Target Resolution...")
    ips_file = os.path.join(BASE_DIR, 'ips.txt')
    if not os.path.exists(ips_file):
        print(f"[!] ips.txt missing: {ips_file}")
        return

    with open(ips_file, 'r', encoding='utf-8') as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    urls = []
    for tgt in targets:
        if 'github.com' in tgt and '/tree/' in tgt:
            urls.extend(resolve_github_tree(tgt))
        else:
            urls.append(tgt)

    raw_entries = set()
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(fetch_feed_stream, u): u for u in urls}
        for fut in as_completed(futures):
            raw_entries.update(fut.result())

    print(f"[*] Stage 2/3: Parsing & Collapsing {len(raw_entries)} raw entries...")
    v4_networks = []
    v6_networks = []

    for entry in raw_entries:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            if not net.is_global:
                continue
            if net.version == 6 and net.network_address.ipv4_mapped:
                net = ipaddress.ip_network(f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}", strict=False)
            
            # Whitelist guard
            if any(net.overlaps(safe) for safe in CRITICAL_WHITELIST):
                continue

            if net.version == 4:
                v4_networks.append(net)
            else:
                v6_networks.append(net)
        except ValueError:
            continue

    del raw_entries

    print(f"[*] Stage 3/3: Supernet Radix Tree Collapse (IPv4: {len(v4_networks)}, IPv6: {len(v6_networks)})...")
    collapsed_v4 = list(ipaddress.collapse_addresses(v4_networks))
    collapsed_v6 = list(ipaddress.collapse_addresses(v6_networks))
    total_rules = len(collapsed_v4) + len(collapsed_v6)
    print(f"[+] Total Radix-Collapsed Bounds: {total_rules} rules (IPv4: {len(collapsed_v4)}, IPv6: {len(collapsed_v6)})")

    out_file = os.path.join(BASE_DIR, 'optimized_rules_merged.txt')
    with open(out_file, 'w', encoding='ascii', buffering=65536) as f:
        for net in collapsed_v4:
            f.write(f"{net}\n")
        for net in collapsed_v6:
            f.write(f"{net}\n")

    print(f"[+] Compiled active bounds table: {out_file}")

if __name__ == '__main__':
    execute_radix_optimization()
