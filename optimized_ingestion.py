import ssl
import json
import ipaddress
import urllib.request
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

base_dir = os.path.dirname(os.path.abspath(__file__))

def resolve_github_tree(repo_tree_url):
    """Dynamically traverses a GitHub tree structure to extract direct download URIs."""
    api_url = repo_tree_url.replace("github.com", "api.github.com/repos").replace("/tree/master/", "/contents/")
    cache_path = os.path.join(base_dir, "github_tree_cache.json")
    
    local_cache = {}
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r') as f:
                local_cache = json.load(f)
        except Exception:
            pass

    try:
        req = urllib.request.Request(api_url, headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/vnd.github.v3+json'})
        token = os.environ.get('GITHUB_TOKEN')
        if token:
            req.add_header('Authorization', f'token {token}')
            
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            
            local_cache[api_url] = data
            with open(cache_path, 'w') as f:
                json.dump(local_cache, f)
                
            return [file['download_url'] for file in data if file['type'] == 'file' and not file['name'].endswith(('.csv', '.md'))]
            
    except urllib.error.HTTPError as e:
        if e.code in [403, 429] and api_url in local_cache:
            print(f"[*] API Rate Limit Hit ({e.code}). Reconstructing '{repo_tree_url}' from local Fallback Cache.")
            data = local_cache[api_url]
            return [file['download_url'] for file in data if file['type'] == 'file' and not file['name'].endswith(('.csv', '.md'))]
        print(f"[!] GitHub Tree HTTP error: {e}")
        return []
    except Exception as e:
        print(f"[!] GitHub Tree resolution error: {e}")
        return []

def fetch_feed(url):
    """Executes asynchronous extraction of raw IP telemetry."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            return resp.read().decode('utf-8', errors='ignore').splitlines()
    except Exception as e:
        print(f"[!] Target feed {url} dropped: {e}")
        return []

def execute_radix_optimization():
    print("[*] Stage 1/3: Asynchronous Ingestion & Feed Resolution Initiated...")
    ips_path = os.path.join(base_dir, 'ips.txt')
    if not os.path.exists(ips_path):
        print(f"[!] Feed targets missing: {ips_path}")
        return

    with open(ips_path, 'r') as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    urls = []
    for tgt in targets:
        if 'github.com' in tgt and '/tree/' in tgt:
            urls.extend(resolve_github_tree(tgt))
        else:
            urls.append(tgt)

    raw_data = set()
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_map = {executor.submit(fetch_feed, u): u for u in urls}
        for future in as_completed(future_map):
            raw_data.update(future.result())

    print("[*] Stage 2/3: Sanitization & Network Boundary Parsing...")
    
    # CRITICAL SECURITY SAFEGUARD: IMMUTABLE WHITELIST
    # Forbids the engine from ever null-routing upstream DNS infrastructure.
    critical_whitelist = {
        ipaddress.ip_network("1.1.1.1/32"),        # Cloudflare Primary
        ipaddress.ip_network("1.0.0.1/32"),        # Cloudflare Secondary
        ipaddress.ip_network("1.1.1.2/32"),        # Cloudflare Security Primary
        ipaddress.ip_network("1.0.0.2/32"),        # Cloudflare Security Secondary
        ipaddress.ip_network("8.8.8.8/32"),        # Google Primary
        ipaddress.ip_network("8.8.4.4/32"),        # Google Secondary
        ipaddress.ip_network("9.9.9.9/32"),        # Quad9 Primary
        ipaddress.ip_network("149.112.112.112/32") # Quad9 Secondary
    }

    networks = set()
    for line in raw_data:
        clean_entry = line.split('#')[0].strip()
        if not clean_entry:
            continue
        try:
            net = ipaddress.ip_network(clean_entry, strict=False)
            
            # Global routing strictness: ignore private/multicast addresses
            if not net.is_global:
                continue

            if net.version == 6 and net.network_address.ipv4_mapped:
                net = ipaddress.ip_network(f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}", strict=False)
                
            # Threat Integration Safeguard: Subnet Override
            if any(net.overlaps(allow) for allow in critical_whitelist):
                print(f"[!] Whitelist override activated. Stripping critical DNS collision: {net}")
                continue

            networks.add(net)
        except ValueError:
            pass

    print(f"[*] Pre-Collapse Memory Footprint: {len(networks)} rules.")

    print("[*] Stage 3/3: Radix Tree Matrix Collapse Computation...")
    ipv4_nets = [n for n in networks if n.version == 4]
    ipv6_nets = [n for n in networks if n.version == 6]
    optimized_subnets = list(ipaddress.collapse_addresses(ipv4_nets)) + list(ipaddress.collapse_addresses(ipv6_nets))
    print(f"[*] Post-Collapse Operational Matrix: {len(optimized_subnets)} bounds deployed.")

    output_path = os.path.join(base_dir, 'optimized_rules_merged.txt')
    with open(output_path, 'w') as f:
        for net in optimized_subnets:
            f.write(f"{net}\n")
    print(f"[+] Architecture deployment complete. Matrix compiled at {output_path}.")

if __name__ == '__main__':
    execute_radix_optimization()
