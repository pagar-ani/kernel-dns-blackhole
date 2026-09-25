import urllib.request
import concurrent.futures
import time
import os
import subprocess
import shutil
import logging
from logging.handlers import RotatingFileHandler

# Enterprise Observability: 5MB max size, 3 rolling backups
base_dir = os.path.dirname(os.path.abspath(__file__))
log_file = os.path.join(base_dir, 'optimizer.log')

handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger = logging.getLogger('SinkholeOptimizer')
logger.setLevel(logging.INFO)
logger.addHandler(handler)

def process_url(url):
    domains = set()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 Windows NT 10.0'})
        with urllib.request.urlopen(req, timeout=30) as response:
            text = response.read().decode('utf-8', errors='ignore')
            for line in text.splitlines():
                line = line.split('#')[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1'):
                    domain = parts[1]
                elif len(parts) == 1:
                    domain = parts[0]
                else:
                    domain = parts[-1]
                
                domain = domain.lower()
                if domain in ('localhost', 'localhost.localdomain', 'broadcasthost', 'local', '0.0.0.0', '127.0.0.1', 'ip6-localhost', 'ip6-loopback') or ':' in domain: 
                    continue
                domains.add(domain)
    except Exception as e:
        logger.error(f"Failed {url}: {e}")
    return domains

def main():
    start_time = time.time()
    logger.info("--- Automated Sinkhole Optimization Cycle Initiated ---")
    
    lst_path = os.path.join(base_dir, 'lst.txt')
    primary_out = os.path.join(base_dir, 'optimized_hosts.txt')
    
    try:
        with open(lst_path) as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        logger.critical(f"Failed to access source list directory: {e}")
        return
    
    all_domains = set()
    logger.info(f"Fetching and parsing {len(urls)} target lists via ThreadPool...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        for res in executor.map(process_url, urls):
            all_domains.update(res)
            
    logger.info(f"Total unique domains deduplicated: {len(all_domains)}")
    
    try:
        with open(primary_out, 'w', encoding='ascii', errors='ignore') as f:
            f.write("# Optimized Windows Hosts File\n")
            f.write("127.0.0.1 localhost\n")
            f.write("::1 localhost\n\n")
            
            # DNS scaling optimization: chunk 9 domains per line to avoid resolver bottlenecks
            domains_list = sorted(list(all_domains))
            for i in range(0, len(domains_list), 9):
                chunk = domains_list[i:i+9]
                f.write("0.0.0.0 " + " ".join(chunk) + "\n")
    except Exception as e:
        logger.critical(f"Failed to compile primary output matrix: {e}")
        return
            
    end_time = time.time()
    logger.info(f"Optimization compiled in {end_time - start_time:.2f} seconds.")

    # YogaDNS AppData Sync Matrix
    appdata_dir = os.path.join(os.environ.get('APPDATA', ''), 'YogaDNS')
    if os.path.exists(appdata_dir):
        appdata_out = os.path.join(appdata_dir, 'optimized_hosts.txt')
        try:
            shutil.copy2(primary_out, appdata_out)
            logger.info("Threat list successfully propagated to YogaDNS AppData physical cache.")
        except Exception as e:
            logger.error(f"Failed to propagate YogaDNS hosts cache: {e}")
    else:
        logger.warning(f"YogaDNS AppData directory not found. Expected: {appdata_dir}")

    logger.info("--- Automated Cycle Completed Successfully ---")

if __name__ == '__main__':
    main()
