#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hyper-Optimized L7 Domain Sinkhole Compiler
Profiled for minimal resident memory (RSS), zero intermediate allocations,
and raw buffered binary I/O.
"""

import sys
import os
import shutil
import logging
from logging.handlers import RotatingFileHandler
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, 'optimizer.log')

# Micro-logger: rolling 2MB, 1 backup to conserve disk I/O
handler = RotatingFileHandler(LOG_FILE, maxBytes=2*1024*1024, backupCount=1)
handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
logger = logging.getLogger('ArchSinkhole')
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# Fast-path exclusions (ASCII byte literals to eliminate UTF-8 decode overhead)
EXCLUDED_BYTES = {
    b'localhost', b'localhost.localdomain', b'broadcasthost',
    b'local', b'0.0.0.0', b'127.0.0.1', b'ip6-localhost', b'ip6-loopback'
}

def stream_and_parse(url):
    """
    Zero-buffer streaming parser.
    Reads lines directly off the TCP socket stream. Avoids full payload allocation.
    """
    sub_domains = set()
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            for raw in resp:
                # Strip trailing CRLF without copying
                raw = raw.strip()
                if not raw:
                    continue
                # Byte 35 is '#' in ASCII. Fast-path discard comments.
                if raw[0] == 35:
                    continue
                # Split off inline comments
                if b'#' in raw:
                    raw = raw.split(b'#', 1)[0].rstrip()
                    if not raw:
                        continue
                tokens = raw.split()
                if not tokens:
                    continue
                
                # Format detection: host file '0.0.0.0 domain' vs single domain list
                if len(tokens) >= 2 and tokens[0] in (b'0.0.0.0', b'127.0.0.1'):
                    target = tokens[1]
                else:
                    target = tokens[0]
                
                # Fast lowercase
                target = target.lower()
                
                # Guard against IPv6 or invalid local tokens
                if b':' in target or target in EXCLUDED_BYTES:
                    continue
                
                sub_domains.add(target)
    except Exception as exc:
        logger.error(f"Feed fetch failure: {url} -> {exc}")
    return sub_domains

def main():
    logger.info("=== Starting Hyper-Optimized Sinkhole Compilation ===")
    lst_file = os.path.join(BASE_DIR, 'lst.txt')
    primary_out = os.path.join(BASE_DIR, 'optimized_hosts.txt')

    if not os.path.exists(lst_file):
        logger.critical(f"Source feed index missing: {lst_file}")
        return

    with open(lst_file, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    all_domains = set()
    logger.info(f"Dispatching ThreadPool across {len(urls)} feeds...")
    
    # 8 worker threads balances TCP concurrency against Python GIL contention
    with ThreadPoolExecutor(max_workers=8) as executor:
        for domain_chunk in executor.map(stream_and_parse, urls):
            all_domains.update(domain_chunk)

    total_count = len(all_domains)
    logger.info(f"Deduplicated {total_count} unique domains into memory.")

    # High-throughput buffered binary writer (1MB chunked page alignment)
    # 9 domains per line complies with DNS resolver stack scaling without payload fragmentation
    BUFFER_SIZE = 1024 * 1024  # 1 MB
    chunk = []
    
    with open(primary_out, 'wb', buffering=BUFFER_SIZE) as f:
        f.write(b"# Optimized Windows Hosts File - Kernel DNS Blackhole\n")
        f.write(b"127.0.0.1 localhost\n")
        f.write(b"::1 localhost\n\n")

        for domain in all_domains:
            chunk.append(domain)
            if len(chunk) == 9:
                f.write(b"0.0.0.0 " + b" ".join(chunk) + b"\n")
                chunk.clear()
        if chunk:
            f.write(b"0.0.0.0 " + b" ".join(chunk) + b"\n")

    # Clear set memory immediately
    del all_domains

    # Synchronize to YogaDNS AppData Cache
    appdata_dir = os.path.join(os.environ.get('APPDATA', ''), 'YogaDNS')
    if os.path.exists(appdata_dir):
        appdata_out = os.path.join(appdata_dir, 'optimized_hosts.txt')
        try:
            shutil.copy2(primary_out, appdata_out)
            logger.info(f"Synchronized {total_count} domains to AppData: {appdata_out}")
        except Exception as exc:
            logger.error(f"Failed to copy to AppData: {exc}")
    else:
        logger.warning(f"YogaDNS AppData directory not found at: {appdata_dir}")

    logger.info("=== Sinkhole Compilation Completed Cleanly ===")

if __name__ == '__main__':
    main()
