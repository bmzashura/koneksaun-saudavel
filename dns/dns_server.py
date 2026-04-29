#!/usr/bin/env python3
"""DNS server for Koneksaun Saudavel - blocks ads, porn, gambling"""

import socket
import threading
import time
import os
import logging
from datetime import datetime

# Blocklist storage: {(domain, category): blocked}
blocklist = {}  # {(domain, category): blocked}
blocklist_urls = {
    "ads": os.environ.get("BLOCKLIST_ADS_URL", "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt"),
    "porn": os.environ.get("BLOCKLIST_PORN_URL", "https://github.com/blocklistproject/Lists/raw/master/lists/porn-all.txt"),
    "gamble": os.environ.get("BLOCKLIST_GAMBLE_URL", "https://github.com/blocklistproject/Lists/raw/master/lists/gambling-all.txt"),
}
BLOCKLIST_DIR = "/app/blocklists"
DNS_PORT = 53
UPSTREAM_DNS = ["1.1.1.1", "8.8.8.8"]  # Cloudflare, Google

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("/app/logs/dns.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def load_blocklist():
    """Load blocklists from disk"""
    global blocklist
    blocklist = {}
    
    for category in ["ads", "porn", "gamble"]:
        filepath = os.path.join(BLOCKLIST_DIR, f"{category}.txt")
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Handle hosts file format (127.0.0.1 domain.com)
                        parts = line.split()
                        domain = parts[-1] if parts else line
                        domain = domain.lower()
                        if domain:
                            blocklist[(domain, category)] = True
                            # Also block subdomains
                            blocklist[(f"*.{domain}", category)] = True
    
    logger.info(f"Blocklist loaded: {len(blocklist)} entries")


def download_blocklist(url, category):
    """Download a single blocklist"""
    import urllib.request
    import ssl
    
    filepath = os.path.join(BLOCKLIST_DIR, f"{category}.txt")
    
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
            content = response.read().decode("utf-8", errors="ignore")
        
        with open(filepath, "w") as f:
            f.write(content)
        
        logger.info(f"Downloaded {category} blocklist: {len(content.splitlines())} lines")
        return True
    except Exception as e:
        logger.warning(f"Failed to download {category} blocklist: {e}")
        return False


def update_blocklists():
    """Update all blocklists"""
    logger.info("Updating blocklists...")
    for category, url in blocklist_urls.items():
        download_blocklist(url, category)
    load_blocklist()


def resolve_domain(data, upstream):
    """Forward raw DNS query to upstream and return response"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(data, (upstream, 53))
        result, _ = sock.recvfrom(512)
        sock.close()
        return result
    except Exception as e:
        logger.debug(f"Upstream {upstream} failed: {e}")
        return None


def handle_query(data, addr, sock):
    """Handle a DNS query"""
    try:
        # Parse DNS header
        if len(data) < 12:
            return
        
        # Extract domain name from DNS query
        domain = b""
        pos = 12
        while pos < len(data):
            length = data[pos]
            if length == 0:
                pos += 1
                break
            if length >= 192:  # Compression pointer
                break
            domain += data[pos+1:pos+1+length] + b"."
            pos += 1 + length
        
        domain = domain.decode("utf-8", errors="ignore").lower().rstrip(".")
        
        if not domain:
            return
        
        # Normalize: remove trailing dot
        normalized_domain = domain.rstrip(".")
        
        # Log the query (privacy-first: no IP stored)
        log_entry = f"{datetime.now().isoformat()} - {normalized_domain}"
        
        # Check blocklist
        blocked = False
        blocked_category = None
        
        # Direct match
        if (normalized_domain, "*") in blocklist or normalized_domain in [k[0] for k in blocklist if k[1] == "*"]:
            blocked = True
        else:
            # Check each category
            for category in ["ads", "porn", "gamble"]:
                if (normalized_domain, category) in blocklist:
                    blocked = True
                    blocked_category = category
                    break
                # Check subdomain
                for k, v in blocklist.items():
                    if k[0].startswith("*.") and normalized_domain.endswith(k[0][2:]):
                        blocked = True
                        blocked_category = category
                        break
        
        if blocked:
            logger.info(f"BLOCKED [{blocked_category}]: {normalized_domain}")
            # Build proper NXDOMAIN response
            import struct
            # Extract QTYPE/QCLASS from query
            qtype = struct.unpack('!H', data[pos:pos+2])[0]
            qclass = struct.unpack('!H', data[pos+2:pos+4])[0]
            # NXDOMAIN flags: QR=1, AA=1, RD=1, RA=1, RCODE=3
            nxdomain = (
                data[:2] +  # Transaction ID
                struct.pack('!H', 0x8183) +  # Flags
                struct.pack('!HHHH', 1, 0, 0, 0) +  # Header
                data[12:pos+4]  # Question section
            )
            sock.sendto(nxdomain, addr)
        else:
            # Forward to upstream
            for upstream in UPSTREAM_DNS:
                result = resolve_domain(data, upstream)
                if result:
                    # Forward raw upstream response back to client, preserving original transaction ID
                    response = data[:2] + result[2:]
                    sock.sendto(response, addr)
                    logger.debug(f"FORWARDED: {normalized_domain} -> {upstream}")
                    break
    
    except Exception as e:
        logger.error(f"Query error: {e}")


def run():
    """Run DNS server"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", DNS_PORT))
    
    logger.info(f"Koneksaun Saudavel DNS server running on 0.0.0.0:{DNS_PORT}")
    
    # Initial blocklist load
    if not blocklist:
        update_blocklists()
    
    while True:
        try:
            data, addr = sock.recvfrom(512)
            thread = threading.Thread(target=handle_query, args=(data, addr, sock))
            thread.daemon = True
            thread.start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error(f"Server error: {e}")


if __name__ == "__main__":
    run()
