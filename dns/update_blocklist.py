#!/usr/bin/env python3
"""Blocklist updater for Koneksaun Saudavel DNS server"""

import os
import urllib.request
import ssl
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BLOCKLIST_DIR = "/app/blocklists"
BLOCKLIST_URLS = {
    "ads": "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
    "porn": "https://github.com/blocklistproject/Lists/raw/master/lists/porn-all.txt",
    "gamble": "https://github.com/blocklistproject/Lists/raw/master/lists/gambling-all.txt",
}


def download_blocklist(url, category):
    """Download blocklist and save to disk"""
    filepath = os.path.join(BLOCKLIST_DIR, f"{category}.txt")
    
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=60, context=ctx) as response:
            content = response.read().decode("utf-8", errors="ignore")
        
        with open(filepath, "w") as f:
            f.write(content)
        
        lines = len([l for l in content.splitlines() if l.strip() and not l.startswith("#")])
        logger.info(f"Downloaded {category}: {lines} entries")
        return True
    except Exception as e:
        logger.error(f"Failed to download {category}: {e}")
        # If file exists, keep old version
        if os.path.exists(filepath):
            logger.info(f"Keeping existing {category} blocklist")
            return True
        return False


def update_all():
    """Download all blocklists"""
    os.makedirs(BLOCKLIST_DIR, exist_ok=True)
    logger.info("Starting blocklist update...")
    
    success = 0
    for category, url in BLOCKLIST_URLS.items():
        if download_blocklist(url, category):
            success += 1
    
    logger.info(f"Blocklist update complete: {success}/{len(BLOCKLIST_URLS)} successful")


if __name__ == "__main__":
    update_all()
