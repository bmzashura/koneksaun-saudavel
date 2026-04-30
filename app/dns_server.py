#!/usr/bin/env python3
"""DNS Server - Koneksaun Saudavel
Listens on 0.0.0.0:53, blocks domains via configurable blocklists."""

import socket
import sqlite3
import struct
import random
import logging
import signal
import sys
import os
from pathlib import Path
from datetime import datetime

# Setup logging
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [DNS] %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "dns.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Config
DNS_PORT = 53
BLOCKLIST_DIR = Path(__file__).parent.parent / "db" / "blocklists"
PID_FILE = Path("/opt/ks/koneksaun-saudavel/dns.pid")

_blocklists = {
    'ads': set(),
    'porn': set(),
    'gambling': set(),
    'other': set()
}

_blocklist_globs = {
    'ads': [],
    'porn': [],
    'gambling': []
}

_stats = {
    'total': 0,
    'blocked': 0,
    'forwarded': 0
}


def load_blocklists():
    """Load all blocklist files into memory."""
    for category in _blocklists.keys():
        _blocklists[category].clear()
        filepath = BLOCKLIST_DIR / f"{category}.txt"
        if filepath.exists():
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip().lower()
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    # Handle hosts file format: 0.0.0.0 domain.com
                    if '0.0.0.0' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            domain = parts[1]
                        else:
                            continue
                    else:
                        domain = line
                    # Clean domain
                    domain = domain.rstrip('.')
                    if domain and '.' in domain:  # Must be a valid domain
                        _blocklists[category].add(domain)
            logger.info(f"Loaded {category}: {len(_blocklists[category])} domains")
        else:
            logger.warning(f"Blocklist not found: {filepath}")


def reload_blocklists():
    """Reload blocklists (can be called from signal handler)."""
    logger.info("Reloading blocklists...")
    load_blocklists()
    logger.info(f"Blocklists reloaded: ads={len(_blocklists['ads'])}, porn={len(_blocklists['porn'])}, gambling={len(_blocklists['gambling'])}, other={len(_blocklists['other'])}")


def is_domain_blocked(domain: str) -> tuple[bool, str]:
    """Check if domain is blocked. Returns (blocked, category)."""
    domain_lower = domain.lower().rstrip('.')

    # Exact match
    for category, domains in _blocklists.items():
        if domain_lower in domains:
            return True, category

    # Subdomain check
    parts = domain_lower.split('.')
    for i in range(1, len(parts)):
        suffix = '.'.join(parts[i:])
        for category, domains in _blocklists.items():
            if suffix in domains:
                return True, category

    return False, ""


def parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse DNS name from packet data at given offset."""
    name = []
    jumped = False
    jumps = 0
    pos = offset

    while True:
        if pos >= len(data):
            return '', offset

        label_len = data[pos]

        if label_len == 0:
            if not jumped:
                pos += 1
            return '.'.join(name), pos

        if label_len >= 0xc0:
            if not jumped:
                jumped = True
                offset = pos + 2
            new_pos = ((label_len & 0x3f) << 8) | data[pos + 1]
            pos = new_pos
            jumps += 1
            if jumps > 16:
                return '', offset
            continue

        name.append(data[pos + 1:pos + 1 + label_len].decode('ascii', errors='ignore'))
        pos += label_len + 1

        if not jumped:
            offset = pos


def build_dns_response(query_data: bytes, nxdomain: bool = False) -> bytes:
    """Build DNS response from query."""
    if len(query_data) < 12:
        return b''

    # Copy transaction ID
    txn_id = query_data[0:2]

    # Flags: Response with RCODE set appropriately
    if nxdomain:
        flags = struct.pack('!H', 0x8183)  # Response, NXDOMAIN
    else:
        flags = struct.pack('!H', 0x8180)  # Response, no error

    # Question count = 1, Answer/Authority/Additional = 0
    question = query_data[12:]
    question_len = len(question)

    # Build response: header (12) + question + authority section
    response = txn_id + flags + b'\x00\x01' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00' + question

    return response


def send_nxdomain(query_data: bytes) -> bytes:
    """Send NXDOMAIN response for blocked domain."""
    return build_dns_response(query_data, nxdomain=True)


def forward_to_upstream(query_data: bytes) -> tuple[bytes, str]:
    """Forward DNS query to upstream DNS and return response."""
    upstream = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
    upstream_ip = random.choice(upstream)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(query_data, (upstream_ip, 53))
        data, _ = sock.recvfrom(512)
        sock.close()
        return data, upstream_ip
    except Exception as e:
        logger.warning(f"Upstream {upstream_ip} failed: {e}")
        return b'', upstream_ip


def handle_dns_query(query_data: bytes, client_addr: tuple) -> bytes:
    """Handle incoming DNS query."""
    global _stats

    if len(query_data) < 12:
        return b''

    txn_id = struct.unpack('!H', query_data[0:2])[0]

    try:
        domain, _ = parse_dns_name(query_data, 12)
    except Exception:
        domain = ''

    _stats['total'] += 1

    if domain:
        blocked, category = is_domain_blocked(domain)
        if blocked:
            _stats['blocked'] += 1
            logger.info(f"BLOCKED [{category}] {domain} from {client_addr[0]}")
            log_query(domain, True, category, client_addr[0])
            return send_nxdomain(query_data)

    log_query(domain, False, '', client_addr[0])

    _stats['forwarded'] += 1
    response, _ = forward_to_upstream(query_data)

    if not response:
        return send_nxdomain(query_data)

    return response


def log_query(domain: str, blocked: bool, category: str, client_ip: str):
    """Log DNS query to database."""
    try:
        db_path = Path(__file__).parent.parent / "db" / "koneksaun.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            INSERT INTO dns_logs (domain, blocked, category, client_ip)
            VALUES (?, ?, ?, ?)
        """, (domain, 1 if blocked else 0, category if blocked else None, client_ip))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.debug(f"Failed to log query: {e}")


def signal_handler(signum, frame):
    if signum == signal.SIGUSR1:
        logger.info("Received SIGUSR1 - reloading blocklists")
        reload_blocklists()
    elif signum in (signal.SIGTERM, signal.SIGINT):
        logger.info("DNS Server shutting down...")
        sys.exit(0)


def main():
    logger.info("Starting Koneksaun Saudavel DNS Server...")

    # Write PID file
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))

    # Load blocklists
    load_blocklists()

    logger.info(f"DNS listening on 0.0.0.0:{DNS_PORT}")
    logger.info(f"Blocklists: ads={len(_blocklists['ads'])}, porn={len(_blocklists['porn'])}, gambling={len(_blocklists['gambling'])}, other={len(_blocklists['other'])}")

    # Setup signals
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGUSR1, signal_handler)

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind(('0.0.0.0', DNS_PORT))
        logger.info(f"DNS Server ready on port {DNS_PORT}")

        while True:
            data, addr = sock.recvfrom(512)
            if data:
                try:
                    response = handle_dns_query(data, addr)
                    if response:
                        sock.sendto(response, addr)
                except Exception as e:
                    logger.error(f"Error handling query: {e}")
    except KeyboardInterrupt:
        logger.info("DNS Server stopped by user")
    finally:
        sock.close()
        if PID_FILE.exists():
            PID_FILE.unlink()


if __name__ == '__main__':
    main()