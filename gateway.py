#!/usr/bin/env python3
"""
Koneksaun Saudavel - Blocked Domain Gateway HTTP Server
Receives redirected DNS queries (A record -> 172.17.12.177) and
serves a blocked domain notification page.

Listens on port 80, extracts Host header, serves a static HTML page.
Falls back to a minimal page if the Flask app is unavailable.
"""

import http.server
import logging
from pathlib import Path

GATEWAY_IP = '0.0.0.0'
GATEWAY_PORT = 80

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [GATEWAY] %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "gateway.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


BLOCKED_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Terblokir — Koneksaun Saudavel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {{
            --primary: #1e3a8a;
            --accent: #3b82f6;
            --danger: #ef4444;
            --dark: #0f172a;
            --muted: #94a3b8;
        }}
        body {{
            background: linear-gradient(135deg, var(--dark) 0%, #1e293b 100%);
            min-height: 100vh;
            font-family: 'Segoe UI', system-ui, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .blocked-card {{
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
            padding: 3rem 2.5rem;
            max-width: 520px;
            width: 100%;
            backdrop-filter: blur(12px);
            text-align: center;
        }}
        .shield-icon {{ font-size: 4.5rem; color: var(--danger); margin-bottom: 1.5rem; }}
        .blocked-title {{ font-size: 2rem; font-weight: 700; color: #fff; margin-bottom: 0.5rem; }}
        .blocked-subtitle {{ color: var(--muted); font-size: 1rem; margin-bottom: 2rem; }}
        .domain-box {{
            background: rgba(239,68,68,0.1);
            border: 1px solid rgba(239,68,68,0.3);
            border-radius: 10px;
            padding: 0.75rem 1rem;
            margin-bottom: 1.5rem;
        }}
        .domain-label {{ font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.08em; color: rgba(239,68,68,0.7); margin-bottom: 4px; }}
        .domain-value {{ font-size: 1rem; font-weight: 600; color: #fff; word-break: break-all; }}
        .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 1.5rem; text-align: left; }}
        .info-item {{ background: rgba(255,255,255,0.04); border-radius: 10px; padding: 0.75rem 1rem; }}
        .info-label {{ font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); margin-bottom: 3px; }}
        .info-value {{ font-size: 0.9rem; font-weight: 600; color: #fff; }}
        .badge-category {{
            display: inline-block;
            padding: 4px 14px;
            border-radius: 20px;
            font-size: 0.78rem;
            font-weight: 600;
        }}
        .badge-ads {{ background: rgba(59,130,246,0.2); color: #60a5fa; border: 1px solid rgba(59,130,246,0.3); }}
        .badge-porn {{ background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid rgba(239,68,68,0.3); }}
        .badge-gambling {{ background: rgba(245,158,11,0.2); color: #fbbf24; border: 1px solid rgba(245,158,11,0.3); }}
        .badge-blocked {{ background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid rgba(239,68,68,0.3); }}
        .footer-note {{ margin-top: 2rem; font-size: 0.78rem; color: rgba(148,163,184,0.6); }}
        .footer-note a {{ color: var(--accent); text-decoration: none; }}
        .footer-note a:hover {{ text-decoration: underline; }}
        .btn-dashboard {{
            background: var(--accent); color: #fff; font-weight: 600;
            padding: 0.6rem 1.5rem; border-radius: 50px; text-decoration: none;
            display: inline-block; transition: all 0.2s; border: none;
        }}
        .btn-dashboard:hover {{ background: #2563eb; color: #fff; transform: translateY(-2px); }}
    </style>
</head>
<body>
    <div class="blocked-card">
        <div class="shield-icon"><i class="bi bi-shield-x"></i></div>
        <h1 class="blocked-title">Domain Terblokir</h1>
        <p class="blocked-subtitle">
            Domain yang Anda coba akses telah diblokir melalui jaringan ini.<br>
            Akses dibatasi untuk menjaga keamanan dan tanggung jawab internet.
        </p>
        <div class="domain-box">
            <div class="domain-label">Domain yang Diblokir</div>
            <div class="domain-value">{domain}</div>
        </div>
        <div class="info-grid">
            <div class="info-item">
                <div class="info-label">Kategori</div>
                <div class="info-value">
                    <span class="badge-category badge-{category}">{category_upper}</span>
                </div>
            </div>
            <div class="info-item">
                <div class="info-label">Waktu</div>
                <div class="info-value">{timestamp}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Status</div>
                <div class="info-value" style="color: #f87171;">DIBLOKIR</div>
            </div>
            <div class="info-item">
                <div class="info-label">Dilindungi Oleh</div>
                <div class="info-value">Koneksaun Saudavel</div>
            </div>
        </div>
        <a href="/" class="btn-dashboard">
            <i class="bi bi-house me-1"></i>Kembali ke Beranda
        </a>
        <div class="footer-note">
            Ingin mengajukan keberatan? Hubungi administrator jaringan.<br>
            <a href="/login">Login ke Dashboard</a> untuk detail lebih lanjut.
        </div>
    </div>
</body>
</html>
"""


class BlockedDomainHandler(http.server.BaseHTTPRequestHandler):
    """Handle HTTP requests for blocked domains."""

    def log_message(self, format, *args):
        """Suppress default stderr logging."""
        pass

    def do_GET(self):
        """Serve blocked domain notification page."""
        host = self.headers.get('Host', '')
        if not host:
            self.send_error(400, "Missing Host header")
            return

        domain = host.split(':')[0]
        timestamp = self.headers.get('X-Block-Timestamp', '')
        category = self.headers.get('X-Block-Category', 'blocked')

        if not timestamp:
            from datetime import datetime
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        logger.info(f"Blocked domain request: {domain} (category: {category})")

        page = BLOCKED_PAGE.format(
            domain=domain,
            category=category,
            category_upper=category.upper(),
            timestamp=timestamp
        )
        body = page.encode('utf-8')

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.send_header('X-Blocked-Domain', domain)
        self.send_header('X-Block-Category', category)
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        """Handle HEAD requests."""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()


def main():
    logger.info(f"Starting Blocked Domain Gateway on {GATEWAY_IP}:{GATEWAY_PORT}...")
    try:
        server = http.server.HTTPServer((GATEWAY_IP, GATEWAY_PORT), BlockedDomainHandler)
        logger.info(f"Gateway listening on {GATEWAY_IP}:{GATEWAY_PORT}")
        server.serve_forever()
    except PermissionError:
        logger.error(f"Need root to bind port {GATEWAY_PORT}")
        raise SystemExit(1)
    except KeyboardInterrupt:
        logger.info("Gateway shutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
