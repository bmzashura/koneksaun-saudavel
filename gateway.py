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
import urllib.parse
from pathlib import Path

try:
    from app.translations import TRANSLATIONS
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from app.translations import TRANSLATIONS

GATEWAY_IP = '0.0.0.0'
GATEWAY_PORT = 80

LOG_DIR = Path(__file__).resolve().parent / "logs"
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
<html lang="{lang}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
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
        <h1 class="blocked-title">{blocked_title}</h1>
        <p class="blocked-subtitle">
            {subtitle_1}<br>
            {subtitle_2}
        </p>
        <div class="domain-box">
            <div class="domain-label">{domain_label}</div>
            <div class="domain-value">{domain}</div>
        </div>
        <div class="info-grid">
            <div class="info-item">
                <div class="info-label">{category_label}</div>
                <div class="info-value">
                    <span class="badge-category badge-{category}">{category_name}</span>
                </div>
            </div>
            <div class="info-item">
                <div class="info-label">{time_label}</div>
                <div class="info-value">{timestamp}</div>
            </div>
            <div class="info-item">
                <div class="info-label">{status_label}</div>
                <div class="info-value" style="color: #f87171;">{status_value}</div>
            </div>
            <div class="info-item">
                <div class="info-label">{protected_label}</div>
                <div class="info-value">Koneksaun Saudavel</div>
            </div>
        </div>
        <a href="/" class="btn-dashboard">
            <i class="bi bi-house me-1"></i>{back_home}
        </a>
        <div class="footer-note">
            {footer_note}<br>
            <a href="/login">{login_link}</a> {login_detail}
        </div>
        <div style="margin-top:1.5rem;display:flex;justify-content:center;gap:15px;font-size:0.8rem;">
            <a href="?lang=tet" style="color:{tet_color};text-decoration:none;font-weight:{tet_weight};">Tetum</a> |
            <a href="?lang=id" style="color:{id_color};text-decoration:none;font-weight:{id_weight};">Bahasa Indonesia</a>
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

    def get_lang(self):
        """Resolve language preference (query > cookie > accept-language > default 'tet')."""
        query_lang = None
        if '?' in self.path:
            qs = urllib.parse.parse_qs(self.path.split('?', 1)[1])
            if 'lang' in qs and qs['lang'][0] in ('tet', 'id'):
                query_lang = qs['lang'][0]
        if query_lang:
            return query_lang, True

        cookie_str = self.headers.get('Cookie', '')
        for part in cookie_str.split(';'):
            part = part.strip()
            if part.startswith('ks_lang='):
                val = part.split('=', 1)[1].strip()
                if val in ('tet', 'id'):
                    return val, False

        accept = self.headers.get('Accept-Language', '').lower()
        if 'id' in accept and 'tet' not in accept:
            return 'id', False
        return 'tet', False

    def t(self, key, lang):
        table = TRANSLATIONS.get(lang) or {}
        if key in table:
            return table[key]
        return TRANSLATIONS.get('tet', {}).get(key, key)

    def do_GET(self):
        """Serve blocked domain notification page."""
        host = self.headers.get('Host', '')
        if not host:
            self.send_error(400, "Missing Host header")
            return

        domain = host.split(':')[0]
        timestamp = self.headers.get('X-Block-Timestamp', '')
        category = self.headers.get('X-Block-Category', 'blocked')
        lang, set_cookie = self.get_lang()

        if not timestamp:
            from datetime import datetime
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        logger.info(f"Blocked domain request: {domain} (category: {category}, lang: {lang})")

        cat_keys = {'ads': 'iklan_pelacak', 'porn': 'dewasa', 'gambling': 'judi', 'other': 'lainnya'}
        category_name = self.t(cat_keys.get(category, 'blokadu'), lang)

        page = BLOCKED_PAGE.format(
            lang=lang,
            title=self.t('domain_blocked_koneksaun_saudavel', lang),
            blocked_title=self.t('akses_diblokir', lang),
            subtitle_1=self.t('domain_yang_anda_coba_akses_telah_diblokir_di_jaringan_ini', lang),
            subtitle_2=self.t('akses_dibatasi_untuk_menjaga_keamanan_jaringan_dan_penggunaan_internet_yang_bertanggung_jawab', lang),
            domain_label=self.t('domain_terblokir', lang),
            domain=domain,
            category_label=self.t('kategori', lang),
            category=category,
            category_name=category_name,
            time_label=self.t('waktu', lang),
            timestamp=timestamp,
            status_label=self.t('status', lang),
            status_value=self.t('terblokir_caps', lang),
            protected_label=self.t('dilindungi_oleh', lang),
            back_home=self.t('kembali_ke_beranda', lang),
            footer_note=self.t('ingin_mengajukan_banding_hubungi_administrator_jaringan_anda', lang),
            login_link=self.t('login_ke_dashboard', lang),
            login_detail=self.t('untuk_detail_lebih_lanjut', lang),
            tet_color='#60a5fa' if lang == 'tet' else '#94a3b8',
            tet_weight='700' if lang == 'tet' else '400',
            id_color='#60a5fa' if lang == 'id' else '#94a3b8',
            id_weight='700' if lang == 'id' else '400',
        )
        body = page.encode('utf-8')

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.send_header('X-Blocked-Domain', domain)
        self.send_header('X-Block-Category', category)
        if set_cookie:
            self.send_header('Set-Cookie', f'ks_lang={lang}; Path=/; Max-Age=31536000; SameSite=Lax')
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
