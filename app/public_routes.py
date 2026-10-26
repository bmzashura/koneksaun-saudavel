"""
Public pages - accessible without login.
"""
from flask import Blueprint, abort, make_response, redirect, render_template, request, url_for
from datetime import datetime

from app.database import get_db
from app.i18n import available_languages, set_lang_response

public_bp = Blueprint('public', __name__)


def lookup_block_category(domain: str):
    """Find the category a domain was last blocked under.

    The DNS server logs every blocked query (domain, category, client_ip,
    timestamp) into dns_logs, so the web layer can recover the real
    category ('ads' / 'porn' / 'gambling') for a domain that was blocked
    moments earlier. This lets the reverse proxy redirect with only the
    hostname, without having to know the category itself.
    """
    try:
        db = get_db()
        row = db.execute(
            "SELECT category FROM dns_logs "
            "WHERE domain = ? AND blocked = 1 "
            "ORDER BY id DESC LIMIT 1",
            (domain,),
        ).fetchone()
        return row['category'] if row and row['category'] else None
    except Exception:
        return None


@public_bp.route('/blocked')
def blocked_page():
    """Blocked domain notification page — public, no login required."""
    domain = request.args.get('d', 'Unknown')
    category = request.args.get('c', '')
    timestamp = request.args.get('t', '')
    if not timestamp:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if not category or category == 'blocked':
        category = lookup_block_category(domain) or 'blocked'
    return render_template('blocked.html', domain=domain, category=category, timestamp=timestamp)


@public_bp.route('/')
def home():
    """Public homepage with project info."""
    return render_template('home.html')


@public_bp.route('/lang/<code>')
def set_language(code):
    """Switch the interface language and remember the choice in a cookie."""
    if code not in available_languages():
        abort(404)

    target = request.args.get('next') or request.referrer or url_for('public.home')
    # only allow same-site relative targets
    if not target.startswith('/'):
        target = url_for('public.home')

    response = make_response(redirect(target))
    return set_lang_response(response, code)
