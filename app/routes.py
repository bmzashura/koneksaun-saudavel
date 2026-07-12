"""
API and Dashboard routes for Koneksaun Saudavel.
REST API at /api/v1/*, Dashboard at /*
"""

import hashlib
import urllib.request
from flask import Blueprint, jsonify, request, render_template, render_template_string
from app.auth import login_required
from datetime import datetime, timedelta
from app.database import get_db, query_db

def update_blocklist(name: str, url: str):
    """Download blocklist from URL, save to db/blocklists/{name}.txt. Returns (count, hash)."""
    from pathlib import Path

    if not url or not url.startswith('http'):
        return 0, ''

    blocklist_dir = Path(__file__).parent.parent / 'db' / 'blocklists'
    blocklist_dir.mkdir(parents=True, exist_ok=True)
    out_path = blocklist_dir / f'{name}.txt'

    domains = set()

    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
    except Exception:
        return 0, ''

    import re
    # Regex to extract domain from AdGuard/AdBlock syntax: ||domain.com^ or ||domain.com/$dnsblock
    adguard_re = re.compile(r'\|\|([a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9])\^')
    hosts_re = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([^\s#]+)', re.IGNORECASE)

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('!'):
            continue

        # AdGuard / AdBlock syntax: ||domain.com^
        m = adguard_re.match(line)
        if m:
            domain = m.group(1).lower()
            if domain:
                domains.add(domain)
            continue

        # Hosts file format: 0.0.0.0 domain.com
        m = hosts_re.match(line)
        if m:
            domain = m.group(1).lower().rstrip('.')
            if domain and not domain.startswith('#'):
                domains.add(domain)
            continue

        # Plain domain list (no spaces, no slashes, no AdGuard chars)
        if '/' not in line and '||' not in line and '^' not in line and ' ' not in line and line:
            domain = line.lower().rstrip('.')
            if domain and not domain.startswith('#'):
                domains.add(domain)

    with open(out_path, 'w') as f:
        for domain in sorted(domains):
            f.write(domain + '\n')

    content_hash = hashlib.md5(content.encode()).hexdigest()[:12]
    return len(domains), content_hash


api_bp = Blueprint('api', __name__)
dashboard_bp = Blueprint('dashboard', __name__)


# ==================== CATEGORY MANAGEMENT ====================

@api_bp.route('/categories', methods=['GET'])
def get_categories():
    """Get all blocking categories with actual blocklist counts."""
    from pathlib import Path
    base_dir = Path(__file__).parent.parent
    db = get_db()
    
    # Get category names from DB
    rows = db.execute("SELECT * FROM categories ORDER BY name").fetchall()
    result = []
    
    for row in rows:
        cat = dict(row)
        # Calculate actual domain count from blocklist file
        blocklist_path = base_dir / 'db' / 'blocklists' / f"{cat['name']}.txt"
        count = 0
        if blocklist_path.exists():
            with open(blocklist_path, 'r') as f:
                count = sum(1 for line in f if line.strip() and not line.startswith('#'))
        cat['domains'] = count
        # Remove legacy db field, frontend uses 'domains'
        cat.pop('domain_count', None)
        result.append(cat)
    
    # Add 'other' category
    blocklist_path = base_dir / 'db' / 'blocklists' / 'other.txt'
    other_count = 0
    if blocklist_path.exists():
        with open(blocklist_path, 'r') as f:
            other_count = sum(1 for line in f if line.strip() and not line.startswith('#'))
    result.append({
        'name': 'other',
        'display_name': 'Other',
        'description': 'Custom blocked domains',
        'enabled': 1,
        'domains': other_count,
        'created_at': None,
        'updated_at': None,
        'blocklist_url': ''
    })
    
    return jsonify(result)


@api_bp.route('/categories/<name>/toggle', methods=['POST'])
@admin_required
def toggle_category(name):
    """Enable or disable a blocking category."""
    db = get_db()
    data = request.get_json()
    enabled = data.get('enabled', True)

    db.execute(
        "UPDATE categories SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?",
        (enabled, name)
    )
    db.commit()

    return jsonify({'success': True, 'category': name, 'enabled': enabled})


@api_bp.route('/categories/<name>/update-blocklist', methods=['POST'])
@admin_required
def update_category_blocklist(name):
    """Force update blocklist for a category. Skips 'other' (manual)."""
    if name == 'other':
        return jsonify({'error': 'Other category is updated manually via reports. Not available for auto-update.'}), 400

    db = get_db()
    category = db.execute("SELECT * FROM categories WHERE name = ?", (name,)).fetchone()

    if not category:
        return jsonify({'error': 'Category not found'}), 404

    if not category['blocklist_url']:
        return jsonify({'error': 'No blocklist URL configured for this category'}), 400

    count, hash_val = update_blocklist(name, category['blocklist_url'])
    if count == 0:
        return jsonify({'error': 'Failed to download blocklist. Check URL and network.'}), 500

    # Update blocklist metadata
    db.execute("""
        INSERT INTO blocklist (category, domain_count, last_updated, content_hash)
        VALUES (?, ?, CURRENT_TIMESTAMP, ?)
        ON CONFLICT(category) DO UPDATE SET
            domain_count = excluded.domain_count,
            last_updated = CURRENT_TIMESTAMP,
            content_hash = excluded.content_hash
    """, (name, count, hash_val))
    db.commit()

    return jsonify({'success': True, 'category': name, 'domains': count})


# ==================== WHITELIST MANAGEMENT ====================



# ==================== STATISTICS ====================

@api_bp.route('/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics."""
    db = get_db()

    # Total blocked queries
    total_blocked = db.execute(
        "SELECT COUNT(*) as count FROM dns_logs WHERE blocked = 1"
    ).fetchone()['count']

    # Blocked by category
    by_category = db.execute("""
        SELECT category, COUNT(*) as count
        FROM dns_logs
        WHERE blocked = 1 AND category IS NOT NULL
        GROUP BY category
    """).fetchall()

    # Top blocked domains
    top_domains = db.execute("""
        SELECT domain, COUNT(*) as count
        FROM dns_logs
        WHERE blocked = 1
        GROUP BY domain
        ORDER BY count DESC
        LIMIT 10
    """).fetchall()

    # Recent blocked (last 24h)
    recent_blocked = db.execute("""
        SELECT COUNT(*) as count FROM dns_logs
        WHERE blocked = 1 AND timestamp > datetime('now', '-1 day')
    """).fetchone()['count']

    # Calculate actual total domains from blocklist files
    from pathlib import Path
    base_dir = Path(__file__).parent.parent
    total_blocklist_domains = 0
    all_categories = []
    for cat in ['ads', 'porn', 'gambling', 'other']:
        blocklist_path = base_dir / 'db' / 'blocklists' / f'{cat}.txt'
        count = 0
        if blocklist_path.exists():
            with open(blocklist_path, 'r') as f:
                count = sum(1 for line in f if line.strip() and not line.startswith('#'))
        total_blocklist_domains += count
        
        # Get count from dns_logs for this category (blocked queries)
        cat_count = db.execute(
            "SELECT COUNT(*) FROM dns_logs WHERE blocked = 1 AND category = ?", [cat]
        ).fetchone()[0]
        all_categories.append({'category': cat, 'count': cat_count})

    return jsonify({
        'total_blocked': total_blocked,
        'by_category': all_categories,
        'top_domains': [dict(row) for row in top_domains],
        'recent_blocked_24h': recent_blocked,
        'blocked_domains_total': total_blocklist_domains,
    })


@api_bp.route('/stats/reset', methods=['POST'])
@admin_required
def reset_stats():
    """Reset statistics counters."""
    # stats reset not implemented (in-memory stats removed)
    return jsonify({'success': True})


# ==================== QUERY LOGS ====================

@api_bp.route('/logs', methods=['GET'])
def get_logs():
    """Get query logs with pagination and filters.

    Args:
        page: page number (default 1)
        per_page: items per page (default 100, max 500)
        blocked: 0=allowed, 1=blocked
        category: ads/porn/gambling/other or 'all'
        domain: partial domain search
        start_date: ISO date (>= timestamp)
        end_date: ISO date (<= timestamp)
    """
    db = get_db()

    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(500, max(10, request.args.get('per_page', 100, type=int)))
    blocked = request.args.get('blocked', '')
    category = request.args.get('category', '')
    domain = request.args.get('domain', '').strip()
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')

    offset = (page - 1) * per_page

    where = []
    params = []

    if blocked in ('0', '1'):
        where.append("blocked = ?")
        params.append(int(blocked))

    if category and category != 'all':
        where.append("category = ?")
        params.append(category)

    if domain:
        where.append("domain LIKE ?")
        params.append(f'%{domain}%')

    if start_date:
        where.append("timestamp >= ?")
        params.append(start_date)

    if end_date:
        where.append("timestamp <= ?")
        params.append(end_date)

    where_clause = ' AND '.join(where) if where else '1=1'

    logs = db.execute(
        f"SELECT * FROM dns_logs WHERE {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        params + [per_page, offset]
    ).fetchall()

    total = db.execute(
        f"SELECT COUNT(*) as total FROM dns_logs WHERE {where_clause}",
        params
    ).fetchone()['total']

    return jsonify({
        'logs': [dict(row) for row in logs],
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page if per_page else 1
    })


@api_bp.route('/logs/clear', methods=['POST'])
@admin_required
def clear_logs():
    """Clear all query logs."""
    db = get_db()
    db.execute("DELETE FROM dns_logs")
    db.commit()
    return jsonify({'success': True})
# ==================== DASHBOARD ====================

@dashboard_bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard page."""
    return render_template('index.html')


@dashboard_bp.route('/logs')
@login_required
def logs_page():
    """Query logs page."""
    return render_template('logs.html')


@dashboard_bp.route('/settings')
@login_required
def settings_page():
    """Settings page."""
    return render_template('settings.html')


@dashboard_bp.route('/blocked')
@login_required
def blocked_page():
    """Blocked domain notification page."""
    domain = request.args.get('d', 'Unknown')
    category = request.args.get('c', 'blocked')
    return render_template('blocked.html', domain=domain, category=category)

