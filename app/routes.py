"""
API and Dashboard routes for Koneksaun Saudavel.
REST API at /api/v1/*, Dashboard at /*
"""

from flask import Blueprint, jsonify, request, render_template, render_template_string
from app.auth import login_required
from datetime import datetime, timedelta
from app.database import get_db, query_db

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
def update_category_blocklist(name):
    """Force update blocklist for a category."""
    db = get_db()
    category = db.execute("SELECT * FROM categories WHERE name = ?", (name,)).fetchone()

    if not category:
        return jsonify({'error': 'Category not found'}), 404

    count, hash_val = update_blocklist(name, category['blocklist_url'])

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
def reset_stats():
    """Reset statistics counters."""
    # stats reset not implemented (in-memory stats removed)
    return jsonify({'success': True})


# ==================== QUERY LOGS ====================

@api_bp.route('/logs', methods=['GET'])
def get_logs():
    """Get query logs with pagination and filters."""
    db = get_db()

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    blocked_only = request.args.get('blocked_only', 'false').lower() == 'true'
    search = request.args.get('search', '')

    offset = (page - 1) * per_page

    query = "SELECT * FROM dns_logs WHERE 1=1"
    count_query = "SELECT COUNT(*) as total FROM dns_logs WHERE 1=1"
    params = []

    if blocked_only:
        query += " AND blocked = 1"
        count_query += " AND blocked = 1"

    if search:
        query += " AND domain LIKE ?"
        count_query += " AND domain LIKE ?"
        params.append(f'%{search}%')

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])

    logs = db.execute(query, params).fetchall()
    total = db.execute(count_query, params[:(-2 if search else 0)]).fetchone()['total']

    return jsonify({
        'logs': [dict(row) for row in logs],
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page
    })


@api_bp.route('/logs/clear', methods=['POST'])
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

