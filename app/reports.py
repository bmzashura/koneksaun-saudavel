"""
Domain Report System - User submissions + Admin approval
"""

import logging
import os
import signal
import subprocess
from datetime import datetime
from pathlib import Path

from flask import request, Blueprint, request, jsonify, render_template, redirect, session, flash

from app.database import get_db
from app.auth import login_required, admin_required, get_current_user, hash_password, verify_password

reports_bp = Blueprint('reports', __name__)
logger = logging.getLogger(__name__)


# ==================== USER REPORT PAGES ====================

@reports_bp.route('/reports')
@login_required
def reports_page():
    """User's submitted reports page."""
    user = get_current_user()
    db = get_db()

    reports = db.execute("""
        SELECT r.*, u.username as reviewer_name
        FROM reports r
        LEFT JOIN users u ON r.reviewed_by = u.id
        WHERE r.reporter_id = ?
        ORDER BY r.created_at DESC
    """, (user['id'],)).fetchall()

    return render_template('reports.html',
                         reports=[dict(r) for r in reports],
                         user=user)


@reports_bp.route('/reports/submit')
@login_required
def submit_report_page():
    """Submit new domain report page."""
    user = get_current_user()
    db = get_db()
    categories = db.execute("SELECT name, display_name, description FROM categories").fetchall()
    return render_template('report_submit.html',
                         categories=[dict(c) for c in categories],
                         user=user)


# ==================== ADMIN PAGES ====================

@reports_bp.route('/admin/reports')
@admin_required
def admin_reports_page():
    """Admin: pending reports review page."""
    user = get_current_user()
    db = get_db()

    pending = db.execute("""
        SELECT r.*, u.username as reporter_name
        FROM reports r
        JOIN users u ON r.reporter_id = u.id
        WHERE r.status = 'pending'
        ORDER BY r.created_at ASC
    """).fetchall()

    all_reports = db.execute("""
        SELECT r.*, u.username as reporter_name, v.username as reviewer_name
        FROM reports r
        JOIN users u ON r.reporter_id = u.id
        LEFT JOIN users v ON r.reviewed_by = v.id
        ORDER BY r.created_at DESC
        LIMIT 100
    """).fetchall()

    return render_template('admin_reports.html',
                         pending=[dict(r) for r in pending],
                         all_reports=[dict(r) for r in all_reports],
                         user=user)


@reports_bp.route('/admin/users')
@admin_required
def admin_users_page():
    """Admin: user management page."""
    user = get_current_user()
    db = get_db()

    users = db.execute("""
        SELECT id, username, email, role, created_at, last_login
        FROM users ORDER BY created_at DESC
    """).fetchall()

    return render_template('admin_users.html',
                         users=[dict(u) for u in users],
                         user=user)


# ==================== ADMIN SETTINGS API ====================

@reports_bp.route('/api/v1/admin/settings/whois', methods=['GET'])
@admin_required
def get_whois_settings():
    """
    Get WHOIS configuration.
    Returns: {api_key_configured: bool, api_key_preview: str, cache_ttl_hours: int}
    """
    import os
    from app.services.whois_service import _get_whois_api_key

    api_key = _get_whois_api_key()
    configured = bool(api_key)
    # Preview: show first 8 chars + *** + last 4 if set
    if configured and len(api_key) > 12:
        preview = f"{api_key[:8]}...{api_key[-4:]}"
    elif configured:
        preview = "***" + api_key[-4:] if len(api_key) >= 4 else "****"
    else:
        preview = None

    return jsonify({
        "api_key_configured": configured,
        "api_key_preview": preview,
        "cache_ttl_hours": int(os.getenv("WHOIS_CACHE_TTL_SECONDS", "10800")) // 3600,
    })


@reports_bp.route('/api/v1/admin/settings/whois', methods=['PUT'])
@admin_required
def update_whois_settings():
    """
    Update WHOIS API key in settings table.
    Body: {"api_key": "..."}  — set to null/empty to clear
    """
    data = request.get_json() or {}
    new_key = (data.get("api_key") or "").strip()

    from app.services.whois_service import _encrypt as _fernet_encrypt

    db = get_db()

    if new_key:
        encrypted = _fernet_encrypt(new_key)
        db.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            ("whois_api_key_enc", encrypted),
        )
        db.commit()
        # Clear stale cache so new key is used immediately
        db.execute("DELETE FROM whois_cache")
        db.commit()
        return jsonify({"success": True, "api_key_configured": True})
    else:
        db.execute("DELETE FROM settings WHERE key = ?", ("whois_api_key",))
        db.commit()
        return jsonify({"success": True, "api_key_configured": False})


# ==================== WHOIS API ====================

@reports_bp.route('/api/v1/whois/<domain>', methods=['GET'])
def whois_lookup(domain):
    """
    WHOIS lookup for a domain. Returns registration data + domain-age risk score.

    Risk score is based purely on domain age:
      < 7 days   -> 50 (very new = very suspicious)
      7-30 days  -> 35 (fresh = suspicious)
      30-90 days -> 15 (new-ish)
      90-365 days-> 0  (established)
      1-5 years  -> -10 (mature)
      > 5 years  -> -20 (very established)
    """
    from app.services.whois_service import lookup_whois, calculate_risk_score, risk_level_label
    result = lookup_whois(domain)
    if not result["success"]:
        return jsonify(result), 502
    return jsonify(result)


# ==================== REPORT API ====================

@reports_bp.route('/api/v1/reports', methods=['GET'])
@admin_required
def list_reports():
    """List all reports (admin)."""
    db = get_db()
    reports = db.execute("""
        SELECT r.id, r.domain, r.category, r.status, r.reason, r.created_at,
               u.username AS reporter
        FROM reports r
        JOIN users u ON r.reporter_id = u.id
        ORDER BY r.created_at DESC
        LIMIT 100
    """).fetchall()
    return jsonify({'reports': [dict(r) for r in reports]})

@reports_bp.route('/api/v1/reports/mine', methods=['GET'])
@login_required
def my_reports():
    """Get current user's submitted reports."""
    db = get_db()
    user = get_current_user()
    my_rep = db.execute("""
        SELECT id, domain, category, status, reason, created_at
        FROM reports
        WHERE reporter_id = ?
        ORDER BY created_at DESC
    """, (user['id'],)).fetchall()
    return jsonify({'reports': [dict(r) for r in my_rep]})

@reports_bp.route('/api/v1/reports', methods=['POST'])
@login_required
def submit_report():
    """Submit a new domain report."""
    user = get_current_user()
    data = request.get_json()

    domain = data.get('domain', '').strip().lower()
    category = data.get('category', '').strip() or 'other'
    reason = data.get('reason', '').strip()

    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    if category not in ['ads', 'porn', 'gambling', 'other']:
        return jsonify({'error': 'Invalid category'}), 400

    # Basic domain validation
    if len(domain) > 253 or '.' not in domain:
        return jsonify({'error': 'Invalid domain format'}), 400

    db = get_db()

    # Check for duplicate pending report
    existing = db.execute("""
        SELECT id FROM reports
        WHERE domain = ? AND category = ? AND status = 'pending' AND reporter_id = ?
    """, (domain, category, user['id'])).fetchone()

    if existing:
        return jsonify({'error': 'You already have a pending report for this domain'}), 409

    try:
        cursor = db.execute("""
            INSERT INTO reports (reporter_id, domain, category, reason)
            VALUES (?, ?, ?, ?)
        """, (user['id'], domain, category, reason))
        db.commit()

        return jsonify({
            'success': True,
            'report_id': cursor.lastrowid,
            'message': 'Report submitted for review'
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/api/v1/reports/<int:report_id>', methods=['DELETE'])
@login_required
def delete_report(report_id):
    """User delete their own report (only if pending)."""
    user = get_current_user()
    db = get_db()

    report = db.execute("""
        SELECT id, reporter_id, status FROM reports WHERE id = ?
    """, (report_id,)).fetchone()

    if not report:
        return jsonify({'error': 'Report not found'}), 404

    if report['reporter_id'] != user['id'] and user['role'] != 'admin':
        return jsonify({'error': 'Not authorized'}), 403

    if report['status'] != 'pending':
        return jsonify({'error': 'Can only delete pending reports'}), 400

    db.execute("DELETE FROM reports WHERE id = ?", (report_id,))
    db.commit()

    return jsonify({'success': True})


def _reload_dns_blocklists():
    """Send SIGUSR1 to DNS server to reload blocklists. Falls back to service restart on failure."""
    import subprocess
    pid_file = Path("/opt/ks/koneksaun-saudavel/dns.pid")
    if not pid_file.exists():
        logger.error("dns.pid not found — cannot reload blocklists")
        return False
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, signal.SIGUSR1)
        logger.info(f"DNS blocklists reload triggered (PID {pid})")
        return True
    except Exception as e:
        logger.warning(f"SIGUSR1 failed ({e}) — falling back to service restart")
        try:
            result = subprocess.run(
                ["sudo", "systemctl", "restart", "ks-dns"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                logger.info("DNS server restarted successfully")
                return True
            else:
                logger.error(f"DNS restart failed: {result.stderr}")
                return False
        except Exception as restart_err:
            logger.error(f"DNS restart also failed: {restart_err}")
            return False


@reports_bp.route('/api/v1/reports/<int:report_id>/approve', methods=['POST'])
@admin_required
def approve_report(report_id):
    """Admin: approve report and add domain to blocklist."""
    user = get_current_user()
    data = request.get_json() or {}
    notes = data.get('notes', '').strip()

    db = get_db()

    report = db.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not report:
        return jsonify({'error': 'Report not found'}), 404

    if report['status'] != 'pending':
        return jsonify({'error': 'Report already reviewed'}), 400

    # Add domain to category blocklist file
    blocklist_path = Path(__file__).parent.parent / "db" / "blocklists" / f"{report['category']}.txt"

    try:
        with open(blocklist_path, 'a') as f:
            f.write(report['domain'] + '\n')

        # Mark report as approved
        db.execute("""
            UPDATE reports
            SET status = 'approved', reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP, reviewer_notes = ?
            WHERE id = ?
        """, (user['id'], notes, report_id))
        
        db.execute("""
            INSERT INTO domain_history (domain, category, action, admin_id, notes)
            VALUES (?, ?, 'added', ?, ?)
        """, (report['domain'], report['category'], user['id'], notes))
        
        db.commit()

        _reload_dns_blocklists()

        return jsonify({
            'success': True,
            'message': f"Domain {report['domain']} added to {report['category']} blocklist"
        })
    except Exception as e:
        return jsonify({'error': f'Failed to add domain: {str(e)}'}), 500


@reports_bp.route('/api/v1/reports/<int:report_id>/reject', methods=['POST'])
@admin_required
def reject_report(report_id):
    """Admin: reject report."""
    user = get_current_user()
    data = request.get_json() or {}
    notes = data.get('notes', '').strip()

    db = get_db()

    report = db.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not report:
        return jsonify({'error': 'Report not found'}), 404

    if report['status'] != 'pending':
        return jsonify({'error': 'Report already reviewed'}), 400

    db.execute("""
        UPDATE reports
        SET status = 'rejected', reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP, reviewer_notes = ?
        WHERE id = ?
    """, (user['id'], notes, report_id))
    db.commit()

    return jsonify({'success': True, 'message': 'Report rejected'})


# ==================== USER MANAGEMENT API ====================

@reports_bp.route('/api/v1/users', methods=['GET'])
@admin_required
def list_users():
    """Admin: list all users."""
    db = get_db()
    users = db.execute("""
        SELECT id, username, email, role, status, created_at, last_login
        FROM users ORDER BY created_at DESC
    """).fetchall()
    return jsonify([dict(u) for u in users])


@reports_bp.route('/api/v1/users/<int:user_id>/approve', methods=['POST'])
@admin_required
def approve_user(user_id):
    """Admin: approve pending user -> set status='active'."""
    db = get_db()
    target = db.execute('SELECT id, status FROM users WHERE id = ?', (user_id,)).fetchone()
    if not target:
        return jsonify({'error': 'User not found'}), 404
    if target['status'] == 'active':
        return jsonify({'error': 'User already active'}), 400
    db.execute("UPDATE users SET status = 'active' WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({'success': True, 'user_id': user_id, 'status': 'active'})


@reports_bp.route('/api/v1/users/<int:user_id>/reject', methods=['POST'])
@admin_required
def reject_user(user_id):
    """Admin: reject user -> delete account."""
    user = get_current_user()
    if user_id == user['id']:
        return jsonify({'error': 'Cannot reject yourself'}), 400
    db = get_db()
    target = db.execute('SELECT id FROM users WHERE id = ?', (user_id,)).fetchone()
    if not target:
        return jsonify({'error': 'User not found'}), 404
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({'success': True})


@reports_bp.route('/api/v1/users/<int:user_id>/disable', methods=['POST'])
@admin_required
def disable_user(user_id):
    """Admin: disable user account."""
    user = get_current_user()
    if user_id == user['id']:
        return jsonify({'error': 'Cannot disable yourself'}), 400
    db = get_db()
    db.execute("UPDATE users SET status = 'disabled' WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({'success': True, 'user_id': user_id, 'status': 'disabled'})


@reports_bp.route('/api/v1/users/<int:user_id>/enable', methods=['POST'])
@admin_required
def enable_user(user_id):
    """Admin: re-enable disabled user account."""
    db = get_db()
    db.execute("UPDATE users SET status = 'active' WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({'success': True, 'user_id': user_id, 'status': 'active'})


@reports_bp.route('/api/v1/users/<int:user_id>/reset-password', methods=['PUT'])
@admin_required
def reset_user_password(user_id):
    """Admin: reset user password to a temp password."""
    data = request.get_json()
    new_password = data.get('password', '').strip()
    if not new_password or len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    db = get_db()
    pw_hash, _ = hash_password(new_password)
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, user_id))
    db.commit()
    return jsonify({'success': True, 'user_id': user_id})


@reports_bp.route('/api/v1/users/<int:user_id>/role', methods=['PUT'])
@admin_required
def update_user_role(user_id):
    """Admin: update user role."""
    user = get_current_user()
    data = request.get_json()
    new_role = data.get('role', '').strip()

    if new_role not in ['user', 'admin']:
        return jsonify({'error': 'Role must be user or admin'}), 400

    # Prevent admin from removing own admin status
    if user_id == user['id'] and new_role != 'admin':
        return jsonify({'error': 'Cannot change your own role'}), 400

    db = get_db()
    db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    db.commit()

    return jsonify({'success': True, 'user_id': user_id, 'new_role': new_role})


@reports_bp.route('/api/v1/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    """Admin: delete user."""
    user = get_current_user()

    if user_id == user['id']:
        return jsonify({'error': 'Cannot delete yourself'}), 400

    db = get_db()

    # Check if user has pending reports
    pending = db.execute(
        "SELECT COUNT(*) as cnt FROM reports WHERE reporter_id = ? AND status = 'pending'",
        (user_id,)
    ).fetchone()['cnt']

    if pending > 0:
        return jsonify({'error': f'User has {pending} pending reports. Resolve first.'}), 400

    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()

    return jsonify({'success': True})# ==================== DOMAIN HISTORY ====================

@reports_bp.route('/api/v1/domain-history', methods=['GET'])
@admin_required
def get_domain_history():
    db = get_db()
    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page
    
    history = db.execute("""
        SELECT h.id, h.domain, h.category, h.action, h.notes, h.created_at,
               u.username as admin_name
        FROM domain_history h
        JOIN users u ON h.admin_id = u.id
        ORDER BY h.created_at DESC
        LIMIT ? OFFSET ?
    """, (per_page, offset)).fetchall()
    
    total = db.execute("SELECT COUNT(*) FROM domain_history").fetchone()[0]
    
    return jsonify({
        'history': [dict(h) for h in history],
        'total': total,
        'page': page,
        'pages': (total + per_page - 1) // per_page
    })


@reports_bp.route('/api/v1/blocklist/<path:domain>', methods=['DELETE'])
@admin_required
def remove_from_blocklist(domain):
    user = get_current_user()
    data = request.get_json() or {}
    notes = data.get('notes', '').strip()
    category = data.get('category', '').strip()
    
    if not category or category not in ['ads', 'porn', 'gambling', 'other']:
        return jsonify({'error': 'Valid category required'}), 400
    
    domain_clean = domain.strip().lower()
    blocklist_path = Path(__file__).parent.parent / "db" / "blocklists" / f"{category}.txt"
    
    if not blocklist_path.exists():
        return jsonify({'error': 'Blocklist not found'}), 404
    
    try:
        with open(blocklist_path, 'r') as f:
            lines = f.readlines()
        
        def _extract_domain(line):
            """Extract domain from a blocklist line. Returns domain str or None."""
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                return None
            parts = stripped.split()
            if not parts:
                return None
            # If line has IP prefix like "0.0.0.0 domain.com", domain is last part
            # If line is just "domain.com", first part is the domain
            # Use the last non-comment part
            for part in reversed(parts):
                if not part.startswith('#'):
                    return part.lower()
            return None

        original_count = len(lines)
        lines = [l for l in lines if _extract_domain(l) != domain_clean]
        
        if len(lines) == original_count:
            return jsonify({'error': 'Domain not found in blocklist'}), 404
        
        with open(blocklist_path, 'w') as f:
            f.writelines(lines)
        
        db = get_db()
        db.execute("""
            INSERT INTO domain_history (domain, category, action, admin_id, notes)
            VALUES (?, ?, 'removed', ?, ?)
        """, (domain_clean, category, user['id'], notes))
        
        # Also update the report status
        db.execute("""
            UPDATE reports
            SET status = 'removed_blocklist', reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP, reviewer_notes = ?
            WHERE domain = ? AND category = ? AND status = 'approved'
        """, (user['id'], notes, domain_clean, category))
        
        db.commit()
        
        _reload_dns_blocklists()
        
        return jsonify({
            'success': True,
            'message': f'Domain {domain_clean} removed from {category} blocklist'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/api/v1/blocklist/<path:domain>/add', methods=['POST'])
@admin_required
def add_to_blocklist(domain):
    user = get_current_user()
    data = request.get_json() or {}
    notes = data.get('notes', '').strip()
    category = data.get('category', '').strip()
    
    if not category or category not in ['ads', 'porn', 'gambling', 'other']:
        return jsonify({'error': 'Valid category required'}), 400
    
    domain_clean = domain.strip().lower()
    blocklist_path = Path(__file__).parent.parent / "db" / "blocklists" / f"{category}.txt"
    
    try:
        with open(blocklist_path, 'r') as f:
            existing = [l.strip() for l in f if domain_clean in l.lower()]
        
        if existing:
            return jsonify({'error': f'Domain {domain_clean} already in {category} blocklist'}), 409
        
        with open(blocklist_path, 'a') as f:
            f.write(domain_clean + '\n')
        
        db = get_db()
        db.execute("""
            INSERT INTO domain_history (domain, category, action, admin_id, notes)
            VALUES (?, ?, 'added', ?, ?)
        """, (domain_clean, category, user['id'], notes))
        db.commit()
        
        db.commit()
        
        _reload_dns_blocklists()
        
        return jsonify({
            'success': True,
            'message': f'Domain {domain_clean} added to {category} blocklist'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500