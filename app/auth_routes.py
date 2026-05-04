"""
Auth routes - login, register, logout
"""

from flask import Blueprint, request, jsonify, render_template, redirect, session, flash
from datetime import datetime

from app.database import get_db
from app.auth import hash_password, verify_password, login_required, admin_required, get_current_user, is_admin

auth_bp = Blueprint('auth', __name__)


# ==================== AUTH PAGES ====================

@auth_bp.route('/login', methods=['GET'])
def login_page():
    """Login page."""
    if 'user_id' in session:
        return redirect('/dashboard')
    return render_template('login.html')


@auth_bp.route('/register', methods=['GET'])
def register_page():
    """Register page."""
    if 'user_id' in session:
        return redirect('/dashboard')
    return render_template('register.html')


@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    """Logout and clear session."""
    session.clear()
    return redirect('/login')


# ==================== AUTH API ====================

@auth_bp.route('/api/v1/auth/login', methods=['POST'])
def api_login():
    """API login endpoint."""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    db = get_db()
    user = db.execute(
        "SELECT id, username, password_hash, role, status FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if not user or not verify_password(password, user['password_hash']):
        return jsonify({'error': 'Invalid credentials'}), 401

    # Check account status
    if user['status'] == 'pending':
        return jsonify({'error': 'Account pending approval. Contact admin.'}), 403
    if user['status'] == 'disabled':
        return jsonify({'error': 'Account disabled. Contact admin.'}), 403

    # Update last login
    db.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user['id'],))
    db.commit()

    # Set session
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']

    return jsonify({
        'success': True,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role']
        }
    })


@auth_bp.route('/api/v1/auth/register', methods=['POST'])
def api_register():
    """API register endpoint — all new users start as pending."""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    email = data.get('email', '').strip()

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    db = get_db()

    # Check if username exists
    existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        return jsonify({'error': 'Username already taken'}), 409

    # All new users are 'pending' — must be approved by admin
    role = 'user'
    status = 'pending'

    password_hash, _ = hash_password(password)

    try:
        cursor = db.execute("""
            INSERT INTO users (username, password_hash, role, email, status)
            VALUES (?, ?, ?, ?, ?)
        """, (username, password_hash, role, email, status))
        db.commit()

        return jsonify({
            'success': True,
            'message': 'Registration submitted. Waiting for admin approval.'
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/api/v1/auth/me', methods=['GET'])
def api_me():
    """Get current user info."""
    if 'user_id' not in session:
        return jsonify({'authenticated': False}), 401

    return jsonify({
        'authenticated': True,
        'user': {
            'id': session['user_id'],
            'username': session.get('username'),
            'role': session.get('role')
        }
    })


@auth_bp.route('/api/v1/auth/logout', methods=['POST'])
def api_logout():
    """API logout."""
    session.clear()
    return jsonify({'success': True})


# ==================== WEB FORM HANDLERS ====================

@auth_bp.route('/login', methods=['POST'])
def login_submit():
    """Handle login form submission."""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    if not username or not password:
        flash('Username and password required', 'error')
        return redirect('/login')

    db = get_db()
    user = db.execute(
        "SELECT id, username, password_hash, role, status FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if not user or not verify_password(password, user['password_hash']):
        flash('Invalid credentials', 'error')
        return redirect('/login')

    if user['status'] == 'pending':
        flash('Account pending approval. Contact admin.', 'error')
        return redirect('/login')
    if user['status'] == 'disabled':
        flash('Account disabled. Contact admin.', 'error')
        return redirect('/login')

    db.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user['id'],))
    db.commit()

    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']

    return redirect('/dashboard')


@auth_bp.route('/register', methods=['POST'])
def register_submit():
    """Handle register form submission — new users are pending."""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    email = request.form.get('email', '').strip()

    if not username or not password:
        flash('Username and password required', 'error')
        return redirect('/register')

    if len(password) < 6:
        flash('Password must be at least 6 characters', 'error')
        return redirect('/register')

    db = get_db()

    existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        flash('Username already taken', 'error')
        return redirect('/register')

    password_hash, _ = hash_password(password)

    try:
        db.execute("""
            INSERT INTO users (username, password_hash, role, email, status)
            VALUES (?, ?, ?, ?, 'pending')
        """, (username, password_hash, 'user', email))
        db.commit()

        flash('Registration submitted. Waiting for admin approval.', 'info')
        return redirect('/login')
    except Exception as e:
        flash(str(e), 'error')
        return redirect('/register')


# ==================== PROFILE ====================

@auth_bp.route('/profile')
@login_required
def profile_page():
    """User profile page with password change."""
    db = get_db()
    current = get_current_user()
    users = db.execute(
        "SELECT id, username, email, role, status, created_at, last_login FROM users ORDER BY username"
    ).fetchall()
    return render_template('profile.html',
                         user=current,
                         all_users=[dict(u) for u in users])


@auth_bp.route('/profile/password', methods=['POST'])
@login_required
def change_password():
    """User changes their own password."""
    current = get_current_user()
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')


    if not new_password or len(new_password) < 6:
        flash('New password must be at least 6 characters.', 'error')
        return redirect('/profile')

    if new_password != confirm_password:
        flash('New password and confirmation do not match.', 'error')
        return redirect('/profile')

    db = get_db()
    user = db.execute(
        "SELECT id, password_hash FROM users WHERE id = ?", (current['id'],)
    ).fetchone()

    if not verify_password(current_password, user['password_hash']):
        flash('Current password is incorrect.', 'error')
        return redirect('/profile')

    pw_hash, _ = hash_password(new_password)
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, current['id']))
    db.commit()

    flash('Password updated successfully.', 'info')
    return redirect('/profile')



@auth_bp.route('/profile/admin-reset', methods=['POST'])
@login_required
@admin_required
def admin_reset_password():
    """Admin resets password for another user."""
    target_id = request.form.get('target_user_id', type=int)
    new_password = request.form.get('new_password', '').strip()
    current_user = get_current_user()

    if not target_id or target_id == current_user['id']:
        flash('Invalid target user.', 'error')
        return redirect('/profile')

    if not new_password or len(new_password) < 6:
        flash('Password must be at least 6 characters.', 'error')
        return redirect('/profile')

    db = get_db()
    target = db.execute("SELECT id FROM users WHERE id = ?", (target_id,)).fetchone()
    if not target:
        flash('User not found.', 'error')
        return redirect('/profile')

    pw_hash, _ = hash_password(new_password)
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, target_id))
    db.commit()

    flash(f'Password for user ID {target_id} reset successfully.', 'info')
    return redirect('/profile')
