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
