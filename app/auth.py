"""
Authentication and User Management for Koneksaun Saudavel
"""

import hashlib
import secrets
import functools
from datetime import datetime, timedelta
from flask import request, redirect, jsonify, session, url_for


def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    """Hash password with salt. Returns (hash, salt)."""
    if salt is None:
        salt = secrets.token_hex(16)
    pepper = "ks_pepper_2024"  # Static pepper (in production, use env var)
    hash_input = f"{salt}{password}{pepper}"
    hash_val = hashlib.sha256(hash_input.encode()).hexdigest()
    return f"{salt}${hash_val}", salt


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash."""
    try:
        salt, hash_val = stored_hash.split('$')
        expected_hash = hash_password(password, salt)[0]
        return expected_hash == stored_hash
    except (ValueError, AttributeError):
        return False


def generate_token(user_id: int, username: str, role: str) -> str:
    """Generate a session token."""
    raw = f"{user_id}:{username}:{role}:{secrets.token_hex(16)}"
    return raw  # In production, use JWT or server-side sessions


def login_required(f):
    """Decorator to require authentication."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # API request → return 401
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            # Web request → redirect to login
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect('/login')
        if session.get('role') != 'admin':
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Admin access required'}), 403
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function


def get_current_user():
    """Get current logged-in user from session."""
    if 'user_id' in session:
        return {
            'id': session['user_id'],
            'username': session.get('username'),
            'role': session.get('role'),
        }
    return None


def is_admin():
    """Check if current user is admin."""
    return session.get('role') == 'admin'