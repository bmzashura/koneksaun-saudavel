"""
Public pages - accessible without login.
"""
from flask import Blueprint, render_template, request
from datetime import datetime

public_bp = Blueprint('public', __name__)

@public_bp.route('/blocked')
def blocked_page():
    """Blocked domain notification page — public, no login required."""
    domain = request.args.get('d', 'Unknown')
    category = request.args.get('c', 'blocked')
    timestamp = request.args.get('t', '')
    if not timestamp:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template('blocked.html', domain=domain, category=category, timestamp=timestamp)


@public_bp.route('/')
def home():
    """Public homepage with project info."""
    return render_template('home.html')
