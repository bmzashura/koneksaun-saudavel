"""
Public pages - accessible without login.
"""
from flask import Blueprint, render_template

public_bp = Blueprint('public', __name__)

@public_bp.route('/')
def home():
    """Public homepage with project info."""
    return render_template('home.html')
