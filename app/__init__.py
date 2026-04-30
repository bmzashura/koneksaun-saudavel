"""
Koneksaun Saudavel - DNS-based Content Blocker
Flask Application Entry Point
"""

import os
import sqlite3
from pathlib import Path
from flask import Flask, g, session

from app.routes import api_bp, dashboard_bp
from app.public_routes import public_bp
from app.auth_routes import auth_bp
from app.reports import reports_bp
from app.database import init_db, get_db, close_db

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "db" / "koneksaun.db"


def create_app():
    app = Flask(__name__,
                template_folder=BASE_DIR / "templates",
                static_folder=BASE_DIR / "static")

    # Config
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'ks-dev-secret-change-in-production-2024')
    app.config['DATABASE'] = str(DB_PATH)
    app.config['HOST'] = os.getenv('HOST', '0.0.0.0')
    app.config['PORT'] = int(os.getenv('PORT', 8080))
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24 hours
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    app.config['SESSION_COOKIE_SECURE'] = False

    # Initialize database
    init_db(app.config['DATABASE'])

    # Register teardown
    app.teardown_appcontext(close_db)

    # Register blueprints
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    app.register_blueprint(public_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(reports_bp)

    # Health check
    @app.route('/health')
    def health():
        return {'status': 'ok', 'service': 'koneksaun-saudavel'}

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(
        host=app.config['HOST'],
        port=app.config['PORT'],
        debug=os.getenv('DEBUG', 'False').lower() == 'true'
    )