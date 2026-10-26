"""
Koneksaun Saudavel - DNS-based Content Blocker
Flask Application Entry Point
"""

import os
import sqlite3
from pathlib import Path
from flask import Flask, g, session, send_from_directory, Response

from app.routes import api_bp, dashboard_bp
from app.public_routes import public_bp
from app.auth_routes import auth_bp
from app.reports import reports_bp
from app.database import init_db, get_db, close_db
from app.i18n import (
    LANG_NAMES,
    available_languages,
    get_lang,
    translate,
)

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
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'  # True when served behind HTTPS proxy

    # Security headers — applied to all responses
    @app.after_request
    def security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        return response

    # Initialize database
    init_db(app.config['DATABASE'])

    # Register teardown
    app.teardown_appcontext(close_db)

    # Internationalisation — inject t() into every template
    @app.context_processor
    def inject_i18n():
        lang = get_lang()
        return {
            't': lambda key, **kwargs: translate(key, lang, **kwargs),
            'current_lang': lang,
            'lang_names': LANG_NAMES,
            'lang_codes': available_languages(),
        }

    @app.after_request
    def _strip_werkzeug_redirect_page(response):
        """Drop Werkzeug's English auto-redirect page.

        Werkzeug answers a redirect() with an HTML body that says
        "You should be redirected automatically to the target URL ...".
        That is English prose served by a Tetum-localised app, so the
        body is cleared; browsers follow the Location header regardless.
        """
        if response.status_code in (301, 302, 303, 307, 308):
            if response.mimetype == 'text/html' and b'redirected automatically' in response.get_data():
                response.set_data(b'')
        return response

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

    # Robots.txt — block all crawlers from indexing this DNS blocker
    @app.route('/robots.txt')
    def robots_txt():
        return send_from_directory(app.static_folder, 'robots.txt', mimetype='text/plain')

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(
        host=app.config['HOST'],
        port=app.config['PORT'],
        debug=os.getenv('DEBUG', 'False').lower() == 'true'
    )