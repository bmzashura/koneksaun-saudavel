"""Koneksaun Saudavel Flask Web App"""

import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, g, render_template, redirect, url_for, session
import werkzeug.security

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "ks-secret-key-change-in-production")
DATABASE = "/app/data/koneksaun.db"


# ========================
# Database
# ========================

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    g.pop("db", None)


def init_db():
    """Initialize database tables"""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS blocked_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            category TEXT NOT NULL,
            added_by INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (added_by) REFERENCES users(id)
        );
        
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            category TEXT,
            reporter_id INTEGER,
            status TEXT DEFAULT 'pending',
            admin_response TEXT,
            reviewed_by INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TEXT,
            FOREIGN KEY (reporter_id) REFERENCES users(id)
        );
        
        CREATE TABLE IF NOT EXISTS categories (
            name TEXT PRIMARY KEY,
            enabled INTEGER DEFAULT 1,
            blocklist_url TEXT,
            domain_count INTEGER DEFAULT 0
        );
        
        CREATE TABLE IF NOT EXISTS dns_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            category TEXT,
            blocked INTEGER DEFAULT 0,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    
    # Insert default admin if not exists
    cursor = db.execute("SELECT id FROM users WHERE username = 'admin'")
    if cursor.fetchone() is None:
        from werkzeug.security import generate_password_hash
        db.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
            ("admin", generate_password_hash("admin123"))
        )
    
    # Insert categories
    for cat in [("ads", 1), ("porn", 1), ("gamble", 1)]:
        db.execute(
            "INSERT OR IGNORE INTO categories (name, enabled, domain_count) VALUES (?, ?, 0)",
            cat
        )
    
    db.commit()


# ========================
# Auth
# ========================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        db = get_db()
        user = db.execute("SELECT is_admin FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if not user or not user["is_admin"]:
            return "Admin only", 403
        return f(*args, **kwargs)
    return decorated


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/register")
def register():
    return render_template("register.html")


@app.route("/api/v1/auth/login", methods=["POST"])
def api_login():
    data = request.json
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (data["username"],)).fetchone()
    
    if user and werkzeug.security.check_password_hash(user["password_hash"], data["password"]):
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["is_admin"] = user["is_admin"]
        return jsonify({"success": True, "username": user["username"]})
    
    return jsonify({"success": False, "error": "Invalid credentials"}), 401


@app.route("/api/v1/auth/register", methods=["POST"])
def api_register():
    data = request.json
    db = get_db()
    
    try:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (data["username"], werkzeug.security.generate_password_hash(data["password"]))
        )
        db.commit()
        return jsonify({"success": True})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "Username exists"}), 400


@app.route("/api/v1/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"success": True})


@app.route("/api/v1/auth/me")
def api_me():
    if "user_id" not in session:
        return jsonify({"authenticated": False})
    return jsonify({
        "authenticated": True,
        "username": session["username"],
        "is_admin": session.get("is_admin", 0)
    })


# ========================
# Dashboard & Reports
# ========================

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/reports/submit", methods=["GET", "POST"])
@login_required
def submit_report():
    if request.method == "POST":
        data = request.form
        db = get_db()
        db.execute(
            "INSERT INTO reports (domain, category, reporter_id) VALUES (?, ?, ?)",
            (data["domain"], data.get("category", "manual"), session["user_id"])
        )
        db.commit()
        return redirect(url_for("dashboard"))
    return render_template("submit_report.html")


@app.route("/api/v1/reports/mine")
@login_required
def my_reports():
    db = get_db()
    reports = db.execute(
        "SELECT * FROM reports WHERE reporter_id = ? ORDER BY created_at DESC",
        (session["user_id"],)
    ).fetchall()
    return jsonify([dict(r) for r in reports])


@app.route("/api/v1/reports", methods=["POST"])
@login_required
def create_report():
    data = request.json
    db = get_db()
    cursor = db.execute(
        "INSERT INTO reports (domain, category, reporter_id) VALUES (?, ?, ?)",
        (data["domain"], data.get("category", "manual"), session["user_id"])
    )
    db.commit()
    return jsonify({"success": True, "id": cursor.lastrowid})


@app.route("/api/v1/stats")
def stats():
    db = get_db()
    total_reports = db.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    pending_reports = db.execute("SELECT COUNT(*) FROM reports WHERE status = 'pending'").fetchone()[0]
    total_users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    
    return jsonify({
        "total_reports": total_reports,
        "pending_reports": pending_reports,
        "total_users": total_users
    })


@app.route("/api/v1/categories")
def categories():
    db = get_db()
    cats = db.execute("SELECT * FROM categories").fetchall()
    return jsonify([dict(c) for c in cats])


# ========================
# Admin
# ========================

@app.route("/admin/reports")
@admin_required
def admin_reports():
    return render_template("admin_reports.html")


@app.route("/admin/users")
@admin_required
def admin_users():
    return render_template("admin_users.html")


@app.route("/admin/settings")
@admin_required
def admin_settings():
    return render_template("admin_settings.html")


@app.route("/api/v1/admin/reports/<int:report_id>/<action>", methods=["POST"])
@admin_required
def admin_report_action(report_id, action):
    db = get_db()
    if action == "approve":
        report = db.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        if report:
            # Add to blocked_domains
            db.execute(
                "INSERT OR IGNORE INTO blocked_domains (domain, category, added_by) VALUES (?, ?, ?)",
                (report["domain"], report["category"], session["user_id"])
            )
            db.execute(
                "UPDATE reports SET status = 'approved', reviewed_by = ?, reviewed_at = ? WHERE id = ?",
                (session["user_id"], datetime.now().isoformat(), report_id)
            )
            db.commit()
        return jsonify({"success": True})
    elif action == "reject":
        db.execute(
            "UPDATE reports SET status = 'rejected', reviewed_by = ?, reviewed_at = ? WHERE id = ?",
            (session["user_id"], datetime.now().isoformat(), report_id)
        )
        db.commit()
        return jsonify({"success": True})
    return jsonify({"error": "Invalid action"}), 400


@app.route("/api/v1/admin/users")
@admin_required
def admin_list_users():
    db = get_db()
    users = db.execute("SELECT id, username, is_admin, created_at FROM users").fetchall()
    return jsonify([dict(u) for u in users])


@app.route("/api/v1/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required
def admin_delete_user(user_id):
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({"success": True})


@app.route("/api/v1/categories/<name>/update-blocklist", methods=["POST"])
@admin_required
def update_category_blocklist(name):
    # Placeholder for blocklist update trigger
    return jsonify({"success": True, "message": "Blocklist update triggered"})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080)
