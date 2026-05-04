"""
Database initialization and utilities for Koneksaun Saudavel
"""

import sqlite3
import hashlib
from pathlib import Path
from flask import current_app, g


def get_db():
    """Get database connection for current request context."""
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    """Close database connection at end of request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db(database_path):
    """Initialize database with schema."""
    db_path = Path(database_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Read and execute schema
    schema_path = Path(__file__).parent.parent / "db" / "schema.sql"
    with open(schema_path, 'r') as f:
        schema = f.read()

    cursor.executescript(schema)
    conn.commit()

    # Insert default categories if not exist
    default_categories = [
        ('ads', 'Ads & Trackers', 1,
         'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',
         'Block ads, trackers, and malware domains'),
        ('porn', 'Adult Content', 1,
         'https://easylist.to/easylist/easylist.txt',
         'Block pornographic websites'),
        ('gambling', 'Gambling', 1,
         'https://blocklistproject.github.io/Lists/gambling.txt',
         'Block gambling and betting sites'),
    ]

    cursor.executemany("""
        INSERT OR IGNORE INTO categories (name, display_name, enabled, blocklist_url, description)
        VALUES (?, ?, ?, ?, ?)
    """, default_categories)

    conn.commit()
    conn.close()


def query_db(query, args=(), one=False):
    """Execute a query and return results."""
    db = get_db()
    cursor = db.execute(query, args)
    rv = cursor.fetchall()
    cursor.close()
    return (rv[0] if rv else None) if one else rv


def dict_from_row(row):
    """Convert sqlite3.Row to dict."""
    if row is None:
        return None
    return dict(zip(row.keys(), row))