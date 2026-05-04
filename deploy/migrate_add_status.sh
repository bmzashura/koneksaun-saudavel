#!/bin/bash
# Migration: Add status column to users table
# Run ONCE after git pull on existing deployments.
# Safe to run multiple times (idempotent).

set -e

APP_DIR="/opt/ks/koneksaun-saudavel"
DB="${APP_DIR}/db/koneksaun.db"

if [ ! -f "$DB" ]; then
    echo "ERROR: DB not found at $DB"
    exit 1
fi

echo "[MIGRATION] Adding status column to users table..."

/opt/ks/koneksaun-saudavel/venv/bin/python - << 'PYEOF'
import sqlite3, sys
sys.path.insert(0, '/opt/ks/koneksaun-saudavel')

db_path = '/opt/ks/koneksaun-saudavel/db/koneksaun.db'
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# Check if column exists
cur.execute("PRAGMA table_info(users)")
columns = [col[1] for col in cur.fetchall()]

if 'status' not in columns:
    cur.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'pending'")
    conn.commit()
    print("[MIGRATION] status column added (default: pending)")
else:
    print("[MIGRATION] status column already exists — skipping")

# Ensure existing admin users are 'active' (not pending)
affected = cur.execute("UPDATE users SET status = 'active' WHERE role = 'admin' AND status = 'pending'").rowcount
if affected:
    conn.commit()
    print(f"[MIGRATION] Upgraded {affected} admin user(s) to active")

conn.close()
PYEOF

echo "[MIGRATION] Done."
