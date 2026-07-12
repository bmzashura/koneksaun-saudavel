"""
WhoisService — WHOIS lookup via whoisjson.com + domain-age risk scoring.
Includes SQLite caching (3-hour TTL) to conserve API quota.
"""

import os
import json
import logging
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

WHOIS_API_KEY = os.getenv("WHOIS_API_KEY", "")
WHOIS_BASE_URL = "https://whoisjson.com/api/v1/whois"
WHOIS_TIMEOUT = 10  # seconds
WHOIS_CACHE_TTL = int(os.getenv("WHOIS_CACHE_TTL_SECONDS", 10800))  # default 3 hours

# Lazily initialised DB path
_db_path = None


def _get_whois_api_key():
    """
    Get WHOIS API key. Priority:
    1. Environment variable WHOIS_API_KEY
    2. Database settings table (key='whois_api_key')
    """
    key = os.getenv("WHOIS_API_KEY", "")
    if key:
        return key
    # Fallback: read from settings table
    try:
        conn = _get_db()
        row = conn.execute(
            "SELECT value FROM settings WHERE key = ?", ("whois_api_key",)
        ).fetchone()
        conn.close()
        if row and row["value"]:
            return row["value"]
    except Exception as e:
        logger.warning(f"Could not read whois_api_key from settings: {e}")
    return ""


def _get_db_path():
    global _db_path
    if _db_path is None:
        # Try Flask app config first (during request context)
        try:
            from flask import current_app
            _db_path = current_app.config.get("DATABASE")
        except Exception:
            # Fallback: use env var or default path
            _db_path = os.getenv("DATABASE_PATH", "/opt/ks/koneksaun-saudavel/db/koneksaun.db")
    return _db_path


def _get_db():
    """Get a sqlite3 connection to the app DB."""
    db_path = _get_db_path()
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


# ─────────────────────────────────────────────────────────────────────────────
# Cache helpers
# ─────────────────────────────────────────────────────────────────────────────

def _cache_get(domain: str):
    """Return cached WHOIS result if not expired, else None."""
    try:
        conn = _get_db()
        row = conn.execute(
            "SELECT response_json, expires_at FROM whois_cache WHERE domain = ? AND expires_at > ?",
            (domain.lower(), datetime.now(timezone.utc).isoformat()),
        ).fetchone()
        conn.close()
        if row:
            logger.debug(f"WHOIS cache HIT: {domain}")
            return json.loads(row["response_json"])
        logger.debug(f"WHOIS cache MISS: {domain}")
        return None
    except Exception as e:
        logger.warning(f"WHOIS cache get error for {domain}: {e}")
        return None


def _cache_set(domain: str, data: dict) -> None:
    """Store WHOIS result in cache with TTL."""
    try:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=WHOIS_CACHE_TTL)
        conn = _get_db()
        conn.execute(
            """INSERT OR REPLACE INTO whois_cache (domain, response_json, cached_at, expires_at)
               VALUES (?, ?, ?, ?)""",
            (domain.lower(), json.dumps(data), datetime.now(timezone.utc).isoformat(), expires_at.isoformat()),
        )
        conn.commit()
        conn.close()
        logger.debug(f"WHOIS cached: {domain} (TTL={WHOIS_CACHE_TTL}s)")
    except Exception as e:
        logger.warning(f"WHOIS cache set error for {domain}: {e}")


def cleanup_expired_cache():
    """Delete all expired cache entries. Run periodically (e.g. daily cron)."""
    try:
        conn = _get_db()
        cur = conn.execute(
            "DELETE FROM whois_cache WHERE expires_at <= ?",
            (datetime.now(timezone.utc).isoformat(),),
        )
        conn.commit()
        deleted = cur.rowcount
        conn.close()
        logger.info(f"WHOIS cache cleanup: {deleted} expired entries removed.")
        return deleted
    except Exception as e:
        logger.warning(f"WHOIS cache cleanup error: {e}")
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# WHOIS lookup
# ─────────────────────────────────────────────────────────────────────────────

def lookup_whois(domain: str) -> dict:
    """
    Lookup WHOIS data for a domain via whoisjson.com.
    Result is cached for WHOIS_CACHE_TTL seconds (default 3 hours).

    Returns:
        dict with keys:
          success, domain, error,
          created_date, domain_age_days, domain_age_years,
          registrar_name, registrar_id, name_servers, status,
          is_active, is_young, is_newly_registered,
          expires, dnssec, expiration_days_left,
          risk_score, risk_level,
          cached (bool) — whether result came from cache
    """
    domain = domain.lower().strip()

    # 1. Check cache
    cached = _cache_get(domain)
    if cached:
        cached["cached"] = True
        return cached

    # 2. No API key — return error
    api_key = _get_whois_api_key()
    if not api_key:
        return {
            "success": False,
            "domain": domain,
            "error": "WHOIS_API_KEY not configured (set via admin dashboard or WHOIS_API_KEY env var)",
            "risk_score": None,
            "risk_level": None,
            "created_date": None,
            "domain_age_days": None,
            "domain_age_years": None,
            "registrar_name": None,
            "name_servers": [],
            "status": [],
            "cached": False,
        }

    # 3. Call whoisjson.com API
    import urllib.request

    url = f"{WHOIS_BASE_URL}?domain={domain}"
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"TOKEN={api_key}",
                "Accept": "application/json",
                "User-Agent": "KoneksaunSaudavel/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=WHOIS_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        logger.error(f"WHOIS HTTP {e.code} for {domain}: {body[:200]}")
        if e.code == 429:
            return {"success": False, "domain": domain, "error": "Rate limit exceeded (429)", "risk_score": None, "risk_level": None, "domain_age_days": None, "domain_age_years": None, "created_date": None, "registrar_name": None, "name_servers": [], "status": [], "cached": False}
        if e.code == 401:
            return {"success": False, "domain": domain, "error": "Invalid WHOIS_API_KEY (401)", "risk_score": None, "risk_level": None, "domain_age_days": None, "domain_age_years": None, "created_date": None, "registrar_name": None, "name_servers": [], "status": [], "cached": False}
        return {"success": False, "domain": domain, "error": f"HTTP {e.code}", "risk_score": None, "risk_level": None, "domain_age_days": None, "domain_age_years": None, "created_date": None, "registrar_name": None, "name_servers": [], "status": [], "cached": False}
    except Exception as e:
        logger.error(f"WHOIS lookup error for {domain}: {e}")
        return {"success": False, "domain": domain, "error": str(e), "risk_score": None, "risk_level": None, "domain_age_days": None, "domain_age_years": None, "created_date": None, "registrar_name": None, "name_servers": [], "status": [], "cached": False}

    # 4. Parse response (whoisjson returns flat RDAP structure)
    raw = data

    created_str = raw.get("created") or raw.get("creation_date") or ""
    created_date = None
    domain_age_days = None

    if created_str:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
            try:
                created_date = datetime.strptime(created_str[:19], fmt).replace(tzinfo=timezone.utc)
                break
            except (ValueError, IndexError):
                continue

    age_data = raw.get("age") or {}
    if isinstance(age_data, dict) and age_data.get("days"):
        domain_age_days = int(age_data["days"])
    elif created_date:
        domain_age_days = (datetime.now(timezone.utc) - created_date).days

    registrar_info = raw.get("registrar") or {}
    registrar_name = (registrar_info.get("name") if isinstance(registrar_info, dict) else str(registrar_info)) if registrar_info else ""

    ns_data = raw.get("nameserver") or []
    name_servers = [str(ns) for ns in ns_data] if isinstance(ns_data, list) else [str(ns_data)]

    status_data = raw.get("status") or []
    status = [str(s) for s in status_data] if isinstance(status_data, list) else [str(status_data)]

    # 5. Build result
    risk_score = calculate_risk_score(domain_age_days)
    risk_level = risk_level_label(risk_score)

    result = {
        "success": True,
        "domain": domain,
        "created_date": created_date.isoformat() if created_date else None,
        "domain_age_days": domain_age_days,
        "domain_age_years": round(domain_age_days / 365, 1) if domain_age_days is not None else None,
        "registrar_name": registrar_name,
        "registrar_id": registrar_info.get("id") if isinstance(registrar_info, dict) else None,
        "name_servers": name_servers,
        "status": status,
        "is_active": bool(raw.get("registered")),
        "is_young": age_data.get("isYoung") if isinstance(age_data, dict) else None,
        "is_newly_registered": age_data.get("isNewlyRegistered") if isinstance(age_data, dict) else None,
        "expires": raw.get("expires") or "",
        "dnssec": raw.get("dnssec") or "",
        "expiration_days_left": raw.get("expiration", {}).get("daysLeft") if isinstance(raw.get("expiration"), dict) else None,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "cached": False,
    }

    # 6. Store in cache (fire-and-forget)
    _cache_set(domain, result)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Risk scoring
# ─────────────────────────────────────────────────────────────────────────────

def calculate_risk_score(domain_age_days):
    """
    Calculate risk score (0-100) based purely on domain age.
    Higher score = more suspicious for adult/gambling content blocking.

    < 7 days      ->  50  (very new = very suspicious)
    7-30 days     ->  35  (fresh = suspicious)
    30-90 days    ->  15  (new-ish)
    90-365 days   ->   0  (established — neutral)
    1-5 years     -> -10  (mature)
    > 5 years     -> -20  (very established = lowest risk)
    None          ->  10  (unknown = slight risk)
    """
    if domain_age_days is None:
        return 10
    if domain_age_days < 0:
        return 0
    if domain_age_days < 7:
        return 50
    elif domain_age_days < 30:
        return 35
    elif domain_age_days < 90:
        return 15
    elif domain_age_days < 365:
        return 0
    elif domain_age_days < 1825:
        return -10
    else:
        return -20


def risk_level_label(score):
    """Map numeric risk score to human-readable label."""
    if score >= 45:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    elif score >= 10:
        return "LOW"
    elif score >= 0:
        return "NEUTRAL"
    else:
        return "VERY_LOW"
