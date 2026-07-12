"""
WhoisService — WHOIS lookup via whoisjson.com + domain-age risk scoring.

API docs: https://whoisjson.com/documentation
Response format (RDAP):
{
  "name": "google.com",
  "created": "1997-09-15 04:00:00",
  "age": {"days": 10527, "years": 28, "isNewlyRegistered": false, "isYoung": false},
  "registrar": {"id": "292", "name": "Markmonitor Inc.", ...},
  "nameserver": ["ns1.google.com", ...],
  ...
}
"""

import os
import logging
import urllib.request
import json
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

WHOIS_API_KEY = os.getenv("WHOIS_API_KEY", "")
WHOIS_BASE_URL = "https://whoisjson.com/api/v1/whois"
WHOIS_TIMEOUT = 10  # seconds


def lookup_whois(domain: str) -> dict:
    """
    Lookup WHOIS data for a domain via whoisjson.com.

    Returns:
        dict with keys:
          success, domain, error,
          created_date (ISO str),
          domain_age_days (int),
          registrar_name (str),
          name_servers (list),
          status (list),
          risk_score (int),
          risk_level (str),
          raw (original dict for debugging)
    """
    if not WHOIS_API_KEY:
        return {
            "success": False,
            "domain": domain,
            "error": "WHOIS_API_KEY not configured",
            "risk_score": None,
            "risk_level": None,
            "created_date": None,
            "domain_age_days": None,
            "registrar_name": None,
            "name_servers": [],
            "status": [],
        }

    url = f"{WHOIS_BASE_URL}?domain={domain}"

    try:
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"TOKEN={WHOIS_API_KEY}",
                "Accept": "application/json",
                "User-Agent": "KoneksaunSaudavel/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=WHOIS_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        # whoisjson returns flat RDAP structure directly
        # (not nested under "whois" key)
        raw = data

        # --- Parse created_date ---
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

        # Prefer pre-calculated age from API (more reliable across TLDs)
        age_data = raw.get("age") or {}
        if isinstance(age_data, dict) and age_data.get("days"):
            domain_age_days = age_data["days"]
        elif created_date:
            domain_age_days = (datetime.now(timezone.utc) - created_date).days

        # --- Registrar ---
        registrar_info = raw.get("registrar") or {}
        if isinstance(registrar_info, dict):
            registrar_name = registrar_info.get("name") or ""
        else:
            registrar_name = str(registrar_info) if registrar_info else ""

        # --- Name servers ---
        ns_data = raw.get("nameserver") or raw.get("name_servers") or []
        if isinstance(ns_data, list):
            name_servers = [str(ns) for ns in ns_data]
        else:
            name_servers = [str(ns_data)]

        # --- Status ---
        status_data = raw.get("status") or []
        if isinstance(status_data, list):
            status = [str(s) for s in status_data]
        else:
            status = [str(status_data)]

        # --- Risk score ---
        risk_score = calculate_risk_score(domain_age_days)
        risk_level = risk_level_label(risk_score)

        return {
            "success": True,
            "domain": domain,
            "created_date": created_date.isoformat() if created_date else None,
            "domain_age_days": domain_age_days,
            "domain_age_years": round(domain_age_days / 365, 1) if domain_age_days is not None else None,
            "registrar_name": registrar_name,
            "registrar_id": (registrar_info.get("id") if isinstance(registrar_info, dict) else None),
            "name_servers": name_servers,
            "status": status,
            "is_active": bool(raw.get("registered")),
            "is_young": age_data.get("isYoung") if isinstance(age_data, dict) else None,
            "is_newly_registered": age_data.get("isNewlyRegistered") if isinstance(age_data, dict) else None,
            "expires": raw.get("expires") or raw.get("expiration", {}).get("date") if isinstance(raw.get("expiration"), dict) else raw.get("expires") or "",
            "dnssec": raw.get("dnssec") or "",
            "expiration_days_left": raw.get("expiration", {}).get("daysLeft") if isinstance(raw.get("expiration"), dict) else None,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "raw": raw,  # keep raw for debugging
        }

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        logger.error(f"WHOIS HTTP {e.code} for {domain}: {body[:200]}")
        if e.code == 429:
            return {"success": False, "domain": domain, "error": "Rate limit exceeded (429)", "risk_score": None, "risk_level": None, "domain_age_days": None, "created_date": None, "registrar_name": None, "name_servers": [], "status": []}
        if e.code == 401:
            return {"success": False, "domain": domain, "error": "Invalid WHOIS_API_KEY (401)", "risk_score": None, "risk_level": None, "domain_age_days": None, "created_date": None, "registrar_name": None, "name_servers": [], "status": []}
        return {"success": False, "domain": domain, "error": f"HTTP {e.code}", "risk_score": None, "risk_level": None, "domain_age_days": None, "created_date": None, "registrar_name": None, "name_servers": [], "status": []}
    except Exception as e:
        logger.error(f"WHOIS lookup error for {domain}: {e}")
        return {"success": False, "domain": domain, "error": str(e), "risk_score": None, "risk_level": None, "domain_age_days": None, "created_date": None, "registrar_name": None, "name_servers": [], "status": []}


def calculate_risk_score(domain_age_days):
    """
    Calculate risk score (0-100) based purely on domain age.
    Higher score = more suspicious for adult/gambling content blocking.

    Score bands:
      < 7 days      ->  50  (very new = very suspicious)
      7-30 days     ->  35  (fresh = suspicious)
      30-90 days    ->  15  (new-ish)
      90-365 days   ->   0  (established — neutral)
      1-5 years     -> -10  (mature)
      > 5 years     -> -20  (very established = lowest risk)
      None (no data)->  10  (unknown = slight risk)
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


def risk_level_label(score: int) -> str:
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
