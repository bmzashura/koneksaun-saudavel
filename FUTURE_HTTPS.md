# Future: Domain + HTTPS Integration

> ⚠️ **Deprecated (2026-06-03):** The standalone HTTP gateway (`gateway.py` + `ks-gateway.service`) has been removed from the architecture. The Flask web app on port 8080 now handles all blocked domain page serving. See [README.md](README.md) for current architecture.

---

## Historical Context

Previously, a standalone Python `gateway.py` on port 80 served blocked domain pages. This added complexity (SSL cert management, nginx for HTTPS) with marginal benefit — DNS blocking works even without the HTTPS page, and most browsers just show a generic connection error for blocked HTTPS sites.

## Current Architecture

```
Blocked domain → DNS returns 172.17.12.177 → Flask :8080 serves blocked page
```

All blocked domain serving is now handled by the Flask app directly. No separate gateway process, no nginx, no SSL cert management.

## If You Still Want HTTPS

If you need HTTPS for the blocked page (e.g., to avoid browser "connection refused" warnings), the recommended path forward:

1. **Add a domain** pointing to the server IP
2. **Use Let's Encrypt** (free) for valid certificate
3. **Integrate SSL directly in the Flask app** or add a lightweight reverse proxy

The `FUTURE_HTTPS.md` approach from before would still work — but now it's simpler because:
- Only one service to modify (Flask instead of separate gateway + nginx)
- No port 80 conflict
- No certificate path issues

## Status

- [x] Gateway removed — complexity reduced
- [ ] HTTPS integration — only if you have a domain and want to avoid browser warnings