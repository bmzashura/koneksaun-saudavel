# TODO — Future: Domain + HTTPS Integration

## Context
DNS-based blocking dengan HTTP redirect hanya works untuk HTTP (port 80). HTTPS (port 443) connections gagal karena browser tidak dapat connect ke gateway certificate.

## Problem Statement
```
User request https://facebook.com
  → DNS returns 172.17.12.177 (redirect IP)
  → Browser connect to facebook.com:443
  → Connection REFUSED (gateway not on 443)
  → Browser shows "Connection refused" or "Your connection was interrupted"
  → User tidak melihat blocked page notification
```

## Goal
Serve blocked notification page untuk HTTPS requests juga — user-friendly, no certificate warnings.

---

## Option A: HTTPS Gateway with IP-based Certificate

**Approach:**
1. Gateway listen on port 443 with TLS
2. Use IP certificate (not domain-specific) — browser will show warning but won't block
3. OR use Let's Encrypt with a domain pointing to the server

**Pros:**
- HTTPS works for blocked domains
- No DNS NXDOMAIN

**Cons:**
- Browser shows "Your connection is not private" warning (need user to click "Advanced" → "Proceed")
- Need a domain pointed to 172.17.12.177 for valid cert
- Self-signed cert always shows warning

**Tech:**
- Python stdlib `ssl` module
- Self-signed cert: `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes`
- Gateway modification to wrap socket with SSL

---

## Option B: Split-Proxy HTTPS → HTTP

**Approach:**
1. haproxy atau nginx reverse proxy di port 443
2. Terminate SSL/TLS di proxy
3. Forward to gateway HTTP port 80

**Pros:**
- Clean separation, haproxy/nginx handles SSL better
- Can use Let's Encrypt for valid cert if domain available

**Cons:**
- Extra service to manage
- Additional complexity

**Tech:**
- haproxy with SSL termination
- OR nginx as reverse proxy

---

## Option C: DNS-over-HTTPS (DoH) with Browser Integration

**Approach:**
1. Serve DoH endpoint on the DNS server
2. Browser uses DoH to query our DNS server
3. Our DNS returns blocked domain → blocked page URL
4. Browser automatically fetches blocked page

**Pros:**
- Modern, privacy-friendly approach
- Browser-native HTTPS to blocked page

**Cons:**
- Requires user to configure DoH in browser
- Not automatic for all devices

**Tech:**
- `https://github.com/bmores/simpledoh` or similar DoH server
- Browser DoH configuration

---

## Option D: Captive Portal Style Redirect

**Approach:**
1. Blocked domain returns NXDOMAIN in DNS
2. But also return a "captive portal" IP that intercepts all HTTP/HTTPS
3. Router-level interception (if this is the default gateway)

**Pros:**
- Works on network level, no per-device config
- Captive portal detection on all browsers

**Cons:**
- Requires VM to be default gateway (router)
- Complex network setup
- HTTPS interception needs MITM cert

---

## Decision Criteria for Picking Option

| Criteria | Option A (HTTPS Gateway) | Option B (Split Proxy) | Option C (DoH) | Option D (Captive Portal) |
|----------|--------------------------|------------------------|-----------------|--------------------------|
| User complexity | Medium | Low | High | High |
| Needs domain | Yes | Yes | No | No |
| Setup complexity | Low | Medium | High | Very High |
| Valid cert | Need domain | Need domain | No | No |
| Works for all devices | No | No | Per-browser | Yes |
| Maintenance | Low | Medium | Medium | High |

---

## Recommended Next Steps

1. **Option A (HTTPS Gateway)** — most straightforward if domain is available
   - Generate self-signed cert
   - Add SSL support to gateway.py
   - Listen on port 443

2. **Option B (Split Proxy)** — if we want clean separation
   - Add haproxy or nginx as SSL terminator
   - Forward to gateway on port 80

---

## Status

- [ ] Research: Evaluate which option fits best
- [ ] Decision: Pick option based on deployment context
- [ ] Implementation: TBD based on decision

---

## Notes

- For now: HTTP-only works for testing and simple deployment
- HTTPS gateway is best for production use with a domain
- Cleanbrowsing/OpenDNS approach: they use DNS blocking + browser safe search integration
- Let's Encrypt free certs: needs domain pointing to server IP
