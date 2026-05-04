# Koneksaun Saudavel (Healthy Connection)

DNS-based content blocker for Raspberry Pi / VPS. Blocks ads, porn, and gambling at the network level — no client software needed.

## Features

| Feature | Description |
|---|---|
| **DNS Blocking** | Network-wide ad/porn/gambling blocking via DNS-level filtering |
| **744K+ Domains** | Combined blocklists (241K ads, 500K porn, 2.5K gambling) |
| **Auth System** | User registration + login with role-based access (admin/user) |
| **Report System** | Users report blocked domains for admin review → added to "other" blocklist |
| **Admin Approval** | Admins approve/reject reports -> domain added/removed from blocklist |
| **Privacy-First** | No client IP logging, no device tracking |

---

## Architecture

```
Client Browser
      │
      ▼
Python DNS Server (0.0.0.0:53)
      │
      ├─── Blocklist Match ──► A record → 172.17.12.177 (redirect)
      │                              │
      │                          HTTP Gateway (port 80)
      │                              │
      │                          Blocked Page ──► Browser shows notification
      │
      └─── No Match ──► Forward to upstream DNS (1.1.1.1 / 8.8.8.8)
```

- **Port 53 (UDP)**: Python DNS server — blocks domains, returns redirect A record for blocked sites
- **Port 80 (TCP)**: HTTP gateway — serves blocked domain notification page
- **Port 8080 (TCP)**: Flask web app (dashboard, auth, reports, admin)
- **No client IP stored**: DNS query logs only store domain + category + blocked status

---

## Tech Stack

| Layer | Technology |
|---|---|
| DNS Server | Python (stdlib socket) — custom recursive DNS |
| Web Framework | Flask + SQLite |
| Frontend | Bootstrap 5 + Chart.js (CDN) |
| Blocklists | AdGuard SDNSFilter, BlocklistProject |
| OS | Ubuntu 24.04 / Raspberry Pi OS |

---

## Blocklists

| Source | Domains | Category |
|---|---|---|
| AdGuard SDNSFilter | 241,828 | Ads & Trackers |
| BlocklistProject (NSFW) | 500,283 | Adult Content |
| blocklistproject (gambling) | 2,500 | Gambling |
| User-Reported (other) | dynamic | Other (custom blocked) |
| **Total** | **744,612+** | |

---

## Services

Three independent systemd services:

| Service | Unit File | Port | Purpose |
|---|---|---|---|
| DNS Server | `ks-dns.service` | 53 (UDP) | Blocks domains at DNS level, returns redirect A record |
| HTTP Gateway | `ks-gateway.service` | 80 (TCP) | Serves blocked domain notification page |
| Web App | `ks-web.service` | 8080 (TCP) | Dashboard, auth, admin |

All survive SSH disconnection. All auto-start on boot. All auto-restart on failure.

---

## Quick Start

### 1. Clone
```bash
git clone https://github.com/bmzashura/koneksaun-saudavel.git
cd koneksaun-saudavel
```

### 2. Setup Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Initialize Database
```bash
./venv/bin/python -c "from app.database import init_db; init_db('db/koneksaun.db')"
```

### 4. Deploy on Server (one command)
```bash
sudo ./deploy/setup.sh
```

This installs both systemd services (`ks-dns` + `ks-web`), enables them, and starts them.

### 5. Verify
```bash
# DNS blocking — blocked domain returns redirect A record (not NXDOMAIN)
dig @<server-ip> xnxx.com +short
# Expected: 172.17.12.177

# HTTP redirect — blocked domain serves notification page
curl -s -H "Host: xnxx.com" http://<server-ip>/
# Expected: HTML page with "Domain Terblokir" title

# Non-blocked domain — returns real IP (forwarded to upstream DNS)
dig @<server-ip> google.com +short
# Expected: 142.250.x.x (real Google IP)

# Web app
curl http://<server-ip>:8080/health
# Expected: {"service":"koneksaun-saudavel","status":"ok"}
```


### 6. Login to Dashboard
```
URL:      http://<server-ip>:8080/login
Username: admin
Password: admin123
```

---

## Deployment Files

```
deploy/
├── setup.sh              # Install all 3 services (run once)
├── uninstall.sh          # Remove all services
├── ks-dns.service        # DNS server systemd unit
├── ks-web.service        # Web app systemd unit
└── ks-gateway.service    # HTTP gateway systemd unit (port 80)
```

### Service Management
```bash
# Check status
sudo systemctl status ks-dns
sudo systemctl status ks-web
sudo systemctl status ks-gateway

# View logs
sudo journalctl -u ks-dns -f
sudo journalctl -u ks-web -f
sudo journalctl -u ks-gateway -f

# Restart
sudo systemctl restart ks-dns
sudo systemctl restart ks-web
sudo systemctl restart ks-gateway

# Uninstall
sudo ./deploy/uninstall.sh
```

---

## Web Dashboard

| URL | Description |
|---|---|
| `http://<server>:8080/` | Homepage |
| `http://<server>:8080/login` | User login |
| `http://<server>:8080/register` | User registration |
| `http://<server>:8080/dashboard` | User dashboard (after login) |
| `http://<server>:8080/reports/submit` | Submit blocked domain report |
| `http://<server>:8080/admin/reports` | Admin: review reports |
| `http://<server>:8080/admin/users` | Admin: manage users |
| `http://<server>:8080/settings` | Admin: toggle categories, update blocklists |

---

## API Endpoints

### Auth
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/login` | Login |
| POST | `/api/v1/auth/logout` | Logout |
| GET | `/api/v1/auth/me` | Get current user info |

### Reports
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/reports/mine` | List current user's reports |
| POST | `/api/v1/reports` | Submit domain report |
| GET | `/api/v1/reports` | List all reports (admin) |

### Admin
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/admin/reports/{id}/approve` | Approve report |
| POST | `/api/v1/admin/reports/{id}/reject` | Reject report |
| GET | `/api/v1/admin/users` | List all users |
| DELETE | `/api/v1/admin/users/{id}` | Delete user |

### Stats & Categories
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/stats` | Dashboard statistics |
| GET | `/api/v1/categories` | Category list with domain counts |
| POST | `/api/v1/categories/{name}/update-blocklist` | Force re-download blocklist |

---

## Privacy Design

- **No client IP logging**: DNS query logs store domain, category, blocked status only
- **No device tracking**: No whitelist table, no per-device monitoring
- **No external analytics**: All data stays local on the server

---

## Database Schema

| Table | Description |
|---|---|
| `users` | username, password_hash (sha256+salt+pepper), role |
| `reports` | domain, category, reason, status (pending/approved/rejected) |
| `dns_logs` | domain, category, blocked, client_ip, timestamp (DNS query log) |
| `categories` | name, display_name, enabled, domain_count |
| `settings` | key-value config |

---

## Project Status

| Component | Status |
|---|---|
| DNS blocking (744K domains) | ✅ |
| User auth (register/login/logout) | ✅ |
| Domain report submission | ✅ |
| Admin approval workflow | ✅ |
| Systemd services (permanent, auto-restart) | ✅ |
| Privacy-first (no client IP logging) | ✅ |

---

## License

MIT
