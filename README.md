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
Client Device
     │
     ▼
Python DNS Server (0.0.0.0:53) ──► Blocklist Match
     │                              │
     │                          NXDOMAIN    Forward to 1.1.1.1 / 8.8.8.8
     │                          (blocked)   (allowed)
     ▼
[No CoreDNS needed — Python DNS binds directly to port 53]
```

- **Port 53**: Python DNS server (authoritative, handles all DNS queries)
- **Port 8080**: Flask web app (dashboard, auth, reports, admin)
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

Two independent systemd services:

| Service | Unit File | Port | Purpose |
|---|---|---|---|
| DNS Server | `ks-dns.service` | 53 (UDP) | Blocks domains at DNS level |
| Web App | `ks-web.service` | 8080 (TCP) | Dashboard, auth, admin |

Both survive SSH disconnection. Both auto-start on boot. Both auto-restart on failure.

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
# DNS blocking — must return NXDOMAIN
dig @<server-ip> pornhub.com +short
# Expected: (empty / NXDOMAIN)

# Web app — must return JSON
curl http://<server-ip>:8080/health
# Expected: {"service":"koneksaun-saudavel","status":"ok"}
```

---

## Deployment Files

```
deploy/
├── setup.sh          # Install both services (run once)
├── uninstall.sh       # Remove all services
├── ks-dns.service    # DNS server systemd unit
└── ks-web.service    # Web app systemd unit
```

### Service Management
```bash
# Check status
sudo systemctl status ks-dns
sudo systemctl status ks-web

# View logs
sudo journalctl -u ks-dns -f
sudo journalctl -u ks-web -f

# Restart
sudo systemctl restart ks-dns
sudo systemctl restart ks-web

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
