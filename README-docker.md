# Koneksaun Saudavel — Docker Deployment

Docker Compose setup untuk deploy DNS blocker + Web dashboard.

## Struktur

```
koneksaun-saudavel/
├── docker-compose.yml
├── dns/
│   ├── Dockerfile
│   ├── dns_server.py
│   ├── update_blocklist.py
│   └── requirements.txt
└── web/
    ├── Dockerfile
    ├── app.py
    └── templates/
        └── ... (HTML templates)
```

## Quick Start

```bash
git clone https://github.com/bmzashura/koneksaun-saudavel.git
cd koneksaun-saudavel
docker compose up -d
```

## Verifikasi

```bash
# DNS blocking test
dig @localhost pornhub.com +short   # should return empty (blocked)

# Web health check
curl http://localhost:8080/health    # {"status": "ok"}
```

## Default Credentials

| Service | Username | Password |
|---|---|---|
| Web Admin | admin | admin123 |
| Web Admin | (register new via UI) | — |

## Ports

| Service | Port | Protocol |
|---|---|---|
| DNS Server | 53 | UDP |
| Web Dashboard | 8080 | TCP |

## Konfigurasi DNS Blocklists (via environment)

```yaml
environment:
  BLOCKLIST_ADS_URL: "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt"
  BLOCKLIST_PORN_URL: "https://github.com/blocklistproject/Lists/raw/master/lists/porn-all.txt"
  BLOCKLIST_GAMBLE_URL: "https://github.com/blocklistproject/Lists/raw/master/lists/gambling-all.txt"
```

## Management

```bash
# View logs
docker compose logs -f ks-dns
docker compose logs -f ks-web

# Restart
docker compose restart

# Stop
docker compose down

# Update blocklists
docker compose exec ks-dns python update_blocklist.py

# Access web container shell
docker compose exec ks-web /bin/bash
```

## Persistensi

| Volume | Path | Description |
|---|---|---|
| `blocklists` | `/app/blocklists` | Cached domain blocklists |
| `dns_logs` | `/app/logs` | DNS query logs |
| `sqlite_db` | `/app/data` | SQLite database |

## Production Notes

1. **Change default admin password** — login ke `/login` dengan `admin/admin123`
2. **Set SECRET_KEY** — environment variable untuk session security
3. **Configure upstream DNS** — edit `UPSTREAM_DNS` di `dns/dns_server.py` jika perlu
4. **Firewall** — pastikan port 53/UDP dan 8080/TCP terbuka
5. **Configure router** — set DNS server ke IP host Docker

## Hardware Requirements

- RAM: 512MB minimum (blocklists ~200MB+ saat load)
- CPU: 1 core cukup untuk ~1000 concurrent DNS queries
- Disk: 1GB untuk blocklists + logs
