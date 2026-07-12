# Koneksaun Saudavel

DNS-based content blocker. Blokir iklan, porn, dan gambling di seluruh jaringan.

**744,574+ domain** diblokir. Tidak perlu install software di client.

---

## Install (2 langkah)

```bash
git clone https://github.com/bmzashura/koneksaun-saudavel.git
cd koneksaun-saudavel
sudo bash deploy/setup.sh
```

Cek hasilnya:

```bash
sudo systemctl status ks-dns ks-web
```

---

## Login Dashboard

```
URL:     http://<server-ip>:8080/login
Akun:    admin
Password: admin123
```

---

## Ganti Password Admin

1. Login ke dashboard
2. Pilih menu **Settings** → **Admin Settings**
3. Ganti password

---

## Troubleshooting

### `Permission denied` atau `command not found`

```bash
# SALAH:
./setup.sh
bash ./setup.sh

# BENAR:
sudo bash deploy/setup.sh
```

### Service tidak aktif

```bash
sudo systemctl restart ks-dns ks-web
sudo systemctl status ks-dns ks-web
```

### Cek log

```bash
sudo journalctl -u ks-dns -n 30 --no-pager
sudo journalctl -u ks-web -n 30 --no-pager
```

---

## Update ke Versi Terbaru

```bash
cd ~/koneksaun-saudavel
git pull
sudo systemctl restart ks-dns ks-web
```

---

## Uninstall

```bash
sudo bash deploy/uninstall.sh
```
