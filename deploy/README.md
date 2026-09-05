# Deploy

Single-VM production deployment of Threat Watcher.

## Layout on host

```
/opt/threat-watcher/         # this repo, owned by `threatwatcher` user
/var/log/threat-watcher/     # logs (LOG_FILE in each .env points here)
/etc/letsencrypt/...         # TLS certs (certbot)
```

## One-time setup

```bash
# System user (no shell)
sudo useradd --system --shell /usr/sbin/nologin --home /opt/threat-watcher threatwatcher

# Repo
sudo git clone <repo> /opt/threat-watcher
sudo chown -R threatwatcher: /opt/threat-watcher

# Node 20 + Python 3.9 + Tor + MongoDB (Ubuntu 22.04 example)
sudo apt install nodejs npm python3.9 python3-pip tor mongodb-org nginx

# Install deps
sudo -u threatwatcher npm --prefix /opt/threat-watcher/backend  ci --omit=dev
sudo -u threatwatcher npm --prefix /opt/threat-watcher/frontend ci --omit=dev
sudo -u threatwatcher python3.9 -m pip install -r /opt/threat-watcher/backend/ml/requirements.txt

# Logs
sudo mkdir -p /var/log/threat-watcher
sudo chown threatwatcher: /var/log/threat-watcher

# .env files (copy from .env.example, fill secrets)
sudo -u threatwatcher cp /opt/threat-watcher/backend/.env.example  /opt/threat-watcher/backend/.env
sudo -u threatwatcher cp /opt/threat-watcher/frontend/.env.example /opt/threat-watcher/frontend/.env
```

## Choose your process supervisor

### Option A — systemd (recommended)

```bash
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo cp deploy/systemd/*.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now threat-watcher-backend.service
sudo systemctl enable --now threat-watcher-frontend.service
sudo systemctl enable --now threat-watcher-crawl.timer
```

Logs: `journalctl -u threat-watcher-backend -f`.

### Option B — PM2

```bash
sudo -u threatwatcher npm i -g pm2
sudo -u threatwatcher pm2 start /opt/threat-watcher/deploy/pm2.ecosystem.config.js --env production
sudo -u threatwatcher pm2 save
sudo env PATH=$PATH:/usr/bin pm2 startup systemd -u threatwatcher --hp /opt/threat-watcher
```

## nginx + TLS

```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/threat-watcher.conf
sudo ln -s /etc/nginx/sites-available/threat-watcher.conf /etc/nginx/sites-enabled/
sudo certbot --nginx -d threatwatcher.example.com -d api.threatwatcher.example.com
sudo nginx -t && sudo systemctl reload nginx
```

The nginx config:

- Terminates TLS, redirects 80 → 443, sets HSTS.
- Reverse-proxies `:4000` → frontend, `:443` (`api.*`) → backend.
- Gates `/metrics` so only the Prometheus host (set `geo $prom_allow`) can scrape it.
- Edit the two `server_name` lines and the `geo $prom_allow` block before applying.

## Tor

Tor runs as a system service: `sudo systemctl enable --now tor`. The crawler script connects via `socks5h://127.0.0.1:9050`. Confirm `127.0.0.1:9050` is open and unbound from the public interface.

## MongoDB

Use Atlas (managed) or local. If local, enable auth (`security.authorization: enabled` in `/etc/mongod.conf`) and create a dedicated user for `threatwatcher`. Update `MONGODB_URI` in `backend/.env`.

## WorkOS in production

Before flipping DNS:

1. In the WorkOS dashboard, add the production redirect URI: `https://threatwatcher.example.com/auth/callback`.
2. Mint a production API key (not the test one) and put it in `backend/.env` and `frontend/.env`.
3. Verify that **AuthKit → Sign-up** is disabled and **MFA → TOTP** is enabled.
4. Set `SESSION_COOKIE_SECURE=true` in `frontend/.env` so the sealed cookie is only sent over TLS.
5. Generate a fresh `SESSION_PASSWORD` (`openssl rand -base64 48`) for prod — never reuse the dev value.
6. Send yourself an admin invitation from the WorkOS dashboard, accept it, then sign in once. The backend auto-promotes you to `role: "admin"` based on your WorkOS roleSlug.

## Health checks

```bash
curl -s https://threatwatcher.example.com/health
curl -s https://api.threatwatcher.example.com/health
```

Both should return `{"ok":true}`. Backend additionally returns mongo + ml readiness:

```bash
curl -s https://api.threatwatcher.example.com/health | jq
```

## Rollback

```bash
sudo systemctl stop threat-watcher-{backend,frontend}.service
# revert deploy
cd /opt/threat-watcher && git checkout <previous-tag>
sudo -u threatwatcher npm --prefix backend  ci --omit=dev
sudo -u threatwatcher npm --prefix frontend ci --omit=dev
sudo systemctl start threat-watcher-{backend,frontend}.service
```
