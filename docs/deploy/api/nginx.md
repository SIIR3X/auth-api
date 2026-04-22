# Nginx

Previous: [API Deployment](deployment.md) | [Index](../README.md)

## Overview

Nginx sits in front of the Docker container as a reverse proxy. It handles TLS termination, security headers, and rate limiting before requests reach the API.

```
Client → Nginx (443) → Docker container (127.0.0.1:3000)
```

## 1. Install Nginx and Certbot

```bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx
```

## 2. Obtain a TLS certificate

```bash
sudo certbot certonly --nginx -d api.example.com
```

Certbot automatically renews certificates. Verify the renewal timer is active:

```bash
sudo systemctl status certbot.timer
```

## 3. Deploy the configuration

Copy the config file from the repository and replace the placeholder domain:

```bash
sudo cp /srv/auth-api/nginx/nginx.conf /etc/nginx/sites-available/auth-api
sudo sed -i 's/api.example.com/your-actual-domain.com/g' /etc/nginx/sites-available/auth-api
sudo ln -s /etc/nginx/sites-available/auth-api /etc/nginx/sites-enabled/auth-api
sudo rm -f /etc/nginx/sites-enabled/default
```

Test and reload:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## 4. Open the firewall

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

Port 3000 must **not** be open — the API is only reachable through Nginx on loopback.

## Configuration notes

### Rate limiting

Two zones mirror the API's own rate limiting as a first line of defense:

| Zone | Limit | Applied to |
|------|-------|------------|
| `api_auth` | 20 req/min | `/auth/register`, `/auth/login`, `/auth/refresh`, password and 2FA routes |
| `api_general` | 300 req/min | All other routes |

Adjust the values to match `RATE_LIMIT_RPM` and `RATE_LIMIT_AUTH_RPM` in `config.prod.env`.

### Trusted proxy

Since the API receives requests via Nginx, configure `TRUSTED_PROXY_CIDRS=127.0.0.1/32` in `config.prod.env` so the API resolves the real client IP from `X-Forwarded-For` instead of the loopback address.
