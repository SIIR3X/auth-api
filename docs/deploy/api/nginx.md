# Nginx

Previous: [API Deployment](deployment.md) | [Index](../README.md)

## Overview

Nginx sits in front of the Docker container as a reverse proxy. It handles TLS termination, security headers, and rate limiting before requests reach the API.

```
Client -> Nginx (443) -> Docker container (127.0.0.1:3000)
```

The configuration needs nginx 1.25.1 or later (`http2 on;`).

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

Port 3000 must **not** be open - the API is only reachable through Nginx on loopback.

## Configuration notes

### Rate limiting

Two zones mirror the API's own rate limiting as a first line of defense:

| Zone | Limit | Applied to |
|------|-------|------------|
| `api_auth` | 20 req/min | Credential-bearing routes: register, login, refresh, email verification, password reset, 2FA completion, device and authorization code token routes, re-authentication and email change |
| `api_general` | 300 req/min | Every other route, logout and the JWKS included |

The route patterns are anchored on both ends, so `/auth/login-anything` is not
a login route.

Adjust the values to match `RATE_LIMIT_RPM` and `RATE_LIMIT_AUTH_RPM` in `config.prod.env`.

### Trusted proxy

Nginx reaches the container through Docker's port proxy, so the address the API
sees is the gateway of the compose network, not `127.0.0.1`.
`docker-compose.api.yml` pins that network to `172.30.0.0/24`, and
`config.prod.env` sets `TRUSTED_PROXY_CIDRS=172.30.0.1/32`. With any other
value the API ignores `X-Forwarded-For` and every client shares one rate-limit
bucket.

Nginx overwrites `X-Forwarded-For` with the client address instead of appending
to it, so a client cannot inject hops the API would trust.

### Headers

Nginx is the single source of the security headers: it hides the copies the API
sets and adds its own, on every response including the ones it generates (429,
502). The values match the API's, with `preload` added to HSTS.

### Public keys

`/.well-known/jwks.json` has an exact-match location placed before the
hidden-file rule (`location ~ /\.`), which would otherwise deny it and leave
resource servers unable to verify tokens.

### OCSP stapling

Not configured: Let's Encrypt stopped operating OCSP responders in 2025.
