# Nginx

Previous: [API Deployment](deployment.md) | [Index](../README.md)

## Overview

Nginx sits in front of the API instances as a reverse proxy. It handles TLS
termination, security headers, rate limiting and the failover between
instances before requests reach the API.

```
Client -> Nginx (443) -> api-a (127.0.0.1:3001)
                      -> api-b (127.0.0.1:3002)
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

Reload nginx after each renewal, so it serves the new certificate:

```bash
echo 'deploy-hook = nginx -t && systemctl reload nginx' | sudo tee -a /etc/letsencrypt/cli.ini
```

## 3. Deploy the configuration

Copy the config file from the repository and replace the placeholder domain:

```bash
sudo cp /srv/auth-api/releases/auth-api-X.Y.Z/nginx/nginx.conf /etc/nginx/sites-available/auth-api
sudo sed -i 's/api.example.com/your-actual-domain.com/g' /etc/nginx/sites-available/auth-api
sudo ln -s /etc/nginx/sites-available/auth-api /etc/nginx/sites-enabled/auth-api
sudo rm -f /etc/nginx/sites-enabled/default
```

Raise the worker limits in the main configuration (`/etc/nginx/nginx.conf`,
outside the site file: these settings belong to the main and `events`
contexts):

```bash
sudo sed -i 's/^worker_processes .*/worker_processes auto;/' /etc/nginx/nginx.conf
sudo sed -i '/^worker_processes/a worker_rlimit_nofile 65536;' /etc/nginx/nginx.conf
sudo sed -i 's/worker_connections .*/worker_connections 4096;/' /etc/nginx/nginx.conf
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

Ports 3001 and 3002 must **not** be open: the instances are published on
loopback and reached through nginx only.

## Configuration notes

### Rate limiting

Two zones mirror the API's own rate limiting as a first line of defense:

| Zone | Limit | Applied to |
|------|-------|------------|
| `api_auth` | 40 req/min | Credential-bearing routes: register, login, refresh, email verification, password reset, 2FA completion, device and authorization code token routes, re-authentication and email change |
| `api_general` | 600 req/min | Every other route, logout, probes and the JWKS included |

The route patterns are anchored on both ends, so `/auth/login-anything` is not
a login route.

The zones allow twice `RATE_LIMIT_RPM` and `RATE_LIMIT_AUTH_RPM` of
`config.prod.env`: they only absorb floods, and a client over its limit gets the
API's 429 with its `Retry-After`. Change both files together.

### Instances and failover

The upstream lists both instances. An instance that refuses connections or
fails three times is skipped for 10 seconds, and a request that could not reach
one is passed to the other. nginx never resends a `POST`, `PATCH` or `DELETE`
that an instance already received, so a write is never applied twice. During
[a rolling update](../guides/update.md) the instance being replaced stops
accepting connections while it finishes its requests: new requests go to the
other one without an error. Profile L adds `127.0.0.1:3003` and `127.0.0.1:3004`
to the upstream.

### Timeouts

| Location | Proxy timeout | Why |
|----------|--------------:|-----|
| Credential routes and everything else | 35 s | Above the API's 30-second request timeout: a sign-in queued behind Argon2 during a storm completes instead of ending in a 504 the client retries |
| `/live`, `/ready`, `/health` | 5 s | Probes; not logged |
| `/.well-known/jwks.json` | 10 s | |

### Logs

`/var/log/nginx/auth-api.access.log` has one JSON line per request with its
`request_id`, which nginx passes to the API as `X-Request-Id`: the API keeps it
in every log line of that request. The nginx package's logrotate configuration
already covers `/var/log/nginx/*.log`.

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
