# API Deployment

Previous: [Database Deployment](../database/deployment.md) | [Index](../README.md) | Next: [Nginx](nginx.md)

## Overview

The API runs from a release bundle built with `make release` (see
[Creating a Release](../../dev/guides/release.md)). The server needs Docker and
`sqlx-cli` for migrations - no source code and no registry.

```
trusted machine: make ci && make release VERSION=X.Y.Z
    |
scp dist/auth-api-X.Y.Z -> API VPS
    |
API VPS: verify checksums, docker load, migrate, docker compose up -d
```

The NATS event broker ships in `docker-compose.api.yml` and starts with the
API. Nginx runs on the host as the reverse proxy (see [Nginx](nginx.md)); the
API and its metrics listener are published on loopback only.

## 1. Initial Setup

### 1.1 Open the firewall

**On the API VPS** - HTTP and HTTPS for nginx. The WireGuard tunnel to the DB
VPS is opened from this side, so no WireGuard port is needed here:

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

---

### 1.2 Install Docker and sqlx-cli

```bash
curl -fsSL https://get.docker.com | sh
```

Build `sqlx` on a machine with Rust and copy the binary to the server:

```bash
cargo install sqlx-cli --no-default-features --features rustls,postgres --locked
scp ~/.cargo/bin/sqlx api-vps:/usr/local/bin/sqlx
```

---

### 1.3 Copy and verify the bundle

```bash
# On the trusted machine
scp -r dist/auth-api-X.Y.Z api-vps:/srv/auth-api/releases/

# On the API VPS, once: the public release key, never taken from a bundle
echo "release $(cat auth-api-release.pub)" > /srv/auth-api/allowed_signers

# On the API VPS, for every bundle
cd /srv/auth-api/releases/auth-api-X.Y.Z
ssh-keygen -Y verify -f /srv/auth-api/allowed_signers -I release \
  -n auth-api-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c SHA256SUMS
gunzip -c auth-api-X.Y.Z.image.tar.gz | docker load
test "$(docker image inspect --format '{{.Id}}' auth-api:X.Y.Z)" = "$(cat IMAGE_ID)" \
  && echo "image matches the signed bundle"
```

The signature proves `SHA256SUMS` was written by the release key; the checksums
prove every file matches it, and `IMAGE_ID` that the loaded image is the one
that was scanned. Stop at the first command that fails.

---

### 1.4 Configure

Copy the deployment files next to each other and fill in the non-sensitive
values:

```bash
mkdir -p /srv/auth-api && cd /srv/auth-api
cp releases/auth-api-X.Y.Z/docker-compose.api.yml releases/auth-api-X.Y.Z/config.prod.env \
   releases/auth-api-X.Y.Z/nats.conf releases/auth-api-X.Y.Z/scripts/rolling-update.sh .
cp releases/auth-api-X.Y.Z/deploy/profiles/m.env profile.env   # s.env, m.env, l.env or xl.env
# Profile L: also copy docker-compose.api.l.yml
nano config.prod.env
```

Values to set:

- `APP_PUBLIC_URL`, `FRONTEND_URL`, `CORS_ALLOWED_ORIGINS`, `JWT_AUDIENCE`
- `DEVICE_AUTH_VERIFICATION_URI`
- `SMTP_HOST`, `SMTP_FROM_ADDRESS`, `TOTP_ISSUER`
- `ARGON2_*` for the server's memory and cores
- `TRUSTED_PROXY_CIDRS` stays `172.30.0.1/32` (the compose network gateway, see [Nginx](nginx.md#trusted-proxy))

The instance sizes (CPU, memory, Argon2 concurrency, pool sizes, broker limits)
live in `profile.env`: pick the profile of the expected load from the
[capacity planning](../guides/operations.md#9-capacity-planning), and adjust
the copy rather than `config.prod.env`.

---

### 1.5 Run the migrations

```bash
DATABASE_URL=$(pass prod/auth-api/database-url) \
  sqlx migrate run --source /srv/auth-api/releases/auth-api-X.Y.Z/migrations
```

---

### 1.6 Export secrets and start

```bash
cd /srv/auth-api
export AUTH_API_VERSION=X.Y.Z
export DATABASE_URL=$(pass prod/auth-api/database-url)
export REDIS_URL=$(pass prod/auth-api/redis-url)
export JWT_PRIVATE_KEY=$(pass prod/auth-api/jwt-private-key)
export JWT_PUBLIC_KEY=$(pass prod/auth-api/jwt-public-key)
export ENCRYPTION_KEY=$(pass prod/auth-api/encryption-key)
export SMTP_USERNAME=$(pass prod/auth-api/smtp-username)
export SMTP_PASSWORD=$(pass prod/auth-api/smtp-password)
export CAPTCHA_SECRET=$(pass prod/auth-api/captcha-secret)
export NATS_URL=$(pass prod/auth-api/nats-url)
# Owned by root: the broker runs without capabilities (see Secrets)
sudo install -m 600 -o root -g root /dev/null nats-auth.conf
printf 'authorization { token: "%s" }\n' "$(pass prod/auth-api/nats-auth-token)" \
  | sudo tee nats-auth.conf > /dev/null

docker compose --env-file profile.env -f docker-compose.api.yml up -d --wait
curl -fsS http://127.0.0.1:3001/ready && curl -fsS http://127.0.0.1:3002/ready
```

Both instances must answer `/ready` before nginx is pointed at them.

---

### 1.7 Register the client applications

Device and authorization code flows only serve registered clients. Register the
application this instance owns as primary, then any other client:

```bash
docker compose --env-file profile.env -f docker-compose.api.yml run --rm --no-deps api-a \
  ./auth-api --register-client web-app --name "Web app" --primary \
  --redirect-uri https://app.example.com/callback
```

Options are listed in [Commands](../../dev/guides/commands.md#binary-commands).
