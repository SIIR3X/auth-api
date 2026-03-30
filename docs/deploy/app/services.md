# Service Deployment

[Previous: Nginx and HTTPS](nginx.md) | [Back to setup](setup.md) | [Next: Observability](monitoring.md)

## 1. Create the directories

```bash
sudo mkdir -p /srv/rust-api/compose
sudo mkdir -p /srv/rust-api/env
sudo mkdir -p /srv/rust-api/data
```

## 2. Prepare GeoIP data

If you use GeoIP, place `GeoLite2-City.mmdb` in:

```text
/srv/rust-api/data/GeoLite2-City.mmdb
```

If you do not use GeoIP, set `GEOIP_REQUIRED=false` in `runtime.env`.

## 3. Create the `pass` entries

On the application server:

```bash
pass insert rust-api/app/database_url
pass insert rust-api/app/redis_url
pass insert rust-api/app/jwt_secret
pass insert rust-api/app/encryption_key
pass insert rust-api/app/smtp_username
pass insert rust-api/app/smtp_password
pass insert rust-api/app/captcha_secret
```

Optional:

```bash
pass insert rust-api/app/jwt_previous_secret
pass insert rust-api/app/previous_encryption_key
```

`database_url` and `redis_url` must already point to the private data services.

## 4. Create `runtime.env`

```bash
sudo nano /srv/rust-api/env/runtime.env
```

Use [runtime.env.example](../../../deploy/app/runtime.env.example) as the reference.

Set at least:

```text
APP_ENV=production
SERVER_HOST=0.0.0.0
SERVER_PORT=3000
APP_PUBLIC_URL=https://__APP_DOMAIN__
TRUSTED_PROXY_CIDRS=127.0.0.1/32,172.16.0.0/12

GEOIP_DB_PATH=/app/data/GeoLite2-City.mmdb
GEOIP_REQUIRED=false

SMTP_HOST=__SMTP_HOST__
SMTP_PORT=587
SMTP_FROM_NAME=__SMTP_FROM_NAME__
SMTP_FROM_ADDRESS=__SMTP_FROM_ADDRESS__

CORS_ALLOWED_ORIGINS=https://__FRONTEND_DOMAIN__
CORS_ALLOW_CREDENTIALS=true

WEBAUTHN_RP_ID=__APP_DOMAIN__
WEBAUTHN_RP_ORIGIN=https://__APP_DOMAIN__
WEBAUTHN_RP_NAME=__APP_NAME__

LOG_LEVEL=info
LOG_FORMAT=json
```

## 5. Create the application compose file

```bash
sudo nano /srv/rust-api/compose/docker-compose.yml
```

Use [docker-compose.yml](../../../deploy/app/docker-compose.yml) as the reference.

## 6. Export the secrets and runtime variables

```bash
export DATABASE_URL="$(pass show rust-api/app/database_url)"
export REDIS_URL="$(pass show rust-api/app/redis_url)"
export JWT_SECRET="$(pass show rust-api/app/jwt_secret)"
export ENCRYPTION_KEY="$(pass show rust-api/app/encryption_key)"
export SMTP_USERNAME="$(pass show rust-api/app/smtp_username 2>/dev/null || true)"
export SMTP_PASSWORD="$(pass show rust-api/app/smtp_password 2>/dev/null || true)"
export CAPTCHA_SECRET="$(pass show rust-api/app/captcha_secret 2>/dev/null || true)"
export JWT_PREVIOUS_SECRET="$(pass show rust-api/app/jwt_previous_secret 2>/dev/null || true)"
export PREVIOUS_ENCRYPTION_KEY="$(pass show rust-api/app/previous_encryption_key 2>/dev/null || true)"
export RUST_API_IMAGE=ghcr.io/<owner>/rust-api:<tag>
export RUST_API_RUNTIME_ENV_FILE=/srv/rust-api/env/runtime.env
export RUST_API_BIND_IP=127.0.0.1
export RUST_API_BIND_PORT=3000
export RUST_API_DATA_DIR=/srv/rust-api/data
```

## 7. Start the service

```bash
docker compose \
  -f /srv/rust-api/compose/docker-compose.yml \
  pull

docker compose \
  -f /srv/rust-api/compose/docker-compose.yml \
  up -d
```

## 8. Validate locally and through Nginx

```bash
cd /srv/rust-api/compose
docker compose ps
docker compose logs app --tail 50
ss -ltnp | grep ':3000'
curl -I http://127.0.0.1:3000
curl -I https://__APP_DOMAIN__
```
