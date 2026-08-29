# Deploying a New Release

[Index](../README.md)

## Overview

Read the release's entry in `CHANGELOG.md` first: it lists breaking changes and
the configuration to add. Migrations always run before the new image starts;
they are written to be compatible with the previous version still running.

## 1. Copy and verify the bundle

```bash
# On the trusted machine
scp -r dist/auth-api-X.Y.Z api-vps:/srv/auth-api/releases/

# On the API VPS
cd /srv/auth-api/releases/auth-api-X.Y.Z
sha256sum SHA256SUMS          # compare with the value recorded at build time
sha256sum -c SHA256SUMS
gunzip -c auth-api-X.Y.Z.image.tar.gz | docker load
```

## 2. Update the deployment files

Compare the bundle's `docker-compose.api.yml` and `config.prod.env` with the
ones in `/srv/auth-api` and carry over new or changed settings:

```bash
cd /srv/auth-api
diff docker-compose.api.yml releases/auth-api-X.Y.Z/docker-compose.api.yml
diff config.prod.env releases/auth-api-X.Y.Z/config.prod.env
```

## 3. Run the migrations

```bash
DATABASE_URL=$(pass prod/auth-api/database-url) \
  sqlx migrate run --source /srv/auth-api/releases/auth-api-X.Y.Z/migrations
```

## 4. Start the new version

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
export NATS_AUTH_TOKEN=$(pass prod/auth-api/nats-auth-token)

docker compose -f docker-compose.api.yml up -d
curl -fsS http://127.0.0.1:3000/health
```

The container is recreated because the image tag changed; downtime is a few
seconds.

## Rolling back

Start the previous tag again (`AUTH_API_VERSION=<previous>`, `up -d`). Migrations
are not rolled back: each one is written so the previous version keeps working
with the new schema. The changelog calls out a release after which rolling back
is not possible.
