# Deploying a New Release

[Index](../README.md)

## Overview

Each release may include:
- A new Docker image (always)
- New migrations (check the release notes)

Always run migrations before restarting the container. If there are no new migrations, skip directly to step 2.

## 1. Run Migrations (if any)

Check the release notes on GitHub to confirm whether the release includes new migrations.

**On the API VPS** — fetch and run migrations from the release asset:

```bash
curl -sL https://github.com/SIIR3X/auth-api/releases/latest/download/migrations.tar.gz \
  | tar -xz -C /dev/shm

DATABASE_URL=$(pass prod/auth-api/database-url) \
  sqlx migrate run --source /dev/shm/migrations

rm -rf /dev/shm/migrations
```

The archive is extracted directly into `/dev/shm` (RAM) — nothing is written to disk.

## 2. Deploy the New Image

**On the API VPS:**

```bash
cd /srv/auth-api

export DATABASE_URL=$(pass prod/auth-api/database-url)
export REDIS_URL=$(pass prod/auth-api/redis-url)
export JWT_SECRET=$(pass prod/auth-api/jwt-secret)
export ENCRYPTION_KEY=$(pass prod/auth-api/encryption-key)
export SMTP_USERNAME=$(pass prod/auth-api/smtp-username)
export SMTP_PASSWORD=$(pass prod/auth-api/smtp-password)
export CAPTCHA_SECRET=$(pass prod/auth-api/captcha-secret)

docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

`up -d` recreates the container only if the image has changed. Downtime is a few seconds.
