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

## 2. Update the deployment files

Compare the bundle's deployment files with the ones in `/srv/auth-api`, carry
over new or changed settings into `config.prod.env` and `profile.env`, and
install the files you do not edit:

```bash
cd /srv/auth-api
R=releases/auth-api-X.Y.Z
diff config.prod.env $R/config.prod.env
diff profile.env $R/deploy/profiles/m.env           # the profile this server uses
for f in docker-compose.api.yml nats.conf; do diff "$f" "$R/$f"; done
cp $R/docker-compose.api.yml $R/nats.conf $R/scripts/rolling-update.sh .
# Profile L only:
cp $R/docker-compose.api.l.yml .
```

A change to `nats.conf` or to the broker's service restarts the broker during
the update; the instances reconnect, and events published meanwhile are dropped
(see [the operations runbook](operations.md#11-nats-and-smtp-outages)).

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
# Only while a key rotation is in progress (see the operations runbook); unset
# otherwise. An empty value is treated as unset.
export JWT_PREVIOUS_PUBLIC_KEY=$(pass prod/auth-api/jwt-previous-public-key 2>/dev/null)
export JWT_NEXT_PUBLIC_KEY=$(pass prod/auth-api/jwt-next-public-key 2>/dev/null)
export PREVIOUS_ENCRYPTION_KEY=$(pass prod/auth-api/previous-encryption-key 2>/dev/null)
export SMTP_USERNAME=$(pass prod/auth-api/smtp-username)
export SMTP_PASSWORD=$(pass prod/auth-api/smtp-password)
export CAPTCHA_SECRET=$(pass prod/auth-api/captcha-secret)
export NATS_URL=$(pass prod/auth-api/nats-url)

./rolling-update.sh
```

`rolling-update.sh` recreates the instances one at a time and moves on only
once the new one is healthy and answers `/ready`. The instance being replaced
finishes its requests (up to 32 seconds) while nginx sends new ones to the
other: the update causes no downtime. If the new version does not become
ready, the script stops and the remaining instances keep serving the previous
version; roll back as below.

## Rolling back

Run the rolling update again with the previous tag (`AUTH_API_VERSION=<previous> ./rolling-update.sh`). Migrations
are not rolled back: each one is written so the previous version keeps working
with the new schema. The changelog calls out a release after which rolling back
is not possible.
