#!/usr/bin/env bash
# Write the API's secrets, exported from pass as in docs/deploy/guides/update.md,
# to the files docker-compose.api.yml mounts as compose secrets. The instances
# read each variable X from the file named by X_FILE: the values appear neither
# in `docker inspect` nor in the process environment.
#
# Files live in AUTH_API_SECRETS_DIR (/etc/auth-api/secrets by default): a
# directory only root enters, files only the image's user (65532) reads, like
# nats-auth.conf. They survive a reboot, so Docker can restart the instances.
# An optional secret left unexported is written empty and counts as unset.
#
# Usage (as the operator, with sudo):
#   export DATABASE_URL=$(pass prod/auth-api/database-url) ...
#   scripts/write-secrets.sh
set -euo pipefail

DIR=${AUTH_API_SECRETS_DIR:-/etc/auth-api/secrets}
APP_UID=${AUTH_API_UID:-65532}
DIR_OWNER=${AUTH_API_SECRETS_DIR_OWNER:-root}
SUDO=${SUDO-sudo}

REQUIRED=(DATABASE_URL REDIS_URL JWT_PRIVATE_KEY JWT_PUBLIC_KEY ENCRYPTION_KEY
  SMTP_USERNAME SMTP_PASSWORD CAPTCHA_SECRET NATS_URL METRICS_TOKEN)
OPTIONAL=(JWT_PREVIOUS_PUBLIC_KEY JWT_NEXT_PUBLIC_KEY PREVIOUS_ENCRYPTION_KEY)

missing=()
for name in "${REQUIRED[@]}"; do
  [[ -n "${!name:-}" ]] || missing+=("$name")
done
if ((${#missing[@]})); then
  echo "write-secrets: export ${missing[*]} first (docs/deploy/guides/update.md)" >&2
  exit 1
fi

$SUDO install -d -m 700 -o "$DIR_OWNER" -g "$DIR_OWNER" "$DIR"
for name in "${REQUIRED[@]}" "${OPTIONAL[@]}"; do
  file="$DIR/$(tr '[:upper:]' '[:lower:]' <<<"$name")"
  printf '%s' "${!name:-}" | $SUDO install -m 400 -o "$APP_UID" -g "$APP_UID" /dev/stdin "$file"
done
echo "write-secrets: ${#REQUIRED[@]} required and ${#OPTIONAL[@]} optional secrets written to $DIR"
