#!/usr/bin/env bash
# Write the API's secrets, exported from pass as in docs/deploy/guides/update.md,
# to the files docker-compose.api.yml mounts as compose secrets. The instances
# read each variable X from the file named by X_FILE: the values appear neither
# in `docker inspect` nor in the process environment.
#
# Files live in AUTH_API_SECRETS_DIR (/etc/auth-api/secrets by default): a
# directory only root enters, files only the image's user (65532) reads, like
# nats-auth.conf. They survive a reboot, so Docker can restart the instances.
# An optional secret without a value is written empty and counts as unset.
#
# Each value is read from pass (prod/auth-api/<name>, PASS_PREFIX to change it)
# straight into its file: it never sits in an exported variable, where every
# process the operator's shell starts could read it. A variable that is set
# takes precedence (tests, other secret stores).
#
# Usage (as the operator, with sudo):
#   scripts/write-secrets.sh
set -euo pipefail

DIR=${AUTH_API_SECRETS_DIR:-/etc/auth-api/secrets}
APP_UID=${AUTH_API_UID:-65532}
DIR_OWNER=${AUTH_API_SECRETS_DIR_OWNER:-root}
SUDO=${SUDO-sudo}
PASS_PREFIX=${PASS_PREFIX:-prod/auth-api}

REQUIRED=(DATABASE_URL REDIS_URL JWT_PRIVATE_KEY JWT_PUBLIC_KEY ENCRYPTION_KEY
  SMTP_USERNAME SMTP_PASSWORD CAPTCHA_SECRET NATS_URL METRICS_TOKEN)
OPTIONAL=(JWT_PREVIOUS_PUBLIC_KEY JWT_NEXT_PUBLIC_KEY PREVIOUS_ENCRYPTION_KEY)

# The value of a secret: its variable if set, else its pass entry, else empty.
value_of() {
  local name=$1
  if [[ -n "${!name:-}" ]]; then
    printf '%s' "${!name}"
  elif command -v pass >/dev/null 2>&1; then
    # A local, unexported variable: trailing newlines go, as with `$(pass ...)`.
    local value
    value=$(pass show "$PASS_PREFIX/$(tr '[:upper:]_' '[:lower:]-' <<<"$name")" 2>/dev/null || true)
    printf '%s' "$value"
  fi
}

missing=()
for name in "${REQUIRED[@]}"; do
  [[ -n "$(value_of "$name" | head -c 1)" ]] || missing+=("$name")
done
if ((${#missing[@]})); then
  echo "write-secrets: no value for ${missing[*]} in pass ($PASS_PREFIX) (docs/deploy/guides/update.md)" >&2
  exit 1
fi

$SUDO install -d -m 700 -o "$DIR_OWNER" -g "$DIR_OWNER" "$DIR"
for name in "${REQUIRED[@]}" "${OPTIONAL[@]}"; do
  file="$DIR/$(tr '[:upper:]' '[:lower:]' <<<"$name")"
  value_of "$name" | $SUDO install -m 400 -o "$APP_UID" -g "$APP_UID" /dev/stdin "$file"
done
echo "write-secrets: ${#REQUIRED[@]} required and ${#OPTIONAL[@]} optional secrets written to $DIR"
