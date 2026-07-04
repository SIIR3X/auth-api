#!/bin/bash
# backup-drill.sh - End-to-end test of the backup/restore mechanism.
#
# Validates the full pipeline used in production (pg_dump | gzip | age, then
# restore-db.sh) against throwaway Postgres containers:
#
#   1. start a source Postgres, apply all migrations, insert witness rows
#   2. back it up with a throwaway age key (same pipeline as backup-db.sh)
#   3. start a fresh destination Postgres, restore with restore-db.sh
#   4. compare row counts and spot-check a witness value; exit non-zero on
#      any mismatch
#
# This proves the MECHANISM works. It does not prove production backups are
# usable - that requires the quarterly manual drill with a real backup and
# the offline key (see docs/deploy/guides/operations.md section 3).
#
# Requirements: docker, age, psql. Run from anywhere inside the repo.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRILL_ID="drill-$$"
SRC="auth-backup-${DRILL_ID}-src"
DST="auth-backup-${DRILL_ID}-dst"
WORK_DIR="$(mktemp -d)"
PG_IMAGE="${DRILL_PG_IMAGE:-postgres:17}"
PGUSER=drill
PGPASSWORD=drill
PGDATABASE=drill

command -v docker >/dev/null || { echo "ERROR: docker is required" >&2; exit 1; }
command -v age >/dev/null || { echo "ERROR: age is required" >&2; exit 1; }
command -v age-keygen >/dev/null || { echo "ERROR: age-keygen is required" >&2; exit 1; }
command -v psql >/dev/null || { echo "ERROR: psql is required" >&2; exit 1; }

cleanup() {
    docker rm -f "$SRC" "$DST" >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

log() { echo "$(date -Iseconds) [drill] $*"; }

start_postgres() { # $1 = container name
    docker run -d --name "$1" \
        -e POSTGRES_USER="$PGUSER" -e POSTGRES_PASSWORD="$PGPASSWORD" -e POSTGRES_DB="$PGDATABASE" \
        -p 127.0.0.1::5432 "$PG_IMAGE" >/dev/null
    # Wait for a real host connection, not `pg_isready` inside the container:
    # during initdb Postgres briefly accepts connections, then restarts, so a
    # single in-container probe can pass right before the server goes away.
    local url
    url=$(pg_url "$1")
    for _ in $(seq 1 60); do
        if psql "$url" -c 'SELECT 1' >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "ERROR: $1 did not become ready" >&2
    return 1
}

pg_url() { # $1 = container name
    local port
    port=$(docker port "$1" 5432/tcp | head -1 | awk -F: '{print $NF}')
    echo "postgres://$PGUSER:$PGPASSWORD@127.0.0.1:$port/$PGDATABASE"
}

# -- 1. Source database: migrations + witness data ------------------------------

log "starting source postgres ($PG_IMAGE)"
start_postgres "$SRC"
SRC_URL=$(pg_url "$SRC")

log "applying migrations"
for migration in "$ROOT_DIR"/migrations/*.sql; do
    psql "$SRC_URL" --set ON_ERROR_STOP=1 --quiet -f "$migration" >/dev/null
done

log "inserting witness rows"
psql "$SRC_URL" --set ON_ERROR_STOP=1 --quiet <<'SQL'
INSERT INTO users (username, email, password_hash, status, email_verified_at)
VALUES
  ('drill_user_1', 'drill1@example.com', repeat('x', 60), 'active', NOW()),
  ('drill_user_2', 'drill2@example.com', repeat('y', 60), 'active', NOW());
SQL

count_rows() { # $1 = url, $2 = table
    psql "$1" -tAc "SELECT count(*) FROM $2"
}

SRC_USERS=$(count_rows "$SRC_URL" users)
SRC_ROLES=$(count_rows "$SRC_URL" roles)
SRC_PERMS=$(count_rows "$SRC_URL" permissions)
log "source counts: users=$SRC_USERS roles=$SRC_ROLES permissions=$SRC_PERMS"

# -- 2. Backup with a throwaway age key (same pipeline as backup-db.sh) ---------

log "generating throwaway age key"
age-keygen -o "$WORK_DIR/backup.key" 2>/dev/null
AGE_PUBLIC_KEY=$(age-keygen -y "$WORK_DIR/backup.key")

BACKUP_FILE="$WORK_DIR/drill.sql.gz.age"
log "backing up (pg_dump | gzip | age)"
docker exec "$SRC" pg_dump -U "$PGUSER" "$PGDATABASE" \
    | gzip \
    | age --recipient "$AGE_PUBLIC_KEY" \
    > "$BACKUP_FILE"
log "backup written: $(du -h "$BACKUP_FILE" | cut -f1)"

# -- 3. Restore into a fresh database via the real restore script ---------------

log "starting destination postgres"
start_postgres "$DST"
DST_URL=$(pg_url "$DST")

log "restoring with scripts/restore-db.sh"
"$ROOT_DIR/scripts/restore-db.sh" -i "$WORK_DIR/backup.key" -f "$BACKUP_FILE" -d "$DST_URL"

# -- 4. Verify -------------------------------------------------------------------

FAIL=0
verify() { # $1 = label, $2 = expected, $3 = actual
    if [[ "$2" == "$3" ]]; then
        log "OK   $1: $3"
    else
        log "FAIL $1: expected $2, got $3"
        FAIL=1
    fi
}

verify "users count"       "$SRC_USERS" "$(count_rows "$DST_URL" users)"
verify "roles count"       "$SRC_ROLES" "$(count_rows "$DST_URL" roles)"
verify "permissions count" "$SRC_PERMS" "$(count_rows "$DST_URL" permissions)"
verify "witness row" "drill1@example.com" \
    "$(psql "$DST_URL" -tAc "SELECT email FROM users WHERE username = 'drill_user_1'")"

if [[ "$FAIL" != "0" ]]; then
    log "DRILL FAILED"
    exit 1
fi

log "DRILL PASSED - backup/restore mechanism verified"
