#!/bin/bash
# backup-drill.sh - End-to-end test of the backup/restore mechanism.
#
# Reproduces production against throwaway Postgres containers:
#
#   1. a source database owned by a non-superuser `auth_api` role, migrated as
#      that role, with witness rows
#   2. a failed backup (unusable key), which must leave neither a file nor a
#      metric, then a backup through backup-db.sh itself (pg_dump as a
#      superuser | gzip | age, atomic write, textfile metrics)
#   3. a restore with restore-db.sh, connected as a non-superuser `auth_api`,
#      into a fresh database; a second restore without --force, which must be
#      refused; a third with --force over the restored database
#   4. after each restore, the row count of every table compared with the source
#
# This proves the MECHANISM works. It does not prove production backups are
# usable: that takes the quarterly drill with a real backup and the offline key
# (docs/deploy/database/deployment.md, section 4).
#
# Requirements: docker, age, age-keygen, psql. Run from anywhere inside the repo.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRILL_ID="drill-$$"
SRC="auth-backup-${DRILL_ID}-src"
DST="auth-backup-${DRILL_ID}-dst"
WORK_DIR="$(mktemp -d)"
PG_IMAGE="${DRILL_PG_IMAGE:-postgres:17}"
SUPERUSER=drill
SUPERPASS=drill
APP_PASS=drill-app

for tool in docker age age-keygen psql; do
    command -v "$tool" >/dev/null || { echo "ERROR: $tool is required" >&2; exit 1; }
done

cleanup() {
    docker rm -f "$SRC" "$DST" >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

log() { echo "$(date -Iseconds) [drill] $*"; }

pg_url() { # $1 = container, $2 = user, $3 = password, $4 = database
    local port
    port=$(docker port "$1" 5432/tcp | head -1 | awk -F: '{print $NF}')
    echo "postgres://$2:$3@127.0.0.1:$port/$4"
}

start_postgres() { # $1 = container name
    docker run -d --name "$1" \
        -e POSTGRES_USER="$SUPERUSER" -e POSTGRES_PASSWORD="$SUPERPASS" -e POSTGRES_DB=postgres \
        -p 127.0.0.1::5432 "$PG_IMAGE" >/dev/null
    # Wait for a real host connection, not `pg_isready` inside the container:
    # during initdb Postgres briefly accepts connections, then restarts.
    local url
    url=$(pg_url "$1" "$SUPERUSER" "$SUPERPASS" postgres)
    for _ in $(seq 1 60); do
        if psql "$url" -c 'SELECT 1' >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "ERROR: $1 did not become ready" >&2
    return 1
}

create_app_database() { # $1 = container: the role and database of section 2.1
    psql "$(pg_url "$1" "$SUPERUSER" "$SUPERPASS" postgres)" --set ON_ERROR_STOP=1 --quiet \
        -c "CREATE ROLE auth_api LOGIN PASSWORD '$APP_PASS'" \
        -c "CREATE DATABASE auth_api OWNER auth_api"
}

tables() { # $1 = url
    psql "$1" -tAc "SELECT table_name FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1"
}

FAIL=0
verify() { # $1 = label, $2 = expected, $3 = actual
    if [[ "$2" == "$3" ]]; then
        log "OK   $1: $3"
    else
        log "FAIL $1: expected $2, got $3"
        FAIL=1
    fi
}

verify_counts() { # $1 = label, $2 = destination url
    local table
    verify "$1: tables" "$(tables "$SRC_URL" | tr '\n' ' ')" "$(tables "$2" | tr '\n' ' ')"
    for table in $(tables "$SRC_URL"); do
        verify "$1: rows in $table" \
            "$(psql "$SRC_URL" -tAc "SELECT count(*) FROM \"$table\"")" \
            "$(psql "$2" -tAc "SELECT count(*) FROM \"$table\"")"
    done
    verify "$1: witness row" "drill1@example.com" \
        "$(psql "$2" -tAc "SELECT email FROM users WHERE username = 'drill_user_1'")"
}

# -- 1. Source database ---------------------------------------------------------

log "starting source postgres ($PG_IMAGE)"
start_postgres "$SRC"
create_app_database "$SRC"
SRC_URL=$(pg_url "$SRC" auth_api "$APP_PASS" auth_api)

log "applying migrations as auth_api"
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

# -- 2. Backups through backup-db.sh --------------------------------------------

age-keygen -o "$WORK_DIR/backup.key" 2>/dev/null
AGE_PUBLIC_KEY=$(age-keygen -y "$WORK_DIR/backup.key")
mkdir -p "$WORK_DIR/textfile"
backup() { # $1 = age public key
    BACKUP_CONFIG=/nonexistent DB_NAME=auth_api AGE_PUBLIC_KEY="$1" \
        BACKUP_DIR="$WORK_DIR/backups" TEXTFILE_DIR="$WORK_DIR/textfile" \
        PG_DUMP="docker exec $SRC pg_dump -U $SUPERUSER" \
        "$ROOT_DIR/scripts/backup-db.sh"
}

log "a backup that cannot be encrypted must leave nothing behind"
if backup "age1notavalidrecipient" >/dev/null 2>&1; then
    verify "failed backup exit status" "non-zero" "0"
fi
verify "failed backup files" "0" "$(find "$WORK_DIR/backups" -type f 2>/dev/null | wc -l | tr -d ' ')"
verify "failed backup metrics" "0" "$(find "$WORK_DIR/textfile" -type f | wc -l | tr -d ' ')"

log "backing up with scripts/backup-db.sh"
backup "$AGE_PUBLIC_KEY"
BACKUP_FILE=$(find "$WORK_DIR/backups" -name '*.sql.gz.age' | head -1)
verify "backup files" "1" "$(find "$WORK_DIR/backups" -type f | wc -l | tr -d ' ')"
verify "success metric written" "1" "$(grep -c '^auth_backup_last_success_timestamp ' "$WORK_DIR/textfile/auth_backup.prom")"

# -- 3. Restores into a fresh database, as a non-superuser ----------------------

log "starting destination postgres"
start_postgres "$DST"
create_app_database "$DST"
DST_URL=$(pg_url "$DST" auth_api "$APP_PASS" auth_api)

log "restoring with scripts/restore-db.sh as auth_api"
"$ROOT_DIR/scripts/restore-db.sh" -i "$WORK_DIR/backup.key" -f "$BACKUP_FILE" -d "$DST_URL"
verify_counts "restore" "$DST_URL"

log "a second restore without --force must be refused"
if "$ROOT_DIR/scripts/restore-db.sh" -i "$WORK_DIR/backup.key" -f "$BACKUP_FILE" -d "$DST_URL" >/dev/null 2>&1; then
    verify "restore over a database without --force" "refused" "accepted"
fi

log "restoring again with --force"
"$ROOT_DIR/scripts/restore-db.sh" -i "$WORK_DIR/backup.key" -f "$BACKUP_FILE" -d "$DST_URL" --force
verify_counts "forced restore" "$DST_URL"

if [[ "$FAIL" != "0" ]]; then
    log "DRILL FAILED"
    exit 1
fi

log "DRILL PASSED - backup/restore mechanism verified"
