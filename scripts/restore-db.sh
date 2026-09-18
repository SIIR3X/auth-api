#!/bin/bash
# restore-db.sh - Restore an encrypted backup produced by backup-db.sh.
#
# Usage:
#   restore-db.sh -i <age-private-key-file> -f <backup.sql.gz.age> -d <postgres-url> [--force]
#
# Connect as the application's role (auth_api), owner of the target database:
# the dump assigns every object to it. The restore runs in a single transaction,
# so a failure leaves the target as it was.
#
# A database that already holds the `users` table is refused: a restore is
# destructive, and the expected flow is to restore into a FRESH database,
# verify it, then point the API at it. --force empties the target (its public
# schema is dropped and recreated) before restoring.
#
# See docs/deploy/database/deployment.md, section 4.

set -euo pipefail

usage() {
    grep '^#' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

KEY_FILE=""
BACKUP_FILE=""
DB_URL=""
FORCE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i) KEY_FILE="$2"; shift 2 ;;
        -f) BACKUP_FILE="$2"; shift 2 ;;
        -d) DB_URL="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        *) usage ;;
    esac
done

[[ -n "$KEY_FILE" && -n "$BACKUP_FILE" && -n "$DB_URL" ]] || usage
[[ -r "$KEY_FILE" ]] || { echo "ERROR: cannot read key file: $KEY_FILE" >&2; exit 1; }
[[ -r "$BACKUP_FILE" ]] || { echo "ERROR: cannot read backup file: $BACKUP_FILE" >&2; exit 1; }

command -v age >/dev/null || { echo "ERROR: age is not installed" >&2; exit 1; }
command -v psql >/dev/null || { echo "ERROR: psql is not installed" >&2; exit 1; }

log() { echo "$(date -Iseconds) [restore] $*"; }

# -- Safety check: refuse to overwrite an existing database ---------------------

HAS_USERS=$(psql "$DB_URL" -tAc \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users'")

if [[ "$HAS_USERS" != "0" ]]; then
    if [[ "$FORCE" != "1" ]]; then
        echo "ERROR: target database already contains a 'users' table." >&2
        echo "Restore into a fresh database, or pass --force to overwrite." >&2
        exit 1
    fi
    log "emptying the target database (--force)"
    psql "$DB_URL" --set ON_ERROR_STOP=1 --quiet \
        -c 'DROP SCHEMA public CASCADE' -c 'CREATE SCHEMA public'
fi

# -- Restore --------------------------------------------------------------------

log "starting from $BACKUP_FILE"

age --decrypt -i "$KEY_FILE" "$BACKUP_FILE" \
    | gunzip \
    | psql --set ON_ERROR_STOP=1 --single-transaction --quiet "$DB_URL"

# -- Check ----------------------------------------------------------------------

MIGRATION=$(psql "$DB_URL" -tAc \
    "SELECT max(version) FROM _sqlx_migrations WHERE success" 2>/dev/null || true)
if [[ -n "$MIGRATION" ]]; then
    log "OK - schema at migration $MIGRATION"
else
    log "OK - WARNING: no _sqlx_migrations table; this dump was not migrated by sqlx"
fi
