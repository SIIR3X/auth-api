#!/bin/bash
# restore-db.sh - Restore an encrypted backup produced by backup-db.sh.
#
# Usage:
#   restore-db.sh -i <age-private-key-file> -f <backup.sql.gz.age> -d <postgres-url> [--force]
#
# Refuses to restore into a database that already contains the `users` table
# unless --force is passed: a restore is destructive, so the expected flow is
# to restore into a FRESH database, verify it, then switch the API over.
#
# See docs/deploy/guides/operations.md section 3 for the full procedure.

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

# -- Safety check: refuse to overwrite an existing database ---------------------

HAS_USERS=$(psql "$DB_URL" -tAc \
    "SELECT count(*) FROM information_schema.tables WHERE table_name = 'users'")

if [[ "$HAS_USERS" != "0" && "$FORCE" != "1" ]]; then
    echo "ERROR: target database already contains a 'users' table." >&2
    echo "Restore into a fresh database, or pass --force to overwrite." >&2
    exit 1
fi

# -- Restore --------------------------------------------------------------------

echo "$(date -Iseconds) [restore] starting from $BACKUP_FILE"

age --decrypt -i "$KEY_FILE" "$BACKUP_FILE" \
    | gunzip \
    | psql --set ON_ERROR_STOP=1 --quiet "$DB_URL"

echo "$(date -Iseconds) [restore] OK"
