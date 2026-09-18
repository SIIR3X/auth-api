#!/bin/bash
# backup-db.sh - Encrypted PostgreSQL backup using age.
#
# Produces $BACKUP_DIR/auth_api_YYYYMMDD_HHMMSS.sql.gz.age and, after a complete
# success only (offsite copy included), the node_exporter textfile metrics read
# by the AuthBackupMissing and AuthBackupShrunk alerts.
#
# Configuration, /etc/auth-api/backup.env (docs/deploy/database/deployment.md, section 4):
#   AGE_PUBLIC_KEY=age1...           required; the private key never lives on this server
#   OFFSITE_REMOTE=b2:auth-backups   optional rclone remote:path
#   RETAIN_DAYS=7  OFFSITE_RETAIN_DAYS=30  DB_NAME=auth_api
#   BACKUP_DIR=/var/backups/auth-api  TEXTFILE_DIR=/var/lib/node_exporter/textfile
#
# Schedule (sudo crontab -e):
#   0 2 * * * /opt/auth-api/backup-db.sh >> /var/log/auth-api-backup.log 2>&1
#
# Restore with scripts/restore-db.sh: a bare `| psql` does not stop at the first
# error and leaves a half-restored database.

set -euo pipefail

CONFIG_FILE=${BACKUP_CONFIG:-/etc/auth-api/backup.env}
if [[ -r "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
fi

DB_NAME=${DB_NAME:-auth_api}
BACKUP_DIR=${BACKUP_DIR:-/var/backups/auth-api}
RETAIN_DAYS=${RETAIN_DAYS:-7}
OFFSITE_REMOTE=${OFFSITE_REMOTE:-}
OFFSITE_RETAIN_DAYS=${OFFSITE_RETAIN_DAYS:-30}
TEXTFILE_DIR=${TEXTFILE_DIR:-/var/lib/node_exporter/textfile}
# The dump command, overridable for the drill.
PG_DUMP=${PG_DUMP:-sudo -u postgres pg_dump}

log() { echo "$(date -Iseconds) [backup] $*"; }
fail() { log "ERROR: $*" >&2; exit 1; }

[[ "${AGE_PUBLIC_KEY:-}" == age1* && "${AGE_PUBLIC_KEY}" != *xxxxxxxxxx* ]] \
    || fail "AGE_PUBLIC_KEY is not set to a real age public key (in $CONFIG_FILE)"
command -v age >/dev/null || fail "age is not installed"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/${DB_NAME}_${TIMESTAMP}.sql.gz.age"
PARTIAL="$BACKUP_FILE.partial"
STARTED=$(date +%s)

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
# A failed run leaves nothing that looks like a backup.
trap 'rm -f "$PARTIAL"' EXIT

# Dump, compress, encrypt: nothing unencrypted touches disk, and pipefail makes
# the failure of any stage the failure of the whole.
# shellcheck disable=SC2086
$PG_DUMP "$DB_NAME" | gzip | age --recipient "$AGE_PUBLIC_KEY" > "$PARTIAL"
[[ -s "$PARTIAL" ]] || fail "the backup is empty"
chmod 600 "$PARTIAL"
mv "$PARTIAL" "$BACKUP_FILE"
trap - EXIT
SIZE=$(stat -c %s "$BACKUP_FILE")
log "written $BACKUP_FILE ($SIZE bytes)"

# -- Offsite copy ---------------------------------------------------------------
# The file is already encrypted: the remote never sees plaintext. A backup that
# only lives on this VPS dies with it, so a failed copy fails the run.
if [[ -n "$OFFSITE_REMOTE" ]]; then
    command -v rclone >/dev/null || fail "OFFSITE_REMOTE is set but rclone is not installed"
    rclone copy "$BACKUP_FILE" "$OFFSITE_REMOTE" || fail "offsite copy to $OFFSITE_REMOTE failed"
    log "offsite copy OK - $OFFSITE_REMOTE"
    rclone delete --min-age "${OFFSITE_RETAIN_DAYS}d" "$OFFSITE_REMOTE" \
        || log "WARNING: pruning offsite copies older than ${OFFSITE_RETAIN_DAYS} days failed"
fi

# -- Rotation -----------------------------------------------------------------

find "$BACKUP_DIR" -name "${DB_NAME}_*.sql.gz.age" -mtime +"$RETAIN_DAYS" -delete

# -- Metrics ------------------------------------------------------------------
# Written last and atomically: they only ever describe a complete success.
if [[ -d "$TEXTFILE_DIR" ]]; then
    METRICS="$TEXTFILE_DIR/auth_backup.prom"
    cat > "$METRICS.tmp" <<PROM
# HELP auth_backup_last_success_timestamp Unix time of the last complete backup.
# TYPE auth_backup_last_success_timestamp gauge
auth_backup_last_success_timestamp $(date +%s)
# HELP auth_backup_last_size_bytes Size of the last complete encrypted backup.
# TYPE auth_backup_last_size_bytes gauge
auth_backup_last_size_bytes $SIZE
# HELP auth_backup_last_duration_seconds Duration of the last complete backup.
# TYPE auth_backup_last_duration_seconds gauge
auth_backup_last_duration_seconds $(( $(date +%s) - STARTED ))
PROM
    mv "$METRICS.tmp" "$METRICS"
else
    log "WARNING: $TEXTFILE_DIR does not exist; the backup alerts cannot see this backup"
fi

log "OK"
