#!/usr/bin/env bash
# Replace the API instances one at a time with the image of AUTH_API_VERSION.
#
# nginx keeps sending traffic to the instance still running: a stopping
# instance finishes its requests and refuses new connections, which nginx
# passes to the other one. An instance is only left behind once it is healthy
# and ready; if the new version does not come up, the script stops there with
# the other instance still serving the previous one.
#
# Usage, secrets exported as in docs/deploy/guides/update.md:
#   AUTH_API_VERSION=X.Y.Z scripts/rolling-update.sh
set -euo pipefail

COMPOSE_DIR=${COMPOSE_DIR:-/srv/auth-api}
PROFILE_FILE=${PROFILE_FILE:-$COMPOSE_DIR/profile.env}
: "${AUTH_API_VERSION:?set AUTH_API_VERSION to the release being deployed}"

COMPOSE_FILES=(-f "$COMPOSE_DIR/docker-compose.api.yml")
INSTANCES=(api-a:3001 api-b:3002)
if [[ -f "$COMPOSE_DIR/docker-compose.api.l.yml" ]]; then
    COMPOSE_FILES+=(-f "$COMPOSE_DIR/docker-compose.api.l.yml")
    INSTANCES+=(api-c:3003 api-d:3004)
fi
C=(docker compose --project-directory "$COMPOSE_DIR" --env-file "$PROFILE_FILE" "${COMPOSE_FILES[@]}")

log() { echo "$(date -Iseconds) [rolling-update] $*"; }

wait_ready() { # $1 = service, $2 = host port
    local container health
    for _ in $(seq 1 60); do
        container=$("${C[@]}" ps -q "$1")
        health=$(docker inspect -f '{{.State.Health.Status}}' "$container" 2>/dev/null || true)
        if [[ "$health" == healthy ]] && curl -fsS -o /dev/null "http://127.0.0.1:$2/ready"; then
            return 0
        fi
        sleep 2
    done
    log "ERROR: $1 is not ready after 120 s; the remaining instances keep serving"
    "${C[@]}" logs --tail 50 "$1" >&2
    return 1
}

# The broker first; nothing happens when its definition did not change.
"${C[@]}" up -d --wait nats

for instance in "${INSTANCES[@]}"; do
    service=${instance%:*}
    port=${instance#*:}
    log "replacing $service with auth-api:$AUTH_API_VERSION"
    "${C[@]}" up -d --no-deps --force-recreate "$service"
    wait_ready "$service" "$port"
    log "$service ready"
done

log "every instance runs auth-api:$AUTH_API_VERSION"
