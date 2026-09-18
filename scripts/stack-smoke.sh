#!/usr/bin/env bash
# Production stack end to end, as a server runs it: docker-compose.api.yml with
# profile M (two instances, NATS token in a root-owned secret file) behind the
# repository's nginx.conf in TLS, with PostgreSQL and Redis beside it.
#
# Checks limits and hardening of the containers, the metrics listeners and the
# NATS exporter, nginx (redirect, headers, balancing, request id), a sign-in
# flow, failover with one instance stopped, a rolling update under load with no
# failed request, the account deletion event through the authenticated broker
# and a clean stop.
#
# Needs docker, curl, openssl, python3, ports 80, 443, 3001, 3002, 9465, 9466,
# 7777 and 55432 free on loopback, and outbound HTTPS to hcaptcha.com: the
# production configuration verifies CAPTCHA tokens (hCaptcha's test key pair).
#
# Usage: scripts/stack-smoke.sh   (make stack-test). Logs in $OUT.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
OUT=${OUT:-reports/stack/$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
S=$(cd "$OUT" && pwd)
D=$S/auth-smoke                    # deployment directory, like /srv/auth-api
KEYS=$S/keys
# An image with a shell, to own the secret file as root like on the server.
SHELL_IMAGE=redis:7-alpine@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf
unset COMPOSE_PROJECT_NAME

mkdir -p "$D" "$KEYS/certs"
cp "$ROOT"/docker-compose.api.yml "$ROOT"/config.prod.env "$ROOT"/nats.conf "$ROOT"/scripts/rolling-update.sh "$D"/
cp "$ROOT"/deploy/profiles/m.env "$D"/profile.env

# Throwaway keys: ES256 signing key, and a certificate for api.example.com.
openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null \
  | openssl pkcs8 -topk8 -nocrypt -out "$KEYS/jwt-private.pem"
openssl ec -in "$KEYS/jwt-private.pem" -pubout -out "$KEYS/jwt-public.pem" 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -subj /CN=api.example.com -addext subjectAltName=DNS:api.example.com \
  -keyout "$KEYS/certs/privkey.pem" -out "$KEYS/certs/fullchain.pem" 2>/dev/null
chmod 644 "$KEYS/certs/privkey.pem"

export AUTH_API_VERSION=smoke
export METRICS_BIND_ADDRESS=127.0.0.1
POSTGRES_PASSWORD=$(openssl rand -hex 16)
export POSTGRES_PASSWORD
export DATABASE_URL=postgres://auth:${POSTGRES_PASSWORD}@postgres:5432/auth
export REDIS_URL=redis://redis:6379
JWT_PRIVATE_KEY=$(cat "$KEYS"/jwt-private.pem)
JWT_PUBLIC_KEY=$(cat "$KEYS"/jwt-public.pem)
ENCRYPTION_KEY=$(openssl rand -base64 32)
export JWT_PRIVATE_KEY JWT_PUBLIC_KEY ENCRYPTION_KEY
export SMTP_USERNAME=smoke-relay-user SMTP_PASSWORD=smoke-relay-password
# hCaptcha's published test secret; TOKEN below is its test response.
export CAPTCHA_SECRET=0x0000000000000000000000000000000000000000
NATS_TOKEN=$(openssl rand -hex 24)
export NATS_URL=nats://${NATS_TOKEN}@nats:4222
install -m 600 /dev/null "$D"/nats-auth.conf
printf 'authorization { token: "%s" }\n' "$NATS_TOKEN" > "$D"/nats-auth.conf
# Owned by root, as on the server (the broker runs without capabilities).
docker run --rm --entrypoint sh -v "$D:/d" "$SHELL_IMAGE" -c 'chown 0:0 /d/nats-auth.conf && chmod 600 /d/nats-auth.conf'

cat > "$D"/override.yml <<'YML'
# Smoke test only: in production the database and cache run on the DB VPS.
services:
  postgres:
    image: postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73
    environment: { POSTGRES_USER: auth, POSTGRES_DB: auth, POSTGRES_PASSWORD: "${POSTGRES_PASSWORD}" }
    ports: ["127.0.0.1:55432:5432"]
    healthcheck: { test: ["CMD-SHELL", "pg_isready -U auth"], interval: 2s, retries: 30 }
    networks: [auth-api]
  redis:
    image: redis:7-alpine@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf
    healthcheck: { test: ["CMD", "redis-cli", "ping"], interval: 2s, retries: 30 }
    networks: [auth-api]
YML
C=(docker compose --project-directory "$D" --env-file "$D/profile.env" -f "$D/docker-compose.api.yml" -f "$D/override.yml")
H=(curl -sk --max-time 20 --resolve api.example.com:443:127.0.0.1 --resolve api.example.com:80:127.0.0.1)
B=https://api.example.com
TOKEN=10000000-aaaa-bbbb-cccc-000000000001
FAIL=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1 ($3)"; else echo "FAIL $1: expected $2, got $3"; FAIL=1; fi; }
psql_q() { "${C[@]}" exec -T postgres psql -U auth -d auth -tAc "$1"; }
json() { python3 -c "import sys,json; print(json.load(sys.stdin).get('$1',''))" 2>/dev/null; }
# shellcheck disable=SC2329 # run by the EXIT trap
teardown() {
  "${C[@]}" logs --no-color > "$S/compose.log" 2>&1
  docker logs auth-smoke-nginx > "$S/nginx-container.log" 2>&1
  docker cp auth-smoke-nginx:/var/log/nginx/auth-api.access.log "$S/nginx-access.log" >/dev/null 2>&1
  docker rm -f auth-smoke-nginx >/dev/null 2>&1
  "${C[@]}" down -v --remove-orphans >/dev/null 2>&1
  docker run --rm --entrypoint sh -v "$D:/d" "$SHELL_IMAGE" -c 'rm -f /d/nats-auth.conf' >/dev/null 2>&1
}
trap teardown EXIT

echo "== image, dependencies, migrations"
docker build -q -t auth-api:smoke "$ROOT" >/dev/null; check "image build" 0 $?
"${C[@]}" up -d --wait postgres redis >/dev/null 2>&1; check "database and cache" 0 $?
(cd "$ROOT" && cargo build --release --quiet --bin perf_load && DATABASE_URL="postgres://auth:${POSTGRES_PASSWORD}@127.0.0.1:55432/auth" "$ROOT/target/release/perf_load" migrate >/dev/null); check "migrations" 0 $?

echo "== docker-compose.api.yml with profile M"
"${C[@]}" up -d --wait nats nats-exporter api-a api-b >/dev/null 2>&1; check "stack up and healthy" 0 $?
for svc in api-a api-b; do
  id=$("${C[@]}" ps -q $svc)
  check "$svc healthy" healthy "$(docker inspect -f '{{.State.Health.Status}}' "$id")"
  check "$svc CPU limit (profile M)" 3000000000 "$(docker inspect -f '{{.HostConfig.NanoCpus}}' "$id")"
  check "$svc memory limit" 536870912 "$(docker inspect -f '{{.HostConfig.Memory}}' "$id")"
  check "$svc memory reservation" 268435456 "$(docker inspect -f '{{.HostConfig.MemoryReservation}}' "$id")"
  check "$svc pids limit" 256 "$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$id")"
  check "$svc stop grace" 40 "$(docker inspect -f '{{.Config.StopTimeout}}' "$id")"
  check "$svc log rotation" 10m "$(docker inspect -f '{{index .HostConfig.LogConfig.Config "max-size"}}' "$id")"
  check "$svc runs as non-root" 65532:65532 "$(docker inspect -f '{{.Config.User}}' "$id")"
  check "$svc Argon2 concurrency from profile" 3 "$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$id" | sed -n 's/^ARGON2_MAX_CONCURRENCY=//p')"
done
check "api-a ready" 200 "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3001/ready)"
check "api-b ready" 200 "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3002/ready)"
check "metrics api-a" 200 "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9465/metrics)"
check "metrics api-b" 200 "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9466/metrics)"
metric() { curl -s "http://127.0.0.1:$1/metrics" | awk -v m="$2" '$1==m {printf "%d", $2}'; }
check "api-a publishes its memory limit" 536870912 "$(metric 9465 auth_container_memory_limit_bytes)"
ws=$(metric 9465 auth_container_memory_working_set_bytes)
check "api-a working set within limit" true "$([ "${ws:-0}" -gt 0 ] && [ "$ws" -lt 536870912 ] && echo true || echo false)"
check "api-b publishes CPU periods" true "$(curl -s http://127.0.0.1:9466/metrics | grep -q '^auth_container_cpu_periods_total ' && echo true || echo false)"
check "api-b publishes its start time" true "$(curl -s http://127.0.0.1:9466/metrics | grep -q '^auth_process_start_time_seconds ' && echo true || echo false)"
nats_metrics=false
for _ in $(seq 1 10); do
  curl -s http://127.0.0.1:7777/metrics > "$S/nats-exporter.txt" 2>&1
  grep -q '^gnatsd_varz_connections' "$S/nats-exporter.txt" && { nats_metrics=true; break; }
  sleep 1
done
check "NATS exporter" true "$nats_metrics"
nats_id=$("${C[@]}" ps -q nats)
check "NATS token absent from broker arguments" false "$(docker inspect -f '{{json .Args}} {{json .Config.Cmd}}' "$nats_id" | grep -q "$NATS_TOKEN" && echo true || echo false)"
check "NATS memory limit" 201326592 "$(docker inspect -f '{{.HostConfig.Memory}}' "$nats_id")"
check "NATS JetStream file store cap" 1073741824 "$(docker run --rm --network auth-smoke_auth-api natsio/nats-box:0.14.5 wget -qO- http://nats:8222/jsz 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin)["config"]["max_storage"])' 2>/dev/null)"

echo "== nginx.conf in front, TLS"
docker run -d --name auth-smoke-nginx --network host \
  -v "$ROOT/nginx/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$KEYS/certs:/etc/letsencrypt/live/api.example.com:ro" nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10 >/dev/null
sleep 2
docker exec auth-smoke-nginx nginx -t >/dev/null 2>&1; check "nginx -t" 0 $?
check "http redirects to https" 301 "$("${H[@]}" -o /dev/null -w '%{http_code}' http://api.example.com/live)"
check "ready through nginx" 200 "$("${H[@]}" -o /dev/null -w '%{http_code}' $B/ready)"
check "HEAD allowed" 200 "$("${H[@]}" -I -o /dev/null -w '%{http_code}' $B/live)"
check "one HSTS header" 1 "$("${H[@]}" -D - -o /dev/null $B/.well-known/jwks.json | grep -ci '^strict-transport-security')"
for _ in $(seq 1 20); do "${H[@]}" -o /dev/null $B/.well-known/jwks.json; done
sleep 1
docker exec auth-smoke-nginx cat /var/log/nginx/auth-api.access.log > "$S/nginx-access.log" 2>/dev/null
check "requests balanced over both instances" 2 "$(python3 -c "
import json,sys
ups=set()
for l in open('$S/nginx-access.log'):
    r=json.loads(l)
    if r['uri']=='/.well-known/jwks.json': ups.add(r['upstream'])
print(len(ups))")"
rid=$("${H[@]}" -D - -o /dev/null $B/.well-known/jwks.json | sed -n 's/^x-request-id: //Ip' | tr -d '\r')
sleep 1
check "nginx request id reaches the API" true "$(docker exec auth-smoke-nginx cat /var/log/nginx/auth-api.access.log | grep -q "\"request_id\":\"$rid\"" && echo true || echo false)"

echo "== sign-in flow through nginx"
EMAIL=smoke.user@example.com; PASSWORD='Smoke-Password-2026!'
check "register" 202 "$("${H[@]}" -o /dev/null -w '%{http_code}' -H 'content-type: application/json' -d "{\"username\":\"smoke_user\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"captcha_token\":\"$TOKEN\"}" $B/auth/register)"
psql_q "UPDATE users SET status='active', email_verified_at=NOW() WHERE email='$EMAIL'" >/dev/null
LOGIN=$("${H[@]}" -H 'content-type: application/json' -H 'X-Forwarded-For: 203.0.113.9' -d "{\"identifier\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"captcha_token\":\"$TOKEN\"}" $B/auth/login)
ACCESS=$(printf '%s' "$LOGIN" | json access_token); REFRESH=$(printf '%s' "$LOGIN" | json refresh_token)
check "login issues tokens" true "$([ -n "$ACCESS" ] && echo true || echo false)"
check "client address recorded" 127.0.0.1 "$(psql_q "SELECT host(ip_address) FROM sessions ORDER BY created_at DESC LIMIT 1")"
check "profile" 200 "$("${H[@]}" -o /dev/null -w '%{http_code}' -H "authorization: Bearer $ACCESS" $B/users/me)"

echo "== failover: one instance stopped"
"${C[@]}" stop api-a >/dev/null 2>&1
bad=0; for _ in $(seq 1 30); do c=$("${H[@]}" -o /dev/null -w '%{http_code}' -H "authorization: Bearer $ACCESS" $B/users/me); [ "$c" = 200 ] || bad=$((bad+1)); done
check "GET errors with api-a stopped" 0 "$bad"
R=$("${H[@]}" -H 'content-type: application/json' -d "{\"refresh_token\":\"$REFRESH\"}" $B/auth/refresh)
REFRESH2=$(printf '%s' "$R" | json refresh_token)
check "POST refresh with api-a stopped" true "$([ -n "$REFRESH2" ] && echo true || echo false)"
[ -n "$REFRESH2" ] && REFRESH=$REFRESH2
"${C[@]}" start api-a >/dev/null 2>&1
for _ in $(seq 1 30); do [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3001/ready)" = 200 ] && break; sleep 2; done
check "api-a back" 200 "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3001/ready)"

echo "== rolling update under load"
# The GET load gets a session of its own: the refresh loop rotates its session,
# which revokes that session's access tokens.
LOGIN2=$("${H[@]}" -H 'content-type: application/json' -d "{\"identifier\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"captcha_token\":\"$TOKEN\"}" $B/auth/login)
GET_ACCESS=$(printf '%s' "$LOGIN2" | json access_token)
check "second session for the GET load" true "$([ -n "$GET_ACCESS" ] && echo true || echo false)"
: > "$S/load-errors.txt"
end=$(( $(date +%s) + 600 ))
( ok=0; bad=0; while [ ! -f "$S/stop-load" ] && [ "$(date +%s)" -lt $end ]; do
    c=$("${H[@]}" -o /dev/null -w '%{http_code}' -H "authorization: Bearer $GET_ACCESS" $B/users/me)
    if [ "$c" = 200 ]; then ok=$((ok+1)); else bad=$((bad+1)); echo "GET $c $(date +%T)" >> "$S/load-errors.txt"; fi
    sleep 0.3
  done; echo "$ok $bad" > "$S/load-get.txt" ) &
GET_PID=$!
( ok=0; bad=0; rt=$REFRESH; while [ ! -f "$S/stop-load" ] && [ "$(date +%s)" -lt $end ]; do
    out=$("${H[@]}" -H 'content-type: application/json' -d "{\"refresh_token\":\"$rt\"}" -w '\n%{http_code}' $B/auth/refresh)
    c=${out##*$'\n'}; body=${out%$'\n'*}
    if [ "$c" = 200 ]; then ok=$((ok+1)); rt=$(printf '%s' "$body" | python3 -c 'import sys,json; print(json.load(sys.stdin)["refresh_token"])'); else bad=$((bad+1)); echo "REFRESH $c $(date +%T) $body" >> "$S/load-errors.txt"; fi
    sleep 5
  done; echo "$ok $bad" > "$S/load-refresh.txt" ) &
REF_PID=$!
rm -f "$S/stop-load"; sleep 3
start=$(date +%s)
COMPOSE_DIR="$D" PROFILE_FILE="$D/profile.env" "$D/rolling-update.sh" > "$S/rolling-update.log" 2>&1
check "rolling update script" 0 $?
echo "INFO rolling update took $(( $(date +%s) - start ))s"
sleep 3; touch "$S/stop-load"; wait $GET_PID $REF_PID; rm -f "$S/stop-load"
read -r gok gbad < "$S/load-get.txt"; read -r rok rbad < "$S/load-refresh.txt"
echo "INFO load: GET ok=$gok, refresh ok=$rok"
check "GET errors during rolling update" 0 "$gbad"
check "refresh errors during rolling update" 0 "$rbad"

echo "== deletion event through the token-protected broker"
code=$("${H[@]}" -o /dev/null -w '%{http_code}' -X DELETE -H 'content-type: application/json' -H "authorization: Bearer $ACCESS" -d "{\"current_password\":\"$PASSWORD\"}" $B/users/me)
if [ "$code" = 401 ]; then echo "INFO access token of a refreshed session: signing in again"; LOGIN=$("${H[@]}" -H 'content-type: application/json' -d "{\"identifier\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"captcha_token\":\"$TOKEN\"}" $B/auth/login); ACCESS=$(printf '%s' "$LOGIN" | json access_token); code=$("${H[@]}" -o /dev/null -w '%{http_code}' -X DELETE -H 'content-type: application/json' -H "authorization: Bearer $ACCESS" -d "{\"current_password\":\"$PASSWORD\"}" $B/users/me); fi
check "account deletion" 204 "$code"
check "deletion event stored by JetStream" true "$(docker run --rm --network auth-smoke_auth-api natsio/nats-box:0.14.5 nats -s "nats://${NATS_TOKEN}@nats:4222" stream info AUTH_EVENTS -j 2>/dev/null | grep -q '"messages": *[1-9]' && echo true || echo false)"

echo "== graceful stop"
"${C[@]}" stop api-b >/dev/null 2>&1
check "api-b exits cleanly on SIGTERM" 0 "$(docker inspect -f '{{.State.ExitCode}}' "$("${C[@]}" ps -aq api-b)")"
check "shutdown logged" true "$("${C[@]}" logs --no-color api-b 2>&1 | grep -q 'shutdown complete' && echo true || echo false)"

[ "$FAIL" = 0 ] && echo "STACK PASSED" || echo "STACK FAILED"
exit "$FAIL"
