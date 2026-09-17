#!/usr/bin/env bash
# Checks of everything deployed besides the code, in three families:
#
#   hygiene  actionlint on the GitHub workflows, Trivy secret scan of the
#            repository
#   static   docker compose config (the API compose with each profile and the
#            L overlay, the development, test and monitoring compose files),
#            Hadolint on both Dockerfiles, nginx -t on nginx/nginx.conf with a
#            throwaway certificate, promtool (Prometheus configuration, both rule
#            files, the rule unit tests), amtool, shellcheck on every script
#   image    the production image: build, size limit, Trivy (HIGH and CRITICAL
#            vulnerabilities with a fix, and secrets)
#
# CHECKS selects the families (default: all three); the CI runs each family in
# its own job. Every selected check runs; the script fails at the end if any
# failed.
#
# Usage: scripts/infra-check.sh             (make infra-check)
#        CHECKS=static scripts/infra-check.sh
# Needs docker and openssl.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

CHECKS=${CHECKS:-hygiene static image}
HADOLINT_IMAGE=${HADOLINT_IMAGE:-hadolint/hadolint:v2.15.1}
TRIVY_IMAGE=${TRIVY_IMAGE:-aquasec/trivy:0.74.0}
SHELLCHECK_IMAGE=${SHELLCHECK_IMAGE:-koalaman/shellcheck:v0.11.0}
ACTIONLINT_IMAGE=${ACTIONLINT_IMAGE:-rhysd/actionlint:1.7.12}
PROMETHEUS_IMAGE=${PROMETHEUS_IMAGE:-$(sed -n 's/^ *image: *\(prom\/prometheus:.*\)$/\1/p' deploy/monitoring/docker-compose.monitoring.yml | head -1)}
ALERTMANAGER_IMAGE=${ALERTMANAGER_IMAGE:-$(sed -n 's/^ *image: *\(prom\/alertmanager:.*\)$/\1/p' deploy/monitoring/docker-compose.monitoring.yml | head -1)}
NGINX_IMAGE=${NGINX_IMAGE:-nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10}
IMAGE=${IMAGE:-auth-api:infra-check}
# The image weighs about 60 MiB: past this limit, something heavy got in.
MAX_IMAGE_MIB=${MAX_IMAGE_MIB:-100}

for family in $CHECKS; do
  case "$family" in
    hygiene | static | image) ;;
    *) echo "unknown check family '$family' (expected hygiene, static or image)" >&2; exit 2 ;;
  esac
done
selected() { [[ " $CHECKS " == *" $1 "* ]]; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FAILED=()

run() {
  local name=$1
  shift
  if "$@" > "$WORK/out" 2>&1; then
    echo "ok   $name"
  else
    echo "FAIL $name"
    sed 's/^/     /' "$WORK/out"
    FAILED+=("$name")
  fi
}

# --- hygiene ----------------------------------------------------------------

if selected hygiene; then
  run "actionlint: .github/workflows" \
    docker run --rm -v "$ROOT:/repo:ro" -w /repo "$ACTIONLINT_IMAGE" -color
  run "trivy: repository secrets" \
    docker run --rm -v "$ROOT:/src:ro" "$TRIVY_IMAGE" fs --scanners secret --exit-code 1 \
      --secret-config /src/trivy-secret.yaml --skip-dirs /src/.git --skip-dirs /src/target --skip-dirs /src/fuzz/target \
      --skip-dirs /src/reports --skip-dirs /src/dist /src
fi

# --- static -----------------------------------------------------------------

if selected static; then
  # Placeholders for the variables the compose files require.
  compose_env() {
    env AUTH_API_VERSION=check DATABASE_URL=x REDIS_URL=x JWT_PRIVATE_KEY=x JWT_PUBLIC_KEY=x \
      ENCRYPTION_KEY=x SMTP_USERNAME=x SMTP_PASSWORD=x CAPTCHA_SECRET=x NATS_URL=x "$@"
  }

  for profile in s m l xl; do
    files=(-f docker-compose.api.yml)
    case "$profile" in l | xl) files+=(-f docker-compose.api.l.yml) ;; esac
    run "compose: API, profile ${profile^^}" \
      compose_env docker compose --env-file "deploy/profiles/$profile.env" "${files[@]}" config -q
  done
  for file in docker-compose.dev.yml docker-compose.test.yml deploy/monitoring/docker-compose.monitoring.yml; do
    [ -f "$file" ] && run "compose: $file" compose_env docker compose -f "$file" config -q
  done

  for dockerfile in Dockerfile Dockerfile.dev; do
    run "hadolint: $dockerfile" sh -c "docker run --rm -i '$HADOLINT_IMAGE' < '$dockerfile'"
  done

  mkdir -p "$WORK/certs"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj /CN=api.example.com -keyout "$WORK/certs/privkey.pem" -out "$WORK/certs/fullchain.pem" 2>/dev/null
  chmod 644 "$WORK/certs/privkey.pem"
  run "nginx -t" docker run --rm \
    -v "$ROOT/nginx/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
    -v "$WORK/certs:/etc/letsencrypt/live/api.example.com:ro" \
    "$NGINX_IMAGE" nginx -t

  promtool() {
    docker run --rm --entrypoint promtool -v "$ROOT:/r:ro" -w "/r/$1" "$PROMETHEUS_IMAGE" "${@:2}"
  }
  run "promtool: prometheus.yml" promtool deploy/monitoring check config --syntax-only prometheus.yml
  run "promtool: alert rules" promtool . check rules \
    docs/deploy/guides/prometheus-alerts.yml deploy/monitoring/rules/infrastructure.yml
  run "promtool: rule tests" promtool deploy/monitoring/rules test rules infrastructure.test.yml
  run "amtool: alertmanager.yml" docker run --rm --entrypoint amtool -v "$ROOT/deploy/monitoring:/m:ro" \
    "$ALERTMANAGER_IMAGE" check-config /m/alertmanager.yml

  mapfile -t scripts < <(find scripts perf deploy -name '*.sh' -type f | sort)
  run "shellcheck: ${#scripts[@]} scripts" \
    docker run --rm -v "$ROOT:/mnt:ro" -w /mnt "$SHELLCHECK_IMAGE" -x "${scripts[@]}"
fi

# --- image ------------------------------------------------------------------

if selected image; then
  image_size_within_limit() {
    local size
    size=$(docker image inspect -f '{{.Size}}' "$IMAGE") || return 1
    echo "$((size / 1048576)) MiB, limit $MAX_IMAGE_MIB MiB"
    [ "$size" -le $((MAX_IMAGE_MIB * 1048576)) ]
  }
  run "docker build" docker build -q -t "$IMAGE" .
  run "image size" image_size_within_limit
  run "trivy: $IMAGE" docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    "$TRIVY_IMAGE" image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed \
    --scanners vuln,secret "$IMAGE"
fi

if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "infra-check: ${#FAILED[@]} check(s) failed: ${FAILED[*]}"
  exit 1
fi
echo "infra-check: every check passed ($CHECKS)"
