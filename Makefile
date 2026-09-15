.DEFAULT_GOAL := help

# =============================================================================
# Variables
# =============================================================================

DEV_COMPOSE    := docker-compose.dev.yml
TEST_COMPOSE   := docker-compose.test.yml
TEST_PROJECT   := auth-api-test
TEST_DB_URL    := postgres://postgres:postgres@localhost:5433/postgres
TEST_REDIS_URL := redis://127.0.0.1:6380
TEST_NATS_URL  := nats://auth-api-test-token@127.0.0.1:4224
IMAGE_LOCAL    := auth-api:local
IMAGE_DEV      := auth-api:dev
HADOLINT_IMAGE := hadolint/hadolint:v2.15.1
TRIVY_IMAGE    := aquasec/trivy:0.74.0

# =============================================================================
# Help
# =============================================================================

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-28s\033[0m %s\n", $$1, $$2}'

# =============================================================================
# Development
# =============================================================================

.PHONY: dev
dev: ## Start the full development stack
	docker compose -f $(DEV_COMPOSE) up --build

.PHONY: dev-detach
dev-detach: ## Start the full development stack in background
	docker compose -f $(DEV_COMPOSE) up --build -d

.PHONY: dev-stop
dev-stop: ## Stop the development stack
	docker compose -f $(DEV_COMPOSE) down

.PHONY: dev-reset
dev-reset: ## Stop the development stack and remove volumes (reset DB)
	docker compose -f $(DEV_COMPOSE) down -v

.PHONY: dev-logs
dev-logs: ## Stream logs from the development stack
	docker compose -f $(DEV_COMPOSE) logs -f

# =============================================================================
# Code Quality
# =============================================================================

.PHONY: fmt
fmt: ## Format the code
	cargo fmt

.PHONY: fmt-check
fmt-check: ## Check formatting without modifying files
	cargo fmt --check

.PHONY: clippy
clippy: ## Run Clippy linter on every target (lib, bins, tests, benches)
	cargo clippy --workspace --all-targets --all-features -- -D warnings

.PHONY: deny
deny: ## Enforce dependency policy and security audit (cargo-deny)
	cargo deny check

.PHONY: quality
quality: fmt-check clippy deny ## Run all code quality checks

# =============================================================================
# Tests
# =============================================================================

# Suites: `tests/integration`, `tests/security` and `tests/simulation` need the
# test infrastructure; unit tests (`src/`, `crates/testkit`) need none.
TEST_ENV := TEST_DATABASE_URL=$(TEST_DB_URL) TEST_REDIS_URL=$(TEST_REDIS_URL) TEST_NATS_URL=$(TEST_NATS_URL)

.PHONY: test-infra-up
test-infra-up: ## Start test infrastructure (PostgreSQL, Redis, NATS, Mailpit)
	docker compose -p $(TEST_PROJECT) -f $(TEST_COMPOSE) up -d --wait

.PHONY: test-infra-down
test-infra-down: ## Stop test infrastructure
	docker compose -p $(TEST_PROJECT) -f $(TEST_COMPOSE) down

.PHONY: test
test: test-infra-up ## Run every suite (starts/stops infrastructure automatically)
	$(TEST_ENV) cargo nextest run --workspace; \
	EXIT=$$?; $(MAKE) test-infra-down; exit $$EXIT

.PHONY: test-local
test-local: ## Run every suite against already-running infrastructure
	$(TEST_ENV) cargo nextest run --workspace

.PHONY: test-unit
test-unit: ## Unit tests of the service and of the test harness (no infrastructure)
	cargo nextest run --workspace --lib --bins

.PHONY: test-integration
test-integration: ## Integration suite: API end to end, repositories, services
	$(TEST_ENV) cargo nextest run --test integration

.PHONY: test-security
test-security: ## Security suite, fuzz corpus replay included
	$(TEST_ENV) cargo nextest run --test security
	cargo nextest run --test fuzz_corpus --features fuzzing

FUZZ_SECS ?= 60

.PHONY: fuzz
fuzz: ## Fuzz every target FUZZ_SECS seconds each (nightly toolchain, cargo-fuzz)
	@for target in $$(cargo +nightly fuzz list --fuzz-dir fuzz); do \
		echo "== $$target"; \
		mkdir -p fuzz/corpus/$$target; \
		dirs="fuzz/corpus/$$target fuzz/seeds/$$target"; \
		[ -d fuzz/regressions/$$target ] && dirs="$$dirs fuzz/regressions/$$target"; \
		cargo +nightly fuzz run --fuzz-dir fuzz $$target $$dirs -- -max_total_time=$(FUZZ_SECS) || exit 1; \
	done

# Files whose logic the unit tests must pin down: a surviving mutant is a fault
# no unit test notices. Copies are built under $(MUTANTS_TMP), not /tmp.
MUTANTS_FILES := -f 'src/domain/*.rs' -f src/utils/crypto.rs -f src/utils/jwt.rs \
	-f src/utils/totp.rs -f src/utils/time.rs -f src/utils/backoff.rs -f src/utils/password.rs \
	-f src/middleware/client_ip.rs -f src/middleware/error_body.rs \
	-f src/config/validate.rs -f src/handlers/audit.rs
MUTANTS_TMP ?= $(HOME)/.cache/mutants-tmp

.PHONY: mutants
mutants: ## Mutation testing of the security-relevant pure code (cargo-mutants, unit tests)
	mkdir -p $(MUTANTS_TMP) reports
	TMPDIR=$(MUTANTS_TMP) cargo mutants --package auth-api -j 3 -o reports \
		--test-tool nextest $(MUTANTS_FILES) -- --lib

.PHONY: test-sim
test-sim: ## Simulation suite, long scenarios included
	$(TEST_ENV) cargo nextest run --test simulation --run-ignored all

.PHONY: test-verbose
test-verbose: test-infra-up ## Run every suite with detailed output
	$(TEST_ENV) cargo nextest run --workspace --no-capture; \
	EXIT=$$?; $(MAKE) test-infra-down; exit $$EXIT

.PHONY: ci
ci: quality ## Full local CI gate: formatting, lints, dependency policy, every suite
	$(TEST_ENV) cargo nextest run --workspace --profile ci
	cargo nextest run --profile ci --test fuzz_corpus --features fuzzing

.PHONY: coverage
coverage: ## Coverage of every suite, failing under 93% lines, 89% regions, 83% functions (HTML in reports/coverage/)
	$(TEST_ENV) cargo llvm-cov nextest --workspace --profile ci \
		--ignore-filename-regex '(src/bin/|crates/testkit/)' \
		--fail-under-lines 93 --fail-under-regions 89 --fail-under-functions 83 \
		--html --output-dir reports/coverage

.PHONY: bench
bench: ## Run Criterion benchmarks (CPU only, no infrastructure needed)
	cargo bench

.PHONY: bench-http
bench-http: test-infra-up ## Run HTTP integration benchmarks
	TEST_DATABASE_URL=$(TEST_DB_URL) TEST_REDIS_URL=$(TEST_REDIS_URL) \
	cargo run --release --bin bench_http; \
	EXIT=$$?; $(MAKE) test-infra-down; exit $$EXIT

.PHONY: bench-sql
bench-sql: test-infra-up ## Run SQL integration benchmarks
	TEST_DATABASE_URL=$(TEST_DB_URL) TEST_REDIS_URL=$(TEST_REDIS_URL) \
	cargo run --release --bin bench_sql; \
	EXIT=$$?; $(MAKE) test-infra-down; exit $$EXIT

.PHONY: perf
perf: ## Run the performance campaign: data volume x load (hours, see perf/README.md)
	perf/run.sh

.PHONY: perf-report
perf-report: ## Tables and charts of a campaign into docs/perf (RUN=reports/perf/<run>)
	@test -n "$(RUN)" || { echo "usage: make perf-report RUN=reports/perf/<run>"; exit 1; }
	python3 perf/report.py $(RUN) docs/perf

.PHONY: soak
soak: ## One hour of mixed traffic on one API process: no error, stable memory (perf/soak.sh)
	perf/soak.sh

# =============================================================================
# Build
# =============================================================================

.PHONY: build
build: ## Compile the project in release mode
	cargo build --release

.PHONY: docker-build
docker-build: ## Build the production Docker image
	docker build -t $(IMAGE_LOCAL) .

.PHONY: docker-build-dev
docker-build-dev: ## Build the development Docker image
	docker build -f Dockerfile.dev -t $(IMAGE_DEV) .

.PHONY: release
release: ## Build a signed release bundle in dist/ (VERSION=x.y.z RELEASE_SIGNING_KEY=<ssh key>)
	@test -n "$(VERSION)" || { echo "usage: make release VERSION=x.y.z RELEASE_SIGNING_KEY=~/.ssh/auth-api-release"; exit 1; }
	@test -n "$(RELEASE_SIGNING_KEY)" || { echo "RELEASE_SIGNING_KEY must name the SSH private key that signs the bundle"; exit 1; }
	@test -z "$$(git status --porcelain)" || { echo "commit or stash your changes first (untracked files included)"; exit 1; }
	@test "$$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)" = "$(VERSION)" || { echo "VERSION $(VERSION) differs from the version in Cargo.toml"; exit 1; }
	@test "$(ALLOW_UNTAGGED)" = 1 || test "$$(git rev-parse -q --verify 'refs/tags/v$(VERSION)^{commit}')" = "$$(git rev-parse HEAD)" || { echo "tag v$(VERSION) must point at HEAD (ALLOW_UNTAGGED=1 for a test bundle)"; exit 1; }
	git archive HEAD | docker build -t auth-api:$(VERSION) --build-arg VERSION=$(VERSION) --build-arg REVISION=$$(git rev-parse HEAD) -
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock $(TRIVY_IMAGE) \
		image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed auth-api:$(VERSION)
	rm -rf dist/auth-api-$(VERSION) && mkdir -p dist/auth-api-$(VERSION)
	docker save auth-api:$(VERSION) | gzip > dist/auth-api-$(VERSION)/auth-api-$(VERSION).image.tar.gz
	docker image inspect --format '{{.Id}}' auth-api:$(VERSION) > dist/auth-api-$(VERSION)/IMAGE_ID
	git archive HEAD migrations docker-compose.api.yml docker-compose.api.l.yml config.prod.env \
		nats.conf deploy/profiles deploy/db nginx/nginx.conf \
		scripts/backup-db.sh scripts/restore-db.sh scripts/backup-drill.sh scripts/rolling-update.sh \
		docs/deploy/guides/prometheus-alerts.yml deploy/monitoring | tar -x -C dist/auth-api-$(VERSION)
	cd dist/auth-api-$(VERSION) && find . -type f ! -name 'SHA256SUMS*' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
	ssh-keygen -Y sign -q -f $(RELEASE_SIGNING_KEY) -n auth-api-release dist/auth-api-$(VERSION)/SHA256SUMS
	@echo "bundle ready: dist/auth-api-$(VERSION) (signature: SHA256SUMS.sig)"

# =============================================================================
# Docker Security
# =============================================================================

.PHONY: docker-lint
docker-lint: ## Lint the Dockerfiles (hadolint)
	docker run --rm -i $(HADOLINT_IMAGE) < Dockerfile
	docker run --rm -i $(HADOLINT_IMAGE) < Dockerfile.dev

.PHONY: docker-scan
docker-scan: docker-build ## Scan the production image for vulnerabilities (Trivy)
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		$(TRIVY_IMAGE) image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed $(IMAGE_LOCAL)

.PHONY: docker-scan-dev
docker-scan-dev: docker-build-dev ## Scan the development image for vulnerabilities (Trivy)
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		$(TRIVY_IMAGE) image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed $(IMAGE_DEV)

.PHONY: docker-scan-secrets
docker-scan-secrets: docker-build ## Scan the production image for secrets (Trivy)
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		$(TRIVY_IMAGE) image --exit-code 1 --scanners secret $(IMAGE_LOCAL)

.PHONY: docker-check
docker-check: docker-lint docker-scan docker-scan-secrets ## Run all Docker checks

.PHONY: docker-refresh-pins
docker-refresh-pins: ## Point every pinned image digest at its tag's current image (then rebuild, scan, commit)
	scripts/refresh-image-pins.sh

# =============================================================================
# Utilities
# =============================================================================

.PHONY: clean
clean: ## Remove compilation artifacts (target/)
	cargo clean

.PHONY: clean-reports
clean-reports: ## Remove generated reports (benchmarks + coverage)
	rm -rf reports/bench/manual-* reports/coverage/

.PHONY: clean-all
clean-all: clean clean-reports docker-clean ## Remove all build artifacts, reports and Docker images

.PHONY: docker-clean
docker-clean: ## Remove local project Docker images
	docker rmi -f $(IMAGE_LOCAL) $(IMAGE_DEV) 2>/dev/null || true
