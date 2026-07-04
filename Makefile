.DEFAULT_GOAL := help

# =============================================================================
# Variables
# =============================================================================

DEV_COMPOSE    := docker-compose.dev.yml
TEST_COMPOSE   := docker-compose.test.yml
TEST_PROJECT   := auth-api-test
TEST_DB_URL    := postgres://postgres:postgres@localhost:5433/postgres
TEST_REDIS_URL := redis://127.0.0.1:6380
TEST_NATS_URL  := nats://127.0.0.1:4224
IMAGE_LOCAL    := auth-api:local
IMAGE_DEV      := auth-api:dev

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

.PHONY: dev-admin
dev-admin: ## Start the development stack with the Appsmith admin panel (http://localhost:8080)
	docker compose -f $(DEV_COMPOSE) --profile admin up --build -d

.PHONY: dev-admin-stop
dev-admin-stop: ## Stop the development stack including Appsmith
	docker compose -f $(DEV_COMPOSE) --profile admin down

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
clippy: ## Run Clippy linter
	cargo clippy -- -D warnings

.PHONY: deny
deny: ## Enforce dependency policy and security audit (cargo-deny)
	cargo deny check

.PHONY: quality
quality: fmt-check clippy deny ## Run all code quality checks

# =============================================================================
# Tests
# =============================================================================

.PHONY: test-infra-up
test-infra-up: ## Start test infrastructure (postgres + redis)
	docker compose -p $(TEST_PROJECT) -f $(TEST_COMPOSE) up -d --wait

.PHONY: test-infra-down
test-infra-down: ## Stop test infrastructure
	docker compose -p $(TEST_PROJECT) -f $(TEST_COMPOSE) down

.PHONY: test
test: test-infra-up ## Run all tests (starts/stops infrastructure automatically)
	TEST_DATABASE_URL=$(TEST_DB_URL) TEST_REDIS_URL=$(TEST_REDIS_URL) TEST_NATS_URL=$(TEST_NATS_URL) cargo nextest run; \
	EXIT=$$?; $(MAKE) test-infra-down; exit $$EXIT

.PHONY: test-verbose
test-verbose: test-infra-up ## Run all tests with detailed output
	TEST_DATABASE_URL=$(TEST_DB_URL) TEST_REDIS_URL=$(TEST_REDIS_URL) TEST_NATS_URL=$(TEST_NATS_URL) cargo nextest run --no-capture; \
	EXIT=$$?; $(MAKE) test-infra-down; exit $$EXIT

.PHONY: coverage
coverage: test-infra-up ## Run tests with coverage report (tarpaulin) - outputs HTML to reports/coverage/
	TEST_DATABASE_URL=$(TEST_DB_URL) TEST_REDIS_URL=$(TEST_REDIS_URL) TEST_NATS_URL=$(TEST_NATS_URL) \
	cargo tarpaulin --tests --skip-clean \
		--exclude-files "src/main.rs" "src/bin/*" \
		--out html --out json --output-dir reports/coverage; \
	EXIT=$$?; $(MAKE) test-infra-down; exit $$EXIT

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

# =============================================================================
# Docker Security
# =============================================================================

.PHONY: docker-lint
docker-lint: ## Lint the Dockerfile (hadolint)
	docker run --rm -i hadolint/hadolint < Dockerfile

.PHONY: docker-scan
docker-scan: docker-build ## Scan the production image for vulnerabilities (Trivy)
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		aquasec/trivy image --severity CRITICAL,HIGH --ignore-unfixed $(IMAGE_LOCAL)

.PHONY: docker-scan-dev
docker-scan-dev: docker-build-dev ## Scan the development image for vulnerabilities (Trivy)
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		aquasec/trivy image --severity CRITICAL,HIGH --ignore-unfixed $(IMAGE_DEV)

.PHONY: docker-scan-secrets
docker-scan-secrets: docker-build ## Scan the production image for secrets (Trivy)
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		aquasec/trivy image --scanners secret $(IMAGE_LOCAL)

.PHONY: docker-check
docker-check: docker-lint docker-scan docker-scan-secrets ## Run all Docker checks

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
