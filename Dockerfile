# =============================================================================
# Stage 1: Chef - install cargo-chef
# =============================================================================
FROM rust:1.97-slim-bookworm AS chef

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef --locked

WORKDIR /app

# =============================================================================
# Stage 2: Planner - generate the dependency recipe
# =============================================================================
FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# =============================================================================
# Stage 3: Builder - compile dependencies then the binary
# =============================================================================
FROM chef AS builder

COPY --from=planner /app/recipe.json recipe.json

# Cache layer: compile dependencies only
RUN cargo chef cook --release --recipe-path recipe.json

# Compile the binary
COPY . .
RUN cargo build --release --bin auth-api

# =============================================================================
# Stage 4: Runtime
# =============================================================================
FROM debian:bookworm-slim AS runtime

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --uid 1001 --no-create-home --shell /bin/false appuser

WORKDIR /app

COPY --from=builder /app/target/release/auth-api ./auth-api
COPY --from=builder /app/templates ./templates

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 3000

# Self-healthcheck via the binary itself: avoids shipping curl/wget in the
# slim runtime image (smaller attack surface) and keeps the check in-process
# (no PATH lookups, no shell parsing).
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD ["./auth-api", "--healthcheck"]

CMD ["./auth-api"]
