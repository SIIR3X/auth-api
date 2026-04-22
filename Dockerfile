# =============================================================================
# Stage 1: Chef — installe cargo-chef
# =============================================================================
FROM rust:1.88-slim-bookworm AS chef

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef --locked

WORKDIR /app

# =============================================================================
# Stage 2: Planner — génère la recette des dépendances
# =============================================================================
FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# =============================================================================
# Stage 3: Builder — compile les dépendances puis le binaire
# =============================================================================
FROM chef AS builder

COPY --from=planner /app/recipe.json recipe.json

# Cache layer : compile uniquement les dépendances
RUN cargo chef cook --release --recipe-path recipe.json

# Compile le binaire
COPY . .
RUN cargo build --release --bin rust-api

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

COPY --from=builder /app/target/release/rust-api ./rust-api
COPY --from=builder /app/templates ./templates

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 3000

CMD ["./rust-api"]
