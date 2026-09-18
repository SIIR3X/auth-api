# Base images are pinned by digest: a tag can be repointed, a digest cannot.
# Refresh with `docker buildx imagetools inspect <image>:<tag>`.

# =============================================================================
# Stage 1: Chef - install cargo-chef
# =============================================================================
FROM rust:1.96-slim-bookworm@sha256:e18a79fc84dfcfc3ab5ba72290398a644c135c97eaa881447fddc354ee4701a3 AS chef

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef --version 0.1.78 --locked

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
# Distroless: glibc, CA certificates and nothing else - no shell, no package
# manager, no setuid binary to exploit. TLS is rustls, so no OpenSSL either.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="auth-api" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="https://github.com/SIIR3X/auth-api"

WORKDIR /app

# Copied as root and left that way: the service account runs the binary and
# reads the templates, and can change neither.
COPY --from=builder /app/target/release/auth-api ./auth-api
COPY --from=builder /app/templates ./templates

# The distroless `nonroot` account, by number so the runtime never has to
# resolve a name.
USER 65532:65532

EXPOSE 3000 9464

# Self-healthcheck via the binary itself: the image has no curl, wget or shell,
# and the check runs in-process (no PATH lookups, no shell parsing).
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD ["./auth-api", "--healthcheck"]

CMD ["./auth-api"]
