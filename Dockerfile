# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.94.0
ARG ALPINE_VERSION=3.22
ARG SQLX_CLI_VERSION=0.8.6

FROM rust:${RUST_VERSION}-alpine${ALPINE_VERSION} AS rust-base

WORKDIR /build

RUN apk add --no-cache \
    binutils \
    build-base \
    ca-certificates \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    perl \
    pkgconfig

ENV OPENSSL_STATIC=1

FROM rust-base AS api-builder

COPY Cargo.toml Cargo.lock ./
COPY benches ./benches
COPY src ./src
COPY templates ./templates
COPY tests ./tests
COPY vendor ./vendor

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked --bin rust-api && \
    cp target/release/rust-api /tmp/rust-api && \
    strip /tmp/rust-api

FROM rust-base AS migrations-builder

ARG SQLX_CLI_VERSION

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/tmp/sqlx-target \
    CARGO_TARGET_DIR=/tmp/sqlx-target \
    cargo install \
      --locked \
      --root /tmp/sqlx-cli \
      --no-default-features \
      --features rustls,postgres \
      --version ${SQLX_CLI_VERSION} \
      sqlx-cli && \
    strip /tmp/sqlx-cli/bin/sqlx

FROM alpine:${ALPINE_VERSION} AS migrations

RUN apk add --no-cache ca-certificates && \
    addgroup -S migrate && \
    adduser -S -D -H -h /migrations -s /sbin/nologin -G migrate migrate

WORKDIR /migrations

COPY --from=migrations-builder /tmp/sqlx-cli/bin/sqlx /usr/local/bin/sqlx
COPY migrations ./migrations

RUN chown -R migrate:migrate /migrations

USER migrate:migrate

ENTRYPOINT ["/usr/local/bin/sqlx", "migrate", "run", "--source", "/migrations/migrations"]

FROM alpine:${ALPINE_VERSION} AS runtime

RUN apk add --no-cache ca-certificates && \
    addgroup -S app && \
    adduser -S -D -H -h /app -s /sbin/nologin -G app app

WORKDIR /app

COPY --from=api-builder /tmp/rust-api /usr/local/bin/rust-api
COPY --from=api-builder /build/templates /app/templates

RUN mkdir -p /app/data && \
    chown -R app:app /app

ENV APP_ENV=production \
    SERVER_HOST=0.0.0.0 \
    SERVER_PORT=3000 \
    MAIL_TEMPLATES_DIR=/app/templates

USER app:app

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/rust-api"]
