# Secrets

[Index](../README.md) | Next: [Database Deployment](../database/deployment.md)

All secrets are stored in `pass` on the API VPS and exported as environment variables before deployment.

## Setup

Initialize `pass` if not already done:

```bash
gpg --full-generate-key
pass init <GPG_KEY_ID>
```

## Secrets

### Database URL

Full PostgreSQL connection string including credentials.

```bash
pass insert prod/auth-api/database-url
# postgres://auth_api:your-strong-password@10.0.0.2:5432/auth_api
```

---

### Redis Password

Password for Redis authentication. Used both in the Redis server config and in the connection URL.

```bash
pass insert prod/auth-api/redis-password
# Generate with: openssl rand -hex 32
```

---

### Redis URL

Redis connection string including the password.

```bash
pass insert prod/auth-api/redis-url
# redis://:$(pass prod/auth-api/redis-password)@10.0.0.2:6379
```

---

### JWT Keys (ES256)

EC P-256 key pair in PEM format: the private key signs access tokens, the
public key verifies them (and feeds the JWKS endpoint). Generate both on a
secure machine:

```bash
openssl ecparam -genkey -name prime256v1 -noout \
  | openssl pkcs8 -topk8 -nocrypt -out jwt-private.pem
openssl ec -in jwt-private.pem -pubout -out jwt-public.pem

pass insert -m prod/auth-api/jwt-private-key < jwt-private.pem
pass insert -m prod/auth-api/jwt-public-key  < jwt-public.pem
```

During a key rotation, also set `prod/auth-api/jwt-previous-public-key`
(see the [Operations Runbook](../guides/operations.md)).

---

### Encryption Key

AES-256-GCM key used to encrypt TOTP secrets at rest. Must be a base64-encoded 32-byte value.

```bash
pass insert prod/auth-api/encryption-key
# Generate with: openssl rand -base64 32
```

---

### SMTP Username

Authentication username for the SMTP server.

```bash
pass insert prod/auth-api/smtp-username
```

---

### SMTP Password

Authentication password for the SMTP server.

```bash
pass insert prod/auth-api/smtp-password
```

---

### CAPTCHA Secret

hCaptcha secret key. Leave unset to disable CAPTCHA entirely.

```bash
pass insert prod/auth-api/captcha-secret
```

---

### NATS Auth Token

Authenticates the API to the NATS broker shipped in `docker-compose.api.yml`
(defence in depth on top of the compose-network isolation). Store both the
token and the full URL embedding it:

```bash
pass insert prod/auth-api/nats-auth-token
# Generate with: openssl rand -hex 32

pass insert prod/auth-api/nats-url
# nats://<token>@nats:4222
```

---

### GitHub Token

Personal Access Token with `read:packages` scope. Used to authenticate against GHCR to pull the Docker image.

```bash
pass insert prod/auth-api/github-token
```

## Verify

List all inserted secrets:

```bash
pass prod/auth-api
```

