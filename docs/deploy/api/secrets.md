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

### JWT Secret

Signing key for access tokens (HS256). Must be at least 32 characters.

```bash
pass insert prod/auth-api/jwt-secret
# Generate with: openssl rand -hex 32
```

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

