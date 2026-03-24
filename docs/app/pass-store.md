# Application Server pass Entries

This document lists the `pass` entries required on the application server.

## Recommended Entry Names

```text
rust-api/app/DATABASE_URL
rust-api/app/REDIS_URL
rust-api/app/JWT_SECRET
rust-api/app/JWT_PREVIOUS_SECRET
rust-api/app/ENCRYPTION_KEY
rust-api/app/PREVIOUS_ENCRYPTION_KEY
rust-api/app/SMTP_USERNAME
rust-api/app/SMTP_PASSWORD
rust-api/app/CAPTCHA_SECRET
```

## Create the Required Entries

Required values:

```bash
pass insert rust-api/app/DATABASE_URL
pass insert rust-api/app/REDIS_URL
pass insert rust-api/app/JWT_SECRET
pass insert rust-api/app/ENCRYPTION_KEY
pass insert rust-api/app/SMTP_USERNAME
pass insert rust-api/app/SMTP_PASSWORD
```

Optional values:

```bash
pass insert rust-api/app/JWT_PREVIOUS_SECRET
pass insert rust-api/app/PREVIOUS_ENCRYPTION_KEY
pass insert rust-api/app/CAPTCHA_SECRET
```

If an optional value is not needed, you can skip creating that entry.

## Read Back a Secret

Example:

```bash
pass show rust-api/app/JWT_SECRET
```

## Entry Purpose

| Entry | Purpose |
| --- | --- |
| `rust-api/app/DATABASE_URL` | Runtime PostgreSQL connection string for the application role |
| `rust-api/app/REDIS_URL` | Runtime Redis connection string |
| `rust-api/app/JWT_SECRET` | JWT signing secret |
| `rust-api/app/JWT_PREVIOUS_SECRET` | Previous JWT signing secret during rotation only |
| `rust-api/app/ENCRYPTION_KEY` | TOTP encryption key |
| `rust-api/app/PREVIOUS_ENCRYPTION_KEY` | Previous TOTP encryption key during rotation only |
| `rust-api/app/SMTP_USERNAME` | SMTP username |
| `rust-api/app/SMTP_PASSWORD` | SMTP password |
| `rust-api/app/CAPTCHA_SECRET` | CAPTCHA secret if CAPTCHA is enabled |
