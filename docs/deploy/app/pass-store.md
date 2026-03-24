# Application Server Pass Store

This guide lists the recommended `pass` entries for the application server.

The application server should store its secrets under:

```text
rust-api/app/...
```

## Required Secrets

Insert the database URL used by the application:

```bash
pass insert rust-api/app/DATABASE_URL
```

Insert the Redis URL used by the application:

```bash
pass insert rust-api/app/REDIS_URL
```

Insert the active JWT signing secret:

```bash
pass insert rust-api/app/JWT_SECRET
```

Insert the previous JWT secret only during secret rotation:

```bash
pass insert rust-api/app/JWT_PREVIOUS_SECRET
```

Insert the active application encryption key:

```bash
pass insert rust-api/app/ENCRYPTION_KEY
```

Insert the previous encryption key only during key rotation:

```bash
pass insert rust-api/app/PREVIOUS_ENCRYPTION_KEY
```

Insert the SMTP username if required by the provider:

```bash
pass insert rust-api/app/SMTP_USERNAME
```

Insert the SMTP password:

```bash
pass insert rust-api/app/SMTP_PASSWORD
```

Insert the CAPTCHA secret when CAPTCHA is enabled:

```bash
pass insert rust-api/app/CAPTCHA_SECRET
```

## Read Back a Secret

To verify that a secret was inserted successfully:

```bash
pass show rust-api/app/JWT_SECRET
```

## Notes

| Secret | When it is optional |
| --- | --- |
| `JWT_PREVIOUS_SECRET` | Only during JWT secret rotation |
| `PREVIOUS_ENCRYPTION_KEY` | Only during encryption key rotation |
| `SMTP_USERNAME` | Only if the SMTP provider requires it |
| `CAPTCHA_SECRET` | Only if CAPTCHA is enabled |
