# Application Server Secrets

Store these values in `pass`:
- [pass-store.md](./pass-store.md)

## Secrets

| Variable | Purpose | Impact if compromised |
| --- | --- | --- |
| `DATABASE_URL` | Connects the application to PostgreSQL | Full database compromise depending on database role privileges |
| `REDIS_URL` | Connects the application to Redis | Session, cache, and rate-limit manipulation |
| `JWT_SECRET` | Signs access tokens | Attackers can forge valid access tokens |
| `ENCRYPTION_KEY` | Encrypts TOTP secrets at rest | Stored TOTP secrets may be decrypted |
| `SMTP_USERNAME` | SMTP account identifier | Helps attackers target the mail account |
| `SMTP_PASSWORD` | Authenticates to the SMTP provider | Unauthorized email sending and account abuse |
| `CAPTCHA_SECRET` | Verifies CAPTCHA responses | CAPTCHA protection can be bypassed or abused |

## Rotation-Only Secrets

| Variable | Purpose |
| --- | --- |
| `JWT_PREVIOUS_SECRET` | Accepts tokens signed with the previous JWT key during JWT rotation |
| `PREVIOUS_ENCRYPTION_KEY` | Allows TOTP secret re-encryption during key rotation |
