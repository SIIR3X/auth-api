# Data Server Secrets

Store these values in `pass`:
- [pass-store.md](./pass-store.md)

## Secrets

| Variable | Purpose | Impact if compromised |
| --- | --- | --- |
| `POSTGRES_DB` | Target database name used by PostgreSQL | Database targeting and migration errors |
| `POSTGRES_USER` | Application database user | Helps authenticate to PostgreSQL when paired with the password |
| `POSTGRES_PASSWORD` | PostgreSQL password | Direct database access |
| `REDIS_PASSWORD` | Redis password | Direct Redis access |
