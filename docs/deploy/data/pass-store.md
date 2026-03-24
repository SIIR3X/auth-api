# Data Server Pass Store

This guide lists the recommended `pass` entries for the data server.

The data server should store its secrets under:

```text
rust-api/data/...
```

## Required Secrets

Insert the PostgreSQL database name:

```bash
pass insert rust-api/data/POSTGRES_DB
```

Insert the PostgreSQL administrative or migration owner username:

```bash
pass insert rust-api/data/POSTGRES_USER
```

Insert the PostgreSQL password:

```bash
pass insert rust-api/data/POSTGRES_PASSWORD
```

Insert the Redis password:

```bash
pass insert rust-api/data/REDIS_PASSWORD
```

## Read Back a Secret

To verify that a secret was inserted successfully:

```bash
pass show rust-api/data/POSTGRES_PASSWORD
```
