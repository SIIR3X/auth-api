# Data Server pass Entries

This document lists the `pass` entries required on the data server.

## Recommended Entry Names

```text
rust-api/data/POSTGRES_DB
rust-api/data/POSTGRES_USER
rust-api/data/POSTGRES_PASSWORD
rust-api/data/REDIS_PASSWORD
```

## Create the Required Entries

```bash
pass insert rust-api/data/POSTGRES_DB
pass insert rust-api/data/POSTGRES_USER
pass insert rust-api/data/POSTGRES_PASSWORD
pass insert rust-api/data/REDIS_PASSWORD
```

Recommended values:

| Entry | Recommended value |
| --- | --- |
| `rust-api/data/POSTGRES_DB` | `rust_api` |
| `rust-api/data/POSTGRES_USER` | `rust_api_migrator` |
| `rust-api/data/POSTGRES_PASSWORD` | Strong random password |
| `rust-api/data/REDIS_PASSWORD` | Strong random password |

## Read Back a Secret

Example:

```bash
pass show rust-api/data/POSTGRES_PASSWORD
```
