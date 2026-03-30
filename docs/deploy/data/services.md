# Data Services

[Back to setup](setup.md) | [Next: Database](database.md)

## 1. Create the directories

```bash
sudo mkdir -p /srv/rust-api-data/compose
sudo mkdir -p /srv/rust-api-data/env
sudo mkdir -p /srv/rust-api-data/postgres
sudo mkdir -p /srv/rust-api-data/redis
sudo mkdir -p /srv/rust-api-data/observability/rust-api/alloy-data
```

## 2. Create the `pass` entries

On the data server:

```bash
pass insert rust-api/data/postgres_db
pass insert rust-api/data/postgres_user
pass insert rust-api/data/postgres_password
pass insert rust-api/data/redis_password
pass insert rust-api/observability/postgres_grafana_password
```

Recommended values:
- `rust-api/data/postgres_db` -> `rust_api`
- `rust-api/data/postgres_user` -> `rust_api_migrator`

## 3. Create `runtime.env`

```bash
sudo nano /srv/rust-api-data/env/runtime.env
```

Use [runtime.env.example](../../../deploy/data/runtime.env.example) as the reference and set:

```text
POSTGRES_VERSION=17
POSTGRES_BIND_IP=__DATA_SERVER_PRIVATE_IP__
POSTGRES_PORT=5432
POSTGRES_LISTEN_ADDRESSES=0.0.0.0
POSTGRES_MAX_CONNECTIONS=200
POSTGRES_DATA_DIR=/srv/rust-api-data/postgres

REDIS_VERSION=7.2-alpine
REDIS_BIND_IP=__DATA_SERVER_PRIVATE_IP__
REDIS_PORT=6379
REDIS_DATA_DIR=/srv/rust-api-data/redis
```

Replace `__DATA_SERVER_PRIVATE_IP__` with the private IP already allowed from the application server.

## 4. Create the compose file

```bash
sudo nano /srv/rust-api-data/compose/docker-compose.yml
```

Use [docker-compose.yml](../../../deploy/data/docker-compose.yml) as the reference.

## 5. Export the secrets

```bash
export POSTGRES_DB="$(pass show rust-api/data/postgres_db)"
export POSTGRES_USER="$(pass show rust-api/data/postgres_user)"
export POSTGRES_PASSWORD="$(pass show rust-api/data/postgres_password)"
export REDIS_PASSWORD="$(pass show rust-api/data/redis_password)"
```

## 6. Start PostgreSQL and Redis

```bash
docker compose \
  --env-file /srv/rust-api-data/env/runtime.env \
  -f /srv/rust-api-data/compose/docker-compose.yml \
  pull

docker compose \
  --env-file /srv/rust-api-data/env/runtime.env \
  -f /srv/rust-api-data/compose/docker-compose.yml \
  up -d
```

## 7. Validate the services

```bash
cd /srv/rust-api-data/compose
docker compose ps
docker compose logs postgres --tail 50
docker compose logs redis --tail 50
```

Validate Redis:

```bash
redis-cli -h 127.0.0.1 -p 6379 -a "$REDIS_PASSWORD" ping
```

Expected result:

```text
PONG
```
