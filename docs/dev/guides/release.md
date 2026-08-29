# Creating a Release

A release is a bundle built on a trusted machine and copied to the server: no
registry, no hosted CI.

## 1. Pass the gate

On the commit to release, with a clean working tree:

```bash
make test-infra-up
make ci
make docker-check
```

## 2. Update the changelog and tag

Move the `Unreleased` entries of [`CHANGELOG.md`](../../../CHANGELOG.md) under
the new version, set `version` in `Cargo.toml`, commit, then tag:

```bash
git tag -a v1.2.3 -m "auth-api 1.2.3"
```

## 3. Build the bundle

```bash
make release VERSION=1.2.3
```

`dist/auth-api-1.2.3/` then holds:

| File | Purpose |
|------|---------|
| `auth-api-1.2.3.image.tar.gz` | The production image (`auth-api:1.2.3`) |
| `migrations/` | Every migration of this version |
| `docker-compose.api.yml`, `config.prod.env` | Deployment files of this version |
| `nginx/nginx.conf` | Reverse proxy configuration |
| `scripts/backup-db.sh`, `scripts/restore-db.sh` | Database backup and restore (DB VPS) |
| `SHA256SUMS` | Checksums of every file above |

Record the checksum of `SHA256SUMS` itself (`sha256sum dist/auth-api-1.2.3/SHA256SUMS`)
somewhere other than the server: it is what proves the bundle was not altered
on the way.

## 4. Deploy

See [Deploying a New Release](../../deploy/guides/update.md).
