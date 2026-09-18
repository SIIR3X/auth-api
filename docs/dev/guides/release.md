# Creating a Release

A release is a bundle built on a trusted machine and copied to the server: no
registry. The hosted CI checks every change but never builds, signs or
publishes a release: the release key stays on the trusted machine.

## 0. Create the release key (once)

Bundles are signed with an SSH key kept on the trusted machine:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/auth-api-release -C auth-api-release
```

Copy `~/.ssh/auth-api-release.pub` to each server out of band (see the
[API deployment](../../deploy/api/deployment.md#13-copy-and-verify-the-bundle)):
a bundle must never carry the key that verifies it.

## 1. Pass the gate

On the commit to release, with a clean working tree:

```bash
make docker-refresh-pins   # base images: pick up security fixes, then commit
make test-infra-up
make ci
make docker-check          # hadolint on both Dockerfiles, Trivy fails on HIGH/CRITICAL
```

## 2. Update the changelog and tag

Move the `Unreleased` entries of [`CHANGELOG.md`](../../../CHANGELOG.md) under
the new version, set `version` in `Cargo.toml`, commit, then tag:

```bash
git tag -a v1.2.3 -m "auth-api 1.2.3"
```

## 3. Build the bundle

```bash
make release VERSION=1.2.3 RELEASE_SIGNING_KEY=~/.ssh/auth-api-release
```

The target refuses to run when the working tree has changes or untracked
files, when `VERSION` differs from `version` in `Cargo.toml`, or when the tag
`v1.2.3` does not point at `HEAD` (`ALLOW_UNTAGGED=1` builds a test bundle).
The image is built from `git archive HEAD`, so nothing outside the commit can
reach it, labelled with the version and commit, and scanned by Trivy: a
HIGH or CRITICAL vulnerability with a fix stops the release.

`dist/auth-api-1.2.3/` then holds:

| File | Purpose |
|------|---------|
| `auth-api-1.2.3.image.tar.gz` | The production image (`auth-api:1.2.3`), distroless, non-root |
| `IMAGE_ID` | Identifier of that image, checked after `docker load` |
| `migrations/` | Every migration of this version |
| `docker-compose.api.yml`, `config.prod.env` | Deployment files of this version |
| `nginx/nginx.conf` | Reverse proxy configuration |
| `scripts/backup-db.sh`, `scripts/restore-db.sh`, `scripts/backup-drill.sh` | Database backup, restore and drill (DB VPS) |
| `docs/deploy/guides/prometheus-alerts.yml` | Alert rules for the monitoring host |
| `SHA256SUMS` | Checksums of every file above |
| `SHA256SUMS.sig` | Signature of `SHA256SUMS` by the release key |

## 4. Deploy

See [Deploying a New Release](../../deploy/guides/update.md).
