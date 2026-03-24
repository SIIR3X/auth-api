# Image Release

This guide explains how Docker images are built and published for this project.

The repository publishes two images:
- the application image
- the migrations image

## Published Images

| Image | Purpose |
| --- | --- |
| `ghcr.io/<owner>/rust-api` | Runs the application container |
| `ghcr.io/<owner>/rust-api-migrations` | Runs database migrations |

## Trigger

Image publication is triggered by pushing a Git tag that starts with `v`.

Examples:
- `v1.0.0`
- `v1.2.3`

The workflow file is:
- [docker-publish.yml](../../.github/workflows/docker-publish.yml)

## Create a Release Tag

Create and push a tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Once the tag is pushed, GitHub Actions will:
- build the application image
- build the migrations image
- push both images to GHCR

## Published Tags

For each release tag, the workflow publishes:
- the Git tag itself
- a commit SHA tag

Examples:
- `ghcr.io/<owner>/rust-api:v1.0.0`
- `ghcr.io/<owner>/rust-api:sha-<commit>`
- `ghcr.io/<owner>/rust-api-migrations:v1.0.0`
- `ghcr.io/<owner>/rust-api-migrations:sha-<commit>`

## Result

After a successful tagged release, the project publishes:
- one application image
- one migrations image

Deployment and image consumption are documented separately in the server setup guides.
