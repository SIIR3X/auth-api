# Creating a Release

## Overview

A release is triggered by pushing a git tag matching `v*` on `main`. GitHub Actions then:

- Builds the production Docker image and pushes it to GHCR
- Creates a GitHub Release with a `migrations.tar.gz` asset

## Steps

### 1. Ensure staging is ready

All changes must be on `staging` and the CI checks must pass before opening the PR.

```bash
git checkout staging
git pull
```

### 2. Open a pull request staging → main

Open the PR on GitHub. The CI checks must pass before the merge is allowed. Merge using **"Rebase and merge"** — this keeps a linear history with no extra merge commit, so `main` and `staging` stay in sync.

### 3. Create and push the tag

Must be done from `main` — the tag must point to a commit on `main` to trigger the workflow correctly.

```bash
git checkout main
git pull
git tag v1.2.3
git push --tags
```

This triggers the `docker-publish` workflow. The image and the GitHub Release are created automatically.

### 4. Update the version badge

The version badge in `README.md` is static and must be updated manually:

```bash
# In README.md, update the version number in the badge URL
![version](https://img.shields.io/badge/version-1.2.3-blue)
```

### 5. Verify

- Check the workflow run on GitHub Actions
- Confirm the image is available on GHCR: `ghcr.io/siir3x/auth-api:v1.2.3`
- Confirm the GitHub Release includes the `migrations.tar.gz` asset
