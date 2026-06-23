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

Open the PR on GitHub. The CI checks must pass before the merge is allowed. Merge using **"Create a merge commit"** — this keeps the merged `staging` tip as the merge commit's second parent, so `staging` stays an ancestor of `main`. The `backmerge.yml` workflow then fast-forwards `staging` back onto `main` automatically, keeping the two branches in sync.

> Do **not** use "Rebase and merge" or "Squash and merge": both rewrite the staging commits to new SHAs, which makes `staging` diverge from `main` and breaks the automatic back-merge (its `git merge --ff-only` would fail).

### 3. Create and push the tag

Must be done from `main` — the tag must point to a commit on `main` to trigger the workflow correctly.

```bash
git checkout main
git pull
git tag v1.2.3
git push --tags
```

This triggers the `docker-publish` workflow. The image and the GitHub Release are created automatically.

### 4. Verify

- Check the workflow run on GitHub Actions
- Confirm the image is available on GHCR: `ghcr.io/siir3x/auth-api:1.2.3` (the `v` prefix is stripped from image tags)
- Confirm the GitHub Release includes the `migrations.tar.gz` asset
