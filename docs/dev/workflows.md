# Workflows

This document summarizes the GitHub Actions workflows used in this repository.

## Workflow Overview

| Workflow | File | Trigger | Purpose |
| --- | --- | --- | --- |
| Code Checks | [code-checks.yml](../../.github/workflows/code-checks.yml) | Pull request to `main` | Runs Rust formatting, linting, and tests |
| Docker Checks | [docker-checks.yml](../../.github/workflows/docker-checks.yml) | Pull request to `main` | Lints Docker, scans config, builds images, and scans them |
| Security | [security.yml](../../.github/workflows/security.yml) | Pull request to `main` | Runs dependency and secret security checks and generates the SBOM |
| Publish Docker Images | [docker-publish.yml](../../.github/workflows/docker-publish.yml) | Push of a tag matching `v*` | Builds and publishes the application and migrations images to GHCR |

## Details

| Workflow | Main steps |
| --- | --- |
| Code Checks | `cargo fmt --check`, `cargo clippy`, `cargo test` |
| Docker Checks | `hadolint`, `semgrep`, Docker build for app and migrations, `trivy` scans |
| Security | `cargo audit`, `cargo deny`, `gitleaks`, SBOM generation |
| Publish Docker Images | Docker metadata extraction, build, and push for both images |
