# Docker Code Analysis

This guide lists the main tools used to analyze Docker-related files in this project.

The goal is to cover:
- Dockerfile quality
- image vulnerability scanning
- configuration-level security issues

## Recommended Tooling

| Tool | Purpose |
| --- | --- |
| `hadolint` | Lints the Dockerfile and flags Docker best-practice issues |
| `trivy` | Scans container images, filesystems, and configuration for vulnerabilities and misconfiguration |
| `semgrep` | Detects risky patterns in Dockerfiles and deployment config |

## Install the Tools

Install Hadolint on Debian or Ubuntu:

```bash
sudo apt update
sudo apt install -y hadolint
```

Install Trivy on Debian or Ubuntu:

```bash
sudo apt update
sudo apt install -y wget gnupg lsb-release apt-transport-https
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | \
  gpg --dearmor | \
  sudo tee /usr/share/keyrings/trivy.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | \
  sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt update
sudo apt install -y trivy
```

Install Semgrep if it is not already installed:

```bash
sudo apt update
sudo apt install -y pipx
pipx ensurepath
pipx install semgrep
```

## Baseline Commands

Lint the Dockerfile:

```bash
hadolint Dockerfile
```

Scan Docker-related tracked files:

```bash
semgrep scan
```

Build the application image locally:

```bash
docker build -t rust-api:local .
```

Scan the built application image:

```bash
trivy image rust-api:local
```

Build the migrations image locally:

```bash
docker build --target migrations -t rust-api-migrations:local .
```

Scan the migrations image:

```bash
trivy image rust-api-migrations:local
```

## Recommended Review Order

Run the tools in this order:

1. `hadolint Dockerfile`
2. `semgrep scan`
3. `docker build -t rust-api:local .`
4. `trivy image rust-api:local`
5. `docker build --target migrations -t rust-api-migrations:local .`
6. `trivy image rust-api-migrations:local`

This order helps catch:
- Dockerfile issues before image build
- config issues before runtime scanning
- image vulnerabilities after build

## How to Read the Results

| Tool | What usually matters most |
| --- | --- |
| `hadolint` | Root user, unpinned packages, unnecessary layers, weak defaults |
| `semgrep` | Risky proxy config, missing non-root user, obvious secret-like material |
| `trivy` | High and critical vulnerabilities in runtime images and OS packages |

## Practical Notes

| Topic | Recommendation |
| --- | --- |
| Runtime image | Prefer non-root, minimal packages, and read-only mounts where possible |
| Migrations image | Apply the same non-root standard as the app image |
| Scan scope | Scan both the application image and the migrations image |
| Findings | Fix high-confidence config issues first, then OS package vulnerabilities |
| CI baseline | Keep `hadolint` and at least one image scan in CI if build time allows |

## Suggested Minimum Standard

A good baseline for this project is:
- `hadolint Dockerfile` passes
- `semgrep scan` reports no Docker or proxy blocking finding
- the application image builds successfully
- the migrations image builds successfully
- `trivy image` shows no unresolved critical vulnerability in shipped images
