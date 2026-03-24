# Rust Code Analysis

This guide lists the main tools used to analyze the Rust codebase.

The goal is to cover:
- formatting
- linting
- dependency security
- supply chain policy
- targeted static analysis

## Recommended Tooling

| Tool | Purpose |
| --- | --- |
| `cargo fmt` | Formats Rust source code |
| `cargo clippy` | Detects code issues, style problems, and suspicious patterns |
| `cargo audit` | Detects known vulnerabilities in dependencies |
| `cargo deny` | Enforces dependency, advisory, and license policy |
| `semgrep` | Finds security-sensitive code patterns in first-party code |

## Install the Tools

Install the Rust-based tools:

```bash
cargo install cargo-audit cargo-deny
rustup component add clippy rustfmt
```

Install Semgrep on Debian or Ubuntu:

```bash
sudo apt update
sudo apt install -y pipx
pipx ensurepath
pipx install semgrep
```

## Baseline Commands

Format check:

```bash
cargo fmt --all --check
```

Lint the whole project:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

Check the dependency advisory database:

```bash
cargo audit
```

Run dependency policy checks:

```bash
cargo deny check
```

Run Semgrep on tracked files:

```bash
semgrep scan
```

## Recommended Review Order

Run the tools in this order:

1. `cargo fmt --all --check`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo audit`
4. `cargo deny check`
5. `semgrep scan`

This order helps catch:
- style and formatting issues first
- code quality problems next
- dependency and security issues after that

## How to Read the Results

| Tool | What usually matters most |
| --- | --- |
| `cargo fmt` | Any diff means the code is not formatted consistently |
| `cargo clippy` | Warnings on correctness, suspicious logic, needless clones, inefficient patterns |
| `cargo audit` | Vulnerabilities with a fixed version available |
| `cargo deny` | Blocked advisories, license issues, or banned crates |
| `semgrep` | First-party security findings, especially auth, secrets, and proxy config issues |

## Practical Notes

| Topic | Recommendation |
| --- | --- |
| CI baseline | Keep `fmt`, `clippy`, `audit`, and `semgrep` in CI |
| Local workflow | Run `clippy` and `audit` before opening a release tag |
| False positives | Review them manually before suppressing anything |
| Security findings | Prioritize direct or reachable issues on authentication, crypto, tokens, and transport |
| Dependency fixes | Prefer targeted updates first, then broader `cargo update` only when needed |

## Suggested Minimum Standard

A good baseline for this project is:
- `cargo fmt --all --check` passes
- `cargo clippy --all-targets --all-features -- -D warnings` passes
- `cargo audit` reports no unresolved vulnerability
- `cargo deny check` passes
- `semgrep scan` reports no blocking finding
