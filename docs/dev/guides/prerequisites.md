# Prerequisites

## Required

### Rust

Install via [rustup](https://rustup.rs):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Verify:

```bash
rustc --version
cargo --version
```

---

### Docker

Install via the official script:

```bash
curl -fsSL https://get.docker.com | sh
```

Verify:

```bash
docker --version
docker compose version
```

## For code quality checks (`make quality`)

### cargo-deny

```bash
cargo install cargo-deny --locked
```

## For tests (`make test`)

### cargo-nextest

```bash
cargo install cargo-nextest --locked
```

## For coverage (`make coverage`)

### cargo-tarpaulin

Linux only.

```bash
cargo install cargo-tarpaulin --locked
```

## For tests with email (`make test`)

### Mailpit

```bash
curl -sSL https://github.com/axllent/mailpit/releases/latest/download/mailpit-linux-amd64.tar.gz \
  | tar -xz mailpit
sudo mv mailpit /usr/local/bin/mailpit
```

Verify:

```bash
mailpit --version
```

## For production deployment

### pass

Password manager used to store and retrieve secrets before deployment.

```bash
# Debian / Ubuntu
sudo apt install pass

# Arch
sudo pacman -S pass
```
