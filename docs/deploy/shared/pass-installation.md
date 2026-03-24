# pass Installation

This deployment model uses `pass` as the local encrypted secret store on each server.

`pass` stores secrets as GPG-encrypted files.
Without the private GPG key, the stored secrets cannot be read.

## What `pass` Is Used For

`pass` is a local encrypted password store built on top of GPG.

In this project, it is intended to protect:
- application secrets
- PostgreSQL credentials
- Redis credentials
- SMTP credentials
- cryptographic material such as JWT and TOTP keys

## Install on Debian or Ubuntu

On Debian or Ubuntu:

```bash
sudo apt update
sudo apt install -y pass gnupg2
```

## Verify the Installation

Check that both binaries are available:

```bash
pass --version
gpg --version
```

## Initialize the Store

If the server does not already have a dedicated key for secrets:

```bash
gpg --full-generate-key
```

Then list the available secret keys:

```bash
gpg --list-secret-keys --keyid-format=long
```

Choose the key ID that will be used to encrypt the password store.

Initialize `pass` with the selected key ID:

```bash
pass init YOUR_KEY_ID
```

This creates the local password store in:

```text
~/.password-store
```

## Validate the Store

Insert a temporary test secret:

```bash
pass insert test/example
```

Read it back:

```bash
pass show test/example
```

If both commands succeed, the store is ready.

## Recommended Usage in This Project

| Server | Recommended secret prefix |
| --- | --- |
| Application server | `rust-api/app/...` |
| Data server | `rust-api/data/...` |

## Recommendations

| Topic | Recommendation |
| --- | --- |
| Key separation | Use one GPG key per server if possible |
| Backups | Back up the private GPG key and the `~/.password-store` directory |
| Access | Restrict shell access to trusted operators only |
| Rotation | Rotate secrets inside `pass` when credentials change |
| Naming | Keep a stable hierarchy such as `rust-api/app/...` and `rust-api/data/...` |
