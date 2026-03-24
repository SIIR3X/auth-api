# cryptsetup Installation

This guide explains how to install `cryptsetup` before setting up encrypted storage for:
- `/srv/rust-api`
- `/srv/rust-api-data`

This document only covers installation and verification.
Volume creation and mounting can be documented separately.

## What `cryptsetup` Is Used For

`cryptsetup` is the Linux tool used to manage encrypted block devices, usually with LUKS.

In this project, it is intended to protect the storage that will hold:
- application runtime files
- PostgreSQL data
- Redis data
- local deployment assets

## Install on Debian or Ubuntu

```bash
sudo apt update
sudo apt install -y cryptsetup
```

## Verify the Installation

Check that the binary is available:

```bash
cryptsetup --version
```

You should see a version string similar to:

```text
cryptsetup 2.x.x
```

## Recommended Usage in This Project

| Server | Recommended encrypted mount |
| --- | --- |
| Application server | `/srv/rust-api` |
| Data server | `/srv/rust-api-data` |

## Recommendation

Install `cryptsetup` before:
- creating the final `/srv/rust-api` layout
- creating the final `/srv/rust-api-data` layout
- writing real data into those directories
