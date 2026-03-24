# cryptsetup Installation

This deployment model can use `cryptsetup` to encrypt the storage used by each server.

`cryptsetup` is the Linux tool commonly used with LUKS to encrypt block devices and partitions.

## What `cryptsetup` Is Used For

`cryptsetup` is used to protect server data at rest.

In this project, it is intended to protect:
- `/srv/rust-api`
- `/srv/rust-api-data`

This means the storage remains unreadable without the decryption key if the disk or raw device is accessed outside the running system.

## Install on Debian or Ubuntu

On Debian or Ubuntu:

```bash
sudo apt update
sudo apt install -y cryptsetup
```

## Verify the Installation

Check that the binary is available:

```bash
cryptsetup --version
```

## Recommended Usage in This Project

| Server | Recommended encrypted mount point |
| --- | --- |
| Application server | `/srv/rust-api` |
| Data server | `/srv/rust-api-data` |

## Notes

| Topic | Recommendation |
| --- | --- |
| Timing | Set up encrypted storage before placing deployment files or service data on the server |
| Scope | Encrypt the full service root, not only one subdirectory |
| Pairing | Use `cryptsetup` together with `pass`, not instead of it |
| Protection level | `cryptsetup` protects data at rest, not a fully compromised running system |
