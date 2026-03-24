# cryptsetup Volumes

This guide explains how to create and mount encrypted LUKS volumes for:
- `/srv/rust-api`
- `/srv/rust-api-data`

The goal is to keep both server roots on encrypted storage while preserving the same paths used by the deployment files.

## Target Layout

| Server | Encrypted mount |
| --- | --- |
| Application server | `/srv/rust-api` |
| Data server | `/srv/rust-api-data` |

## Step 1: Choose the Block Device

Identify the target disk or partition:

```bash
lsblk
```

Examples:
- `/dev/sdb1`
- `/dev/nvme0n1p3`

Be certain that the selected device is the correct one.
Formatting it will destroy any existing data on that device.

## Step 2: Format the Device with LUKS

Example:

```bash
sudo cryptsetup luksFormat /dev/DEVICE_NAME
```

You will be asked to confirm the operation and provide the unlock passphrase.

## Step 3: Open the Encrypted Device

Application server example:

```bash
sudo cryptsetup open /dev/DEVICE_NAME rust_api_crypt
```

Data server example:

```bash
sudo cryptsetup open /dev/DEVICE_NAME rust_api_data_crypt
```

This creates a mapped device under:

```text
/dev/mapper/...
```

## Step 4: Create a Filesystem

Application server example:

```bash
sudo mkfs.ext4 /dev/mapper/rust_api_crypt
```

Data server example:

```bash
sudo mkfs.ext4 /dev/mapper/rust_api_data_crypt
```

## Step 5: Mount the Volume

Application server:

```bash
sudo mkdir -p /srv/rust-api
sudo mount /dev/mapper/rust_api_crypt /srv/rust-api
```

Data server:

```bash
sudo mkdir -p /srv/rust-api-data
sudo mount /dev/mapper/rust_api_data_crypt /srv/rust-api-data
```

## Step 6: Verify the Mount

```bash
mount | grep '/srv/rust-api\|/srv/rust-api-data'
df -h /srv/rust-api /srv/rust-api-data 2>/dev/null || true
```

## Step 7: Create the Deployment Layout on Top of the Mounted Volume

Once the encrypted volume is mounted, create the directories described by the setup guides.

Application server:

```bash
mkdir -p /srv/rust-api/compose
mkdir -p /srv/rust-api/env
mkdir -p /srv/rust-api/data
```

Data server:

```bash
mkdir -p /srv/rust-api-data/compose
mkdir -p /srv/rust-api-data/env
mkdir -p /srv/rust-api-data/postgres
mkdir -p /srv/rust-api-data/redis
```

## Notes

| Topic | Recommendation |
| --- | --- |
| Existing data | Set up the encrypted mount before writing real deployment data |
| Mount paths | Keep the exact `/srv/rust-api` and `/srv/rust-api-data` paths so Docker Compose does not need changes |
| Persistence | Configure system startup mounting only after validating the layout manually |
| Recovery | Back up the LUKS passphrase securely |
