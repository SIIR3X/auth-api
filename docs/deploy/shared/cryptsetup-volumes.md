# Encrypted Volumes with cryptsetup

This guide explains how to create and mount encrypted LUKS volumes for this project.

The goal is to mount:
- `/srv/rust-api`
- `/srv/rust-api-data`

directly on encrypted storage.

## 1. Choose the Block Device

Identify the target device:

```bash
lsblk
```

Examples:
- `/dev/sdb`
- `/dev/nvme0n1p3`

Make sure the selected device is the correct one before continuing.

## 2. Create the LUKS Volume

Format the target device with LUKS:

```bash
sudo cryptsetup luksFormat /dev/YOUR_DEVICE
```

This step erases the device and creates the encrypted container.

## 3. Open the Encrypted Volume

Open the volume and assign it a mapper name.

For the application server:

```bash
sudo cryptsetup open /dev/YOUR_DEVICE rust_api_crypt
```

For the data server:

```bash
sudo cryptsetup open /dev/YOUR_DEVICE rust_api_data_crypt
```

This creates a mapped device under:

```text
/dev/mapper/<name>
```

## 4. Create the Filesystem

Create a filesystem on the opened encrypted device:

```bash
sudo mkfs.ext4 /dev/mapper/rust_api_crypt
```

or:

```bash
sudo mkfs.ext4 /dev/mapper/rust_api_data_crypt
```

## 5. Mount the Filesystem

Create the target mount point:

For the application server:

```bash
sudo mkdir -p /srv/rust-api
```

For the data server:

```bash
sudo mkdir -p /srv/rust-api-data
```

Mount the filesystem:

Application server:

```bash
sudo mount /dev/mapper/rust_api_crypt /srv/rust-api
```

Data server:

```bash
sudo mount /dev/mapper/rust_api_data_crypt /srv/rust-api-data
```

## 6. Recreate the Service Layout on the Mounted Volume

After the encrypted filesystem is mounted, create the expected project directories.

Application server:

```bash
sudo mkdir -p /srv/rust-api/compose
sudo mkdir -p /srv/rust-api/env
sudo mkdir -p /srv/rust-api/data
```

Data server:

```bash
sudo mkdir -p /srv/rust-api-data/compose
sudo mkdir -p /srv/rust-api-data/env
sudo mkdir -p /srv/rust-api-data/postgres
sudo mkdir -p /srv/rust-api-data/redis
```

## Notes

| Topic | Recommendation |
| --- | --- |
| Mount points | Keep `/srv/rust-api` and `/srv/rust-api-data` as the final paths |
| Docker | No Compose change is needed if the mounted paths remain the same |
| Timing | Set this up before copying runtime files or storing service data |
| Backup | Back up recovery material securely before relying on the encrypted volume |
