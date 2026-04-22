# Database Deployment

Previous: [Secrets](../api/secrets.md) | [Index](../README.md) | Next: [API Deployment](../api/deployment.md)

## Overview

PostgreSQL and Redis each run on a dedicated VPS. The API server connects to them exclusively through a WireGuard VPN — database ports are never exposed on the public network.

```
API VPS (10.0.0.1) ── WireGuard VPN ── DB VPS (10.0.0.2)
```

## 1. WireGuard VPN

**On both VPS** — install WireGuard:

```bash
sudo apt update
sudo apt install -y wireguard
```

---

### 1.1 Generate keys

Keys are stored in a dedicated directory with restricted permissions.

**On the DB VPS:**

```bash
sudo mkdir -p /etc/wireguard/keys
sudo chmod 700 /etc/wireguard/keys

wg genkey | sudo tee /etc/wireguard/keys/wg0_private.key | wg pubkey | sudo tee /etc/wireguard/keys/wg0_public.key
sudo chmod 600 /etc/wireguard/keys/wg0_private.key
```

**On the API VPS:**

```bash
sudo mkdir -p /etc/wireguard/keys
sudo chmod 700 /etc/wireguard/keys

wg genkey | sudo tee /etc/wireguard/keys/wg0_private.key | wg pubkey | sudo tee /etc/wireguard/keys/wg0_public.key
sudo chmod 600 /etc/wireguard/keys/wg0_private.key
```

---

### 1.2 Configure WireGuard on the DB VPS

**On the DB VPS** — create `/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address = 10.0.0.2/24
PrivateKey = <contents of /etc/wireguard/keys/wg0_private.key>
ListenPort = 51820

[Peer]
PublicKey = <contents of /etc/wireguard/keys/wg0_public.key from the API VPS>
AllowedIPs = 10.0.0.1/32
```

---

### 1.3 Configure WireGuard on the API VPS

**On the API VPS** — create `/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address = 10.0.0.1/24
PrivateKey = <contents of /etc/wireguard/keys/wg0_private.key>

[Peer]
PublicKey = <contents of /etc/wireguard/keys/wg0_public.key from the DB VPS>
Endpoint = <DB_VPS_PUBLIC_IP>:51820
AllowedIPs = 10.0.0.2/32
PersistentKeepalive = 25
```

---

### 1.4 Start and enable WireGuard

**On both VPS:**

```bash
sudo systemctl enable --now wg-quick@wg0
```

---

### 1.5 Open the firewall for WireGuard

**On the DB VPS** — allow the WireGuard UDP port from the API VPS public IP only:

```bash
sudo ufw allow from <API_VPS_PUBLIC_IP> to any port 51820 proto udp
```

---

### 1.6 Verify connectivity

**On the API VPS:**

```bash
ping 10.0.0.2
```

## 2. PostgreSQL

**On the DB VPS** — install PostgreSQL:

```bash
sudo apt update
sudo apt install -y postgresql postgresql-contrib
```

---

### 2.1 Create the database and user

**On the DB VPS:**

```bash
sudo -u postgres psql
```

```sql
CREATE USER rust_api WITH PASSWORD 'your-strong-password';
CREATE DATABASE rust_api OWNER rust_api;
GRANT ALL PRIVILEGES ON DATABASE rust_api TO rust_api;
\q
```

---

### 2.2 Allow connections on the VPN interface

**On the DB VPS** — edit `/etc/postgresql/<version>/main/postgresql.conf`:

```conf
listen_addresses = '10.0.0.2'
```

Edit `/etc/postgresql/<version>/main/pg_hba.conf` — allow the API VPS via its VPN IP only:

```conf
host    rust_api    rust_api    10.0.0.1/32    scram-sha-256
```

Restart PostgreSQL:

```bash
sudo systemctl restart postgresql
```

---

### 2.3 Open the firewall

**On the DB VPS:**

```bash
sudo ufw allow from 10.0.0.1 to any port 5432
```

---

### 2.4 Verify connectivity

**On the API VPS:**

```bash
psql "$(pass prod/rust-api/database-url)"
```

---

### 2.5 Run migrations

Each release publishes a `migrations.tar.gz` asset on GitHub. The archive is fetched directly into `/dev/shm` (RAM) — nothing is written to disk.

**On the API VPS** — install `sqlx-cli`:

```bash
cargo install sqlx-cli --no-default-features --features rustls,postgres --locked
```

Fetch and run migrations:

```bash
curl -sL https://github.com/SIIR3X/rust-api/releases/latest/download/migrations.tar.gz \
  | tar -xz -C /dev/shm

DATABASE_URL=$(pass prod/rust-api/database-url) \
  sqlx migrate run --source /dev/shm/migrations

rm -rf /dev/shm/migrations
```

## 3. Redis

**On the DB VPS** — install Redis:

```bash
sudo apt update
sudo apt install -y redis-server
```

---

### 3.1 Configure authentication and binding

**On the DB VPS** — inject the password from `pass` and bind to the VPN interface:

```bash
REDIS_PASSWORD=$(pass prod/rust-api/redis-password)
sudo sed -i "s/^# requirepass .*/requirepass ${REDIS_PASSWORD}/" /etc/redis/redis.conf
sudo sed -i "s/^bind .*/bind 10.0.0.2/" /etc/redis/redis.conf
```

Restart Redis:

```bash
sudo systemctl restart redis
```

---

### 3.2 Open the firewall

**On the DB VPS:**

```bash
sudo ufw allow from 10.0.0.1 to any port 6379
```

---

### 3.3 Verify connectivity

**On the API VPS:**

```bash
redis-cli -h 10.0.0.2 ping
```

