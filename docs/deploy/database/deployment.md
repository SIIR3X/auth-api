# Database Deployment

Previous: [Secrets](../api/secrets.md) | [Index](../README.md) | Next: [API Deployment](../api/deployment.md)

## Overview

PostgreSQL and Redis each run on a dedicated VPS. The API server connects to them exclusively through a WireGuard VPN - database ports are never exposed on the public network.

```
API VPS (10.0.0.1) -- WireGuard VPN -- DB VPS (10.0.0.2)
```

## 1. WireGuard VPN

**On both VPS** - install WireGuard:

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

wg genkey | sudo tee /etc/wireguard/keys/wg10_private.key | wg pubkey | sudo tee /etc/wireguard/keys/wg10_public.key
sudo chmod 600 /etc/wireguard/keys/wg10_private.key
```

**On the API VPS:**

```bash
sudo mkdir -p /etc/wireguard/keys
sudo chmod 700 /etc/wireguard/keys

wg genkey | sudo tee /etc/wireguard/keys/wg10_private.key | wg pubkey | sudo tee /etc/wireguard/keys/wg10_public.key
sudo chmod 600 /etc/wireguard/keys/wg10_private.key
```

---

### 1.2 Configure WireGuard on the DB VPS

**On the DB VPS** - create `/etc/wireguard/wg10.conf`:

```ini
[Interface]
Address = 10.0.0.2/24
PrivateKey = <contents of /etc/wireguard/keys/wg10_private.key>
ListenPort = 51820

[Peer]
PublicKey = <contents of /etc/wireguard/keys/wg10_public.key from the API VPS>
AllowedIPs = 10.0.0.1/32
```

---

### 1.3 Configure WireGuard on the API VPS

**On the API VPS** - create `/etc/wireguard/wg10.conf`:

```ini
[Interface]
Address = 10.0.0.1/24
PrivateKey = <contents of /etc/wireguard/keys/wg10_private.key>

[Peer]
PublicKey = <contents of /etc/wireguard/keys/wg10_public.key from the DB VPS>
Endpoint = <DB_VPS_PUBLIC_IP>:51820
AllowedIPs = 10.0.0.2/32
PersistentKeepalive = 25
```

---

### 1.4 Start and enable WireGuard

**On both VPS:**

```bash
sudo systemctl enable --now wg-quick@wg10
```

---

### 1.5 Open the firewall

**On the DB VPS** - allow the WireGuard UDP port from the API VPS public IP only:

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

**On the DB VPS** - install PostgreSQL:

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
CREATE USER auth_api WITH PASSWORD 'your-strong-password';
CREATE DATABASE auth_api OWNER auth_api;
GRANT ALL PRIVILEGES ON DATABASE auth_api TO auth_api;
\q
```

---

### 2.2 Allow connections on the VPN interface

**On the DB VPS** - edit `/etc/postgresql/<version>/main/postgresql.conf`:

```conf
listen_addresses = '10.0.0.2'
```

Edit `/etc/postgresql/<version>/main/pg_hba.conf` - allow the API VPS via its VPN IP only:

```conf
host    auth_api    auth_api    10.0.0.1/32    scram-sha-256
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
psql "$(pass prod/auth-api/database-url)"
```

---

### 2.5 Run migrations

Each release publishes a `migrations.tar.gz` asset on GitHub. The archive is fetched directly into `/dev/shm` (RAM) - nothing is written to disk.

**On the API VPS** - install `sqlx-cli`:

```bash
cargo install sqlx-cli --no-default-features --features rustls,postgres --locked
```

Fetch and run migrations:

```bash
curl -sL https://github.com/SIIR3X/auth-api/releases/latest/download/migrations.tar.gz \
  | tar -xz -C /dev/shm

DATABASE_URL=$(pass prod/auth-api/database-url) \
  sqlx migrate run --source /dev/shm/migrations

rm -rf /dev/shm/migrations
```

## 3. Appsmith

**On the DB VPS** - install Docker:

```bash
curl -fsSL https://get.docker.com | sh
```

---

### 3.1 Create the Appsmith user

```bash
sudo -u postgres psql -d auth_api
```

```sql
CREATE USER appsmith WITH PASSWORD '<strong-password>';
GRANT CONNECT ON DATABASE auth_api TO appsmith;
GRANT USAGE ON SCHEMA public TO appsmith;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO appsmith;
ALTER DEFAULT PRIVILEGES FOR ROLE auth_api IN SCHEMA public
    GRANT SELECT ON TABLES TO appsmith;
\q
```

---

### 3.2 Deploy Appsmith

```bash
mkdir -p /srv/auth-api && cd /srv/auth-api
curl -O https://raw.githubusercontent.com/SIIR3X/auth-api/main/docker-compose.db.yml
docker compose -f docker-compose.db.yml up -d
```

Appsmith is bound to `127.0.0.1:8080` - never exposed publicly.

---

### 3.3 Access the panel

From your local machine, open an SSH tunnel:

```powershell
ssh -L 8080:127.0.0.1:8080 -p 2222 <username>@<db-vps-vpn-ip>
```

Then open `http://localhost:8080`.

---

### 3.4 Connect to the database

In Appsmith: **Settings -> Datasources -> New datasource -> PostgreSQL**

- Host: `localhost`
- Port: `5432`
- Database: `auth_api`
- Username: `appsmith`
- Password: the password set in 3.1

## 4. Redis

**On the DB VPS** - install Redis:

```bash
sudo apt update
sudo apt install -y redis-server
```

---

### 4.1 Configure authentication and binding

**On the DB VPS** - inject the password from `pass` and bind to the VPN interface:

```bash
REDIS_PASSWORD=$(pass prod/auth-api/redis-password)
sudo sed -i "s/^# requirepass .*/requirepass ${REDIS_PASSWORD}/" /etc/redis/redis.conf
sudo sed -i "s/^bind .*/bind 10.0.0.2/" /etc/redis/redis.conf
```

Restart Redis:

```bash
sudo systemctl restart redis
```

---

### 4.2 Open the firewall

**On the DB VPS:**

```bash
sudo ufw allow from 10.0.0.1 to any port 6379
```

---

### 4.3 Verify connectivity

**On the API VPS:**

```bash
redis-cli -h 10.0.0.2 ping
```

## 5. Backups

Backups are encrypted with [age](https://github.com/FiloSottile/age) before touching disk.
The private key never lives on the DB VPS - only the public key is needed to encrypt.

---

### 5.1 Generate a key pair

Run this **on a secure machine** (your laptop, a password manager export, etc.) - not the DB VPS.

**Linux / macOS:**

```bash
age-keygen -o backup.key
```

**Windows (WSL):**

```bash
sudo apt install age
age-keygen -o backup.key
```

**Windows (native) - via winget:**

```powershell
winget install FiloSottile.age
age-keygen.exe -o backup.key
```

Output looks like:

```
# created: 2026-01-01T00:00:00+00:00
# public key: age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AGE-SECRET-KEY-1...
```

Store `backup.key` somewhere safe and offline (e.g. alongside your other secrets in `pass`).

---

### 5.2 Install age on the DB VPS

```bash
sudo apt update
sudo apt install -y age
```

---

### 5.3 Deploy the backup script

**On the DB VPS** - fetch the script from the repository, then set the public key:

```bash
sudo mkdir -p /opt/auth-api
curl -sL https://raw.githubusercontent.com/SIIR3X/auth-api/main/scripts/backup-db.sh \
    | sudo tee /opt/auth-api/backup-db.sh > /dev/null
sudo chmod 700 /opt/auth-api/backup-db.sh
sudo chown root:root /opt/auth-api/backup-db.sh
```

Edit the script and replace `AGE_PUBLIC_KEY` with the public key from step 5.1:

```bash
sudo nano /opt/auth-api/backup-db.sh
# AGE_PUBLIC_KEY="age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

---

### 5.4 Test the script

```bash
sudo /opt/auth-api/backup-db.sh
ls -lh /var/backups/auth-api/
```

---

### 5.5 Schedule via cron

```bash
sudo crontab -e
```

Add:

```
0 2 * * * /opt/auth-api/backup-db.sh >> /var/log/auth-api-backup.log 2>&1
```

Backups run nightly at 2:00 AM and are retained for 7 days.

---

### 5.6 Restore a backup

On any machine that has the private key and `psql` available:

```bash
age --decrypt -i backup.key auth_api_YYYYMMDD_HHMMSS.sql.gz.age \
    | gunzip \
    | psql "postgres://auth_api:<password>@<host>/auth_api"
```

