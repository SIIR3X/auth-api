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

### 2.2 Configure PostgreSQL

**On the DB VPS** - install the settings shipped in the release bundle
(`deploy/db/`). They listen on the VPN address only and size PostgreSQL for
profile M; the comments give the values of the other profiles (see
[capacity planning](../guides/operations.md#9-capacity-planning)):

```bash
sudo cp deploy/db/postgresql.auth-api.conf /etc/postgresql/17/main/conf.d/auth-api.conf
```

Edit `/etc/postgresql/17/main/pg_hba.conf` - allow the API VPS via its VPN IP only:

```conf
host    auth_api    auth_api    10.0.0.1/32    scram-sha-256
```

Restart PostgreSQL, then give the role its session limits (statements and lock
waits stop before the API's 30-second request timeout; a connection idle inside
a transaction is closed):

```bash
sudo systemctl restart postgresql
sudo -u postgres psql -d auth_api -c 'CREATE EXTENSION IF NOT EXISTS pg_stat_statements'
sudo -u postgres psql -d auth_api -f deploy/db/auth-api-role.sql
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

Migrations ship in every release bundle (see [Deploying a New Release](../guides/update.md)).
**On the API VPS**, with `sqlx-cli` installed (see [API Deployment](../api/deployment.md#12-install-docker-and-sqlx-cli)):

```bash
DATABASE_URL="$(pass prod/auth-api/database-url)?options=-c%20statement_timeout%3D0" \
  sqlx migrate run --source /srv/auth-api/releases/auth-api-X.Y.Z/migrations
```

The `options` parameter lifts the role's 25-second statement timeout for the
migration session only: a migration on a large table may run longer.

---

### 2.6 Size PostgreSQL's memory

Reads barely notice the number of accounts. Writes do, once the indexes they
update no longer fit in memory: at 1 million accounts the sign-in transaction
lost 25 to 35 % of its throughput in the performance campaign. Give PostgreSQL
enough memory to keep those indexes cached:

| Accounts | Database | Indexes updated by sign-ins and refreshes | RAM for PostgreSQL |
|---------:|---------:|------------------------------------------:|-------------------:|
| 100 000 | 1.3 GB | 0.6 GB | 2 GB |
| 1 000 000 | 10.5 GB | 4 GB | 8 GB |
| more | ~10 KB per account | ~4 KB per account | index size x 2 |

**On the DB VPS**, in `postgresql.conf`, for R GB of RAM dedicated to PostgreSQL:

```conf
shared_buffers = <R / 4>GB
effective_cache_size = <R * 3 / 4>GB
random_page_cost = 1.1        # SSD
max_wal_size = 4GB
```

The two largest tables grow with retention, not with accounts alone:
`login_attempts` keeps `CLEANUP_LOGIN_ATTEMPTS_RETENTION_DAYS` days (90) and the
audit log `AUDIT_LOG_RETENTION_MONTHS` months (12). Shortening them shrinks
the tables and their indexes in proportion.

Check whether reads are served from memory (above 0.99 is healthy):

```sql
SELECT round(blks_hit::numeric / nullif(blks_hit + blks_read, 0), 4) AS cache_hit_ratio
FROM pg_stat_database WHERE datname = 'auth_api';
```

## 3. Redis

**On the DB VPS** - install Redis:

```bash
sudo apt update
sudo apt install -y redis-server
```

---

### 3.1 Configure Redis

The settings shipped in `deploy/db/redis.auth-api.conf` bind Redis to the VPN
address, never evict a key (evicting an attempt budget would reset it), persist
to an append-only file so revocations survive a restart, and read the users
from an ACL file. Size `maxmemory` for the profile.

```bash
sudo cp deploy/db/redis.auth-api.conf /etc/redis/auth-api.conf
echo 'include /etc/redis/auth-api.conf' | sudo tee -a /etc/redis/redis.conf
```

Create the ACL file. The default user is disabled; the API's user can run
every command but the administrative and dangerous ones (`FLUSHALL`, `CONFIG`,
`KEYS`, `DEBUG`...), and only the SHA-256 of its password is stored:

```bash
REDIS_PASSWORD_SHA=$(pass prod/auth-api/redis-password | tr -d '\n' | sha256sum | cut -d' ' -f1)
printf 'user default off\nuser auth_api on #%s ~* &* +@all -@dangerous -@admin\n' "$REDIS_PASSWORD_SHA" \
  | sudo tee /etc/redis/users.acl > /dev/null
sudo chown redis:redis /etc/redis/users.acl && sudo chmod 600 /etc/redis/users.acl
sudo systemctl restart redis-server
```

The API connects as that user: store `redis://auth_api:<password>@10.0.0.2:6379`
as `prod/auth-api/redis-url`.

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
redis-cli -u "$(pass prod/auth-api/redis-url)" ping
redis-cli -u "$(pass prod/auth-api/redis-url)" flushall   # must fail: NOPERM
```

---

### 3.4 Kernel settings

**On the DB VPS** - overcommit for Redis's background rewrites, minimal
swapping, and no transparent huge pages (latency spikes in both databases):

```bash
sudo cp deploy/db/sysctl-auth-api.conf /etc/sysctl.d/90-auth-api.conf
sudo sysctl --system
sudo cp deploy/db/disable-thp.service /etc/systemd/system/
sudo systemctl enable --now disable-thp
```

## 4. Backups

Two mechanisms, complementary:

| | Nightly encrypted dump (`backup-db.sh`) | pgBackRest with WAL archiving |
|---|---|---|
| Profiles | Every profile | M and L |
| Recovery point | The last night: up to 24 hours lost | Any moment of the last two weeks |
| Restore | `restore-db.sh`, into a fresh database | `pgbackrest restore --type=time` |

Keep the nightly dump even with pgBackRest: it is an independent copy, readable
with standard tools. Dumps are encrypted with
[age](https://github.com/FiloSottile/age) before touching disk, and the private
key never lives on the DB VPS - only the public key is needed to encrypt.

---

### 4.1 Generate a key pair

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

### 4.2 Install age on the DB VPS

```bash
sudo apt update
sudo apt install -y age
```

---

### 4.3 Deploy the backup script

**On the DB VPS** - install the script from the release bundle and its
configuration (the public key of step 4.1, and optionally an rclone remote for
the offsite copy):

```bash
sudo mkdir -p /opt/auth-api
sudo install -m 700 -o root -g root scripts/backup-db.sh /opt/auth-api/backup-db.sh

sudo install -d -m 700 /etc/auth-api
printf 'AGE_PUBLIC_KEY=%s\nOFFSITE_REMOTE=%s\n' 'age1...' 'b2:auth-backups' \
  | sudo tee /etc/auth-api/backup.env > /dev/null
sudo chmod 600 /etc/auth-api/backup.env

# Read by node_exporter (see the monitoring guide)
sudo install -d -m 755 /var/lib/node_exporter/textfile
```

The script refuses to run with the placeholder key. Without `OFFSITE_REMOTE`,
backups live on this VPS only and die with it.

---

### 4.4 Test the script

```bash
sudo /opt/auth-api/backup-db.sh
ls -lh /var/backups/auth-api/
cat /var/lib/node_exporter/textfile/auth_backup.prom
```

The metrics file is written only after a complete run, offsite copy included.
A failed run exits with an error, leaves no partial file and keeps the previous
metrics: after 48 hours without a complete backup, `AuthBackupMissing` fires.
`AuthBackupShrunk` warns when a backup is less than half the size of those of
the previous week.

---

### 4.5 Schedule via cron

```bash
sudo crontab -e
```

Add:

```
0 2 * * * /opt/auth-api/backup-db.sh >> /var/log/auth-api-backup.log 2>&1
```

Backups run nightly at 2:00 AM and are retained for 7 days (`RETAIN_DAYS`).

---

### 4.6 Restore a backup

Always through `restore-db.sh`, connected as `auth_api`, into a **fresh**
database: a bare `| psql` does not stop at the first error. The script restores
in a single transaction, so a failure leaves the target untouched.

```bash
sudo -u postgres psql -c "CREATE DATABASE auth_api_restore OWNER auth_api"
scripts/restore-db.sh -i backup.key -f auth_api_YYYYMMDD_HHMMSS.sql.gz.age \
  -d "postgres://auth_api:<password>@10.0.0.2/auth_api_restore"
```

Check the restored data, then point `DATABASE_URL` at it (or rename the
databases while the API is stopped). `--force` restores over an existing
database after emptying it.

Every quarter, prove the backups themselves: restore last night's backup with
the offline key into a scratch database and compare it with production.
`scripts/backup-drill.sh` proves the mechanism on throwaway containers
(non-superuser restore, refused overwrite, `--force`, every table compared).

---

### 4.7 Point-in-time recovery with pgBackRest (profiles M and L)

WAL is archived continuously to an encrypted pgBackRest repository, with a full
backup every week and a differential one every day; two full backups are kept,
so any moment of about the last two weeks can be restored.

**On the DB VPS** - install and configure:

```bash
sudo apt install -y pgbackrest
sudo install -d -o postgres -g postgres -m 750 /var/lib/pgbackrest /var/spool/pgbackrest /var/log/pgbackrest
sudo install -o postgres -g postgres -m 640 deploy/db/pgbackrest.conf /etc/pgbackrest/pgbackrest.conf
sudo sed -i "s|^repo1-cipher-pass=.*|repo1-cipher-pass=$(pass prod/auth-api/pgbackrest-cipher-pass)|" \
  /etc/pgbackrest/pgbackrest.conf
sudo cp deploy/db/postgresql.pitr.conf /etc/postgresql/17/main/conf.d/auth-api-pitr.conf
sudo systemctl restart postgresql

sudo -u postgres pgbackrest --stanza=auth_api stanza-create
sudo -u postgres pgbackrest --stanza=auth_api check
sudo -u postgres pgbackrest --stanza=auth_api --type=full backup
```

The repository is unreadable without the cipher passphrase: keep it in `pass`
(`prod/auth-api/pgbackrest-cipher-pass`) and offline. For an offsite copy, add a
second repository as the comment in `pgbackrest.conf` shows.

Schedule the backups (`sudo crontab -u postgres -e`):

```
0 1 * * 0   pgbackrest --stanza=auth_api --type=full backup
0 1 * * 1-6 pgbackrest --stanza=auth_api --type=diff backup
```

**Restore to a point in time** - first into another directory, to inspect the
result without touching production:

```bash
sudo -u postgres install -d -m 700 /var/lib/postgresql/17/restore
sudo -u postgres pgbackrest --stanza=auth_api --pg1-path=/var/lib/postgresql/17/restore \
  --type=time "--target=2026-09-15 14:30:00+02" --target-action=promote restore
```

Once satisfied, stop PostgreSQL and restore in place with `--delta` (only the
files that differ are rewritten), then start it again.
