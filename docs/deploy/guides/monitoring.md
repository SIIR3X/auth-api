# Monitoring

[Index](../README.md)

## Overview

Monitoring runs on a third host: a Prometheus on the API VPS would go down with
what it watches. That host joins the WireGuard network and scrapes exporters
that listen on VPN addresses only; it also probes the public HTTPS endpoint
from outside, as a client would.

```
Monitoring host (10.0.0.3) -- WireGuard -- API VPS (10.0.0.1): API instances, NATS exporter, node_exporter
                           -- WireGuard -- DB VPS  (10.0.0.2): postgres_exporter, redis_exporter, node_exporter
                           -- HTTPS ----- https://api.example.com/ready (blackbox probe)
```

| Target | Address | Exporter |
|--------|---------|----------|
| API instances and their containers | `10.0.0.1:9465`, `10.0.0.1:9466` | the API's metrics listener, which also publishes its container's memory, memory limit, CPU throttling and start time, read from its own cgroup |
| NATS | `10.0.0.1:7777` | `prometheus-nats-exporter`, in `docker-compose.api.yml` |
| Hosts | `10.0.0.1:9100`, `10.0.0.2:9100` | node_exporter (textfile collector on the DB VPS: backup metrics) |
| PostgreSQL | `10.0.0.2:9187` | postgres_exporter |
| Redis | `10.0.0.2:9121` | redis_exporter |
| Public endpoint | `https://api.example.com/ready` | blackbox exporter, on the monitoring host |

The files live in `deploy/monitoring/` of the release bundle.

## 1. Add the monitoring host to WireGuard

**On the monitoring host** - generate keys as in the
[database guide](../database/deployment.md#11-generate-keys) and create
`/etc/wireguard/wg10.conf`:

```ini
[Interface]
Address = 10.0.0.3/24
PrivateKey = <contents of the monitoring host's private key>

[Peer]
PublicKey = <DB VPS public key>
Endpoint = <DB_VPS_PUBLIC_IP>:51820
AllowedIPs = 10.0.0.2/32
PersistentKeepalive = 25

[Peer]
PublicKey = <API VPS public key>
Endpoint = <API_VPS_PUBLIC_IP>:51821
AllowedIPs = 10.0.0.1/32
PersistentKeepalive = 25
```

**On the DB VPS** - add a `[Peer]` for `10.0.0.3/32` to `wg10.conf`. **On the
API VPS** - give `wg10.conf` a `ListenPort = 51821`, add the same peer, and
open that port to the monitoring host's public address only:

```bash
sudo ufw allow from <MONITORING_PUBLIC_IP> to any port 51821 proto udp
```

Restart WireGuard on the three hosts (`sudo systemctl restart wg-quick@wg10`)
and check `ping 10.0.0.1` and `ping 10.0.0.2` from the monitoring host.

## 2. Exporters on the API VPS

**node_exporter:**

```bash
sudo apt install -y prometheus-node-exporter
echo 'ARGS="--web.listen-address=10.0.0.1:9100"' | sudo tee /etc/default/prometheus-node-exporter
sudo systemctl restart prometheus-node-exporter
```

No container exporter is needed: each API instance reads its own cgroup and
publishes its memory against its limit, its CPU throttling and its start time.
(cAdvisor 0.52 does not see the containers of Docker 29 with the containerd
image store, and would need a privileged container.)

**API instances and NATS** - `docker-compose.api.yml` publishes the metrics
listeners and the NATS exporter on `METRICS_BIND_ADDRESS`, `10.0.0.1` by
default, and nothing else.

**Firewall:**

```bash
sudo ufw allow from 10.0.0.3 to any port 9100,9465,9466,7777 proto tcp
```

## 3. Exporters on the DB VPS

**node_exporter**, with the textfile collector that reads the backup metrics
written by `backup-db.sh`:

```bash
sudo apt install -y prometheus-node-exporter
sudo mkdir -p /var/lib/node_exporter/textfile
echo 'ARGS="--web.listen-address=10.0.0.2:9100 --collector.textfile.directory=/var/lib/node_exporter/textfile"' \
  | sudo tee /etc/default/prometheus-node-exporter
sudo systemctl restart prometheus-node-exporter
```

**postgres_exporter** - a role limited to the monitoring views:

```bash
sudo -u postgres psql -c "CREATE ROLE exporter LOGIN PASSWORD '$(pass prod/monitoring/postgres-exporter)' IN ROLE pg_monitor"
echo "host postgres exporter 127.0.0.1/32 scram-sha-256" | sudo tee -a /etc/postgresql/17/main/pg_hba.conf
sudo systemctl reload postgresql
docker run -d --name postgres-exporter --restart unless-stopped --network host \
  -e DATA_SOURCE_NAME="postgresql://exporter:$(pass prod/monitoring/postgres-exporter)@127.0.0.1:5432/postgres?sslmode=disable" \
  quay.io/prometheuscommunity/postgres-exporter:v0.17.1 --web.listen-address=10.0.0.2:9187
```

**redis_exporter** - an ACL user restricted to the read-only commands the
exporter needs. Append it to `/etc/redis/users.acl`, then reload the ACL:

```bash
EXPORTER_SHA=$(pass prod/monitoring/redis-exporter | tr -d '\n' | sha256sum | cut -d' ' -f1)
printf 'user exporter on #%s ~* &* -@all +ping +info +config|get +client|list +slowlog|get +latency|latest +select +memory|usage +dbsize +cluster|info\n' "$EXPORTER_SHA" \
  | sudo tee -a /etc/redis/users.acl > /dev/null
redis-cli -u "$(pass prod/auth-api/redis-url)" ACL LOAD 2>/dev/null || sudo systemctl restart redis-server
docker run -d --name redis-exporter --restart unless-stopped --network host \
  -e REDIS_ADDR=redis://10.0.0.2:6379 -e REDIS_USER=exporter \
  -e REDIS_PASSWORD="$(pass prod/monitoring/redis-exporter)" \
  oliver006/redis_exporter:v1.74.0 --web.listen-address=10.0.0.2:9121
```

**Firewall:**

```bash
sudo ufw allow from 10.0.0.3 to any port 9100,9187,9121 proto tcp
```

## 4. The monitoring host

```bash
mkdir -p /srv/monitoring/rules && cd /srv/monitoring
cp releases/auth-api-X.Y.Z/deploy/monitoring/{docker-compose.monitoring.yml,prometheus.yml,blackbox.yml,alertmanager.yml} .
cp releases/auth-api-X.Y.Z/deploy/monitoring/rules/infrastructure.yml rules/
cp releases/auth-api-X.Y.Z/docs/deploy/guides/prometheus-alerts.yml rules/auth-api.yml
sed -i 's/api.example.com/your-actual-domain.com/' prometheus.yml
```

Edit `alertmanager.yml` (SMTP relay, addresses, webhooks) and store the SMTP
password in `alertmanager/smtp_password`, then start:

```bash
docker compose -f docker-compose.monitoring.yml up -d
```

Prometheus and Alertmanager listen on `127.0.0.1` of the monitoring host: reach
them through an SSH tunnel (`ssh -L 9090:127.0.0.1:9090 monitoring-host`).

## 5. Alerts

| File | Covers |
|------|--------|
| `rules/auth-api.yml` | The API: instances down, 5xx ratio, Argon2 saturation, latency, backups missing or shrunk |
| `rules/infrastructure.yml` | The public probe and certificate, hosts and disks, containers (restarts, memory, CPU throttling), PostgreSQL, Redis and NATS, pools, dropped events and e-mails, retention jobs, the dead man's switch |

Every infrastructure alert has a scenario in `rules/infrastructure.test.yml`:

```bash
docker run --rm --entrypoint promtool -w /m/rules -v "$PWD/deploy/monitoring:/m:ro" \
  prom/prometheus:v3.5.0 test rules infrastructure.test.yml
```

`Watchdog` always fires. Point its receiver at a dead man's switch service
(healthchecks.io, Better Stack, ...) that pages when the ping stops: that is
the only alert that still works when Prometheus or Alertmanager is down.

## 6. Check the pipeline

- `http://127.0.0.1:9090/targets` (through the tunnel): every target `UP`.
- `ALERTS{alertname="Watchdog"}` is firing and the dead man's switch receives it.
- Stop one API instance for three minutes: `AuthApiDown` fires for it and
  nothing else, since nginx serves from the other one.
