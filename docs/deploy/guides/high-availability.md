# High Availability

[Index](../README.md)

The reference deployment (one API VPS, one database VPS) survives the loss of
an instance, not of a host. This guide takes it to a self-hosted deployment that
survives the loss of any single host, with what each component needs and what
auth-api does while a failover runs. No managed service is assumed.

## 1. Targets

| Failure | Service | Data |
|---------|---------|------|
| An API instance or host | No interruption: the load balancer stops sending traffic within 10 s | Nothing lost |
| The PostgreSQL primary | Sign-ins and writes answer `503` for the failover, 10 to 30 s | Nothing committed is lost (synchronous replication) |
| The Redis primary | Rate-limited and budgeted routes answer `503` for the failover, 5 to 15 s | Short-lived state written in the last second may be lost (see section 5) |
| A NATS server | No interruption | Nothing lost: events wait in the outbox, the stream has three copies |
| A load balancer | No interruption beyond the address move, about 3 s | - |
| The whole site | Restore elsewhere from backups (operations runbook, section 3) | Up to the last archived WAL segment |

## 2. Layout

```text
                      clients
                         |
               VIP (keepalived, VRRP)
               /                    \
        lb-1 (nginx)            lb-2 (nginx)
               \                    /
        +------+--------------------+------+
        |                                  |
   api-host-1 (api-a, api-b)       api-host-2 (api-c, api-d)
        |                                  |
        +---------+--------------+---------+
                  |              |
   HAProxy on each API host: 5432 -> PostgreSQL primary, 6379 -> Redis primary
                  |              |
   db-1, db-2, db-3: PostgreSQL + Patroni + etcd, Redis + Sentinel
   nats-1, nats-2, nats-3: NATS cluster with JetStream
```

Three database hosts give etcd, Patroni and Sentinel the quorum they need to
elect a new primary without a split brain. NATS runs on three hosts of its own,
or beside the database services when load allows.

## 3. API instances

Instances share nothing but the database, Redis and NATS: any instance serves
any request, and jobs that must run once coordinate through PostgreSQL advisory
locks (the event relay, retention jobs) or row leases (webhook deliveries).

- Run at least two instances on each of two hosts (section 12 of the operations
  runbook), with **identical configuration**: the same JWT keys,
  `ENCRYPTION_KEY`, `APP_PUBLIC_URL` and client registrations. A token signed by
  one instance is verified by every other.
- The load balancers check `GET /ready` (database, Redis and NATS answer) and
  remove an instance that fails it; the container runtime checks `GET /live`
  and restarts a stuck process. Never use `/ready` for restarts: a database
  failover would restart every instance at once.
- `TRUSTED_PROXY_CIDRS` lists both load balancers, or client addresses (rate
  limits, audit log) become the balancer's.
- Rolling updates (`rolling-update.sh`) replace one instance at a time; run it
  host by host.

nginx on each load balancer, with keepalived moving the public address:

```nginx
upstream auth_api {
    server 10.0.1.11:3001 max_fails=2 fail_timeout=10s;
    server 10.0.1.11:3002 max_fails=2 fail_timeout=10s;
    server 10.0.1.12:3001 max_fails=2 fail_timeout=10s;
    server 10.0.1.12:3002 max_fails=2 fail_timeout=10s;
    keepalive 64;
}
```

```text
# /etc/keepalived/keepalived.conf on lb-1 (priority 100; lb-2: BACKUP, 90)
vrrp_script nginx_alive { script "/usr/bin/pgrep nginx" interval 2 }
vrrp_instance public {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 100
    virtual_ipaddress { 203.0.113.10/24 }
    track_script { nginx_alive }
}
```

## 4. PostgreSQL

Patroni manages three PostgreSQL nodes and elects the primary through etcd.
auth-api connects to one address, HAProxy, which forwards to whichever node
Patroni reports as primary.

```yaml
# patroni.yml (excerpt, one per node)
scope: auth-api
bootstrap:
  dcs:
    ttl: 30
    loop_wait: 10
    maximum_lag_on_failover: 0
    synchronous_mode: true
    postgresql:
      parameters:
        synchronous_commit: "on"
        max_connections: 200
```

```text
# haproxy.cfg on each API host
listen postgres
    bind 127.0.0.1:5432
    option httpchk GET /primary
    http-check expect status 200
    default-server inter 2s fall 2 rise 2 on-marked-down shutdown-sessions
    server db-1 10.0.2.11:5432 check port 8008
    server db-2 10.0.2.12:5432 check port 8008
    server db-3 10.0.2.13:5432 check port 8008
```

- `synchronous_mode` makes a commit wait for a replica: a failover never loses a
  committed sign-in, revocation or event. The price is a few milliseconds per
  write, measured by `make bench-http`.
- `on-marked-down shutdown-sessions` cuts the connections to a demoted primary,
  so the pools reconnect to the new one instead of writing to a read-only node.
- pgBackRest (`deploy/db/pgbackrest.conf`) backs up from a replica; point every
  node's `archive_command` at the same repository.
- Keep the settings of `deploy/db/postgresql.auth-api.conf` on every node.

**During a failover** a request that needs the database waits up to
`DB_ACQUIRE_TIMEOUT_SECS` for a connection, then answers `503`. That includes
authenticated requests whose session state is not in Redis, where it is cached
five seconds: expect most traffic to see `503` for the length of the failover,
and clients to retry. A transaction cut
by the failover rolls back whole: the outbox guarantees an event exists if and
only if its change committed.

## 5. Redis

Three Redis nodes with Sentinel; HAProxy on each API host sends connections to
the node that reports itself primary.

```text
# sentinel.conf on each database host
sentinel monitor auth-api 10.0.2.11 6379 2
sentinel down-after-milliseconds auth-api 5000
sentinel failover-timeout auth-api 30000

# haproxy.cfg on each API host
listen redis
    bind 127.0.0.1:6379
    option tcp-check
    tcp-check send AUTH\ ${REDIS_PASSWORD}\r\n
    tcp-check expect string +OK
    tcp-check send info\ replication\r\n
    tcp-check expect string role:master
    tcp-check send QUIT\r\n
    tcp-check expect string +OK
    default-server inter 1s fall 2 rise 2 on-marked-down shutdown-sessions
    server redis-1 10.0.2.11:6379 check
    server redis-2 10.0.2.12:6379 check
    server redis-3 10.0.2.13:6379 check
```

Redis holds only short-lived state, and auth-api fails closed without it: rate
limits, attempt budgets and the token revocation check answer `503` rather than
letting unchecked traffic through (`RATE_LIMIT_FAIL_OPEN` stays `false`). Its
replication is asynchronous, so a failover can lose the last second of writes.
What that means:

- a budget or rate-limit counter restarts lower: a brute-force attempt gains at
  most the writes of that second, and the database-backed lockout still counts
  every failed password;
- a pre-authentication, email-change, device or authorization request started in
  that second must be started again;
- revoked sessions stay revoked: session revocations are written to PostgreSQL,
  and Redis only caches them. The one revocation held in Redis alone is that of
  a single access token through `POST /oauth/revoke` (and the access token of a
  logout, whose session is revoked in PostgreSQL anyway): lost in that second,
  such a token works again until it expires, within `JWT_ACCESS_EXPIRY_SECS`.

Set `min-replicas-to-write 1` and `min-replicas-max-lag 10` so a primary cut off
from its replicas stops accepting writes instead of diverging.

## 6. NATS

A three-node cluster with JetStream, and three copies of the event stream:

```text
# nats.conf on each NATS host (server_name differs)
server_name: nats-1
jetstream { store_dir: /data }
cluster {
  name: auth-api
  listen: 0.0.0.0:6222
  routes: [nats://10.0.3.11:6222, nats://10.0.3.12:6222, nats://10.0.3.13:6222]
}
```

```env
NATS_URL=nats://<token>@10.0.3.11:4222,nats://<token>@10.0.3.12:4222,nats://<token>@10.0.3.13:4222
NATS_STREAM_REPLICAS=3
```

The client follows the cluster when a server leaves. Events are written to the
PostgreSQL outbox with their change and published afterwards: while no quorum
of the stream is available, they wait (`AuthApiEventsStalled` fires after five
minutes) and go out in order when it returns.

## 7. Configuration checklist

- [ ] Same configuration and secrets on every instance.
- [ ] `DATABASE_URL` and `REDIS_URL` point at the local HAProxy.
- [ ] `DB_MAX_CONNECTIONS` times every instance, plus 10 per PostgreSQL node for
      replication and administration, stays under `max_connections`.
- [ ] `NATS_URL` lists every NATS server; `NATS_STREAM_REPLICAS=3`.
- [ ] `TRUSTED_PROXY_CIDRS` lists both load balancers.
- [ ] Load balancers check `/ready`; containers check `/live`.
- [ ] Prometheus scrapes every instance, exporter and node; the alerts of the
      monitoring guide are installed for all of them.
- [ ] Backups run from a replica and are restored once a quarter.

## 8. Failover drills

Run each drill under the load of `make soak` and watch the dashboards.

| Drill | How | Expected |
|-------|-----|----------|
| API host lost | `systemctl stop docker` on api-host-1 | No error once nginx marks the instances down; `AuthApiDown` for those targets |
| PostgreSQL primary lost | `patronictl failover` or power off the primary | `503` on writes for the failover, then recovery without restart; no committed row missing |
| Redis primary lost | `redis-cli -p 26379 sentinel failover auth-api` | `503` on budgeted routes for a few seconds, then recovery |
| NATS server lost | Stop one NATS server | No error; `auth_outbox_pending` stays near zero |
| Load balancer lost | Stop nginx on the active balancer | The address moves to the other within seconds |

The simulation suite (`tests/simulation/`) reproduces these outages against a
single instance with fault proxies: a dependency that stops answering,
refuses connections or slows down. Run `make test` after changing anything the
failover behaviour depends on.
