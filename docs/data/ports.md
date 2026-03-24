# Data Server Ports

## Ports

| Service | Port | Source allowed | Public exposure |
| --- | --- | --- | --- |
| PostgreSQL | `5432/tcp` | Application server private IP | No |
| Redis | `6379/tcp` | Application server private IP | No |
| SSH | `22/tcp` | Administration IPs only | No |

## Notes

- PostgreSQL and Redis should listen on a private interface or private network only.
- Do not expose PostgreSQL or Redis to the public internet.
- Everything else should remain blocked by default.
