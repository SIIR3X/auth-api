# Application Server Ports

## Ports

| Service | Port | Source allowed | Public exposure |
| --- | --- | --- | --- |
| Application container | `3000/tcp` | Reverse proxy, load balancer, or trusted clients | Usually no |
| SSH | `22/tcp` | Administration IPs only | No |

## Notes

- The application container listens on port `3000`.
- If a reverse proxy is on the same host, keep port `3000` bound to `127.0.0.1`.
- If a reverse proxy is remote, allow only the reverse proxy IPs.
- Everything else should remain blocked by default.
