# Application Server Ports

This document lists the ports used by the application server.

The application server typically hosts:
- the Rust API container
- Nginx as the reverse proxy

## Required Ports

| Port | Protocol | Service | Exposure |
| --- | --- | --- | --- |
| `80` | TCP | Nginx | Public |
| `443` | TCP | Nginx | Public |
| `3000` | TCP | Rust API container | Localhost only |

## Recommended Exposure Model

| Service | Recommendation |
| --- | --- |
| Nginx | Expose publicly |
| Rust API | Bind to `127.0.0.1` only |

## Notes

The Rust API should not be exposed directly to the Internet.
The reverse proxy should be the only public entrypoint on the application server.
