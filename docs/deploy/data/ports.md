# Data Server Ports

This document lists the ports used by the data server.

The data server typically hosts:
- PostgreSQL
- Redis

## Required Ports

| Port | Protocol | Service | Exposure |
| --- | --- | --- | --- |
| `5432` | TCP | PostgreSQL | Private network only |
| `6379` | TCP | Redis | Private network only |

## Recommended Exposure Model

| Service | Recommendation |
| --- | --- |
| PostgreSQL | Expose only to trusted application servers |
| Redis | Expose only to trusted application servers |

## Notes

Neither PostgreSQL nor Redis should be exposed publicly to the Internet.
Use firewall rules and private addressing to restrict access.
