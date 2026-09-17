# Webhooks

[Index](../README.md)

auth-api can call your HTTPS endpoints when accounts change, as an alternative
to consuming the NATS stream. An administrator with `webhooks:manage` registers
each endpoint.

## Registering an endpoint

```bash
curl -X POST https://auth.example.com/admin/webhooks \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"url": "https://crm.example.com/hooks/auth", "events": ["user.created", "user.deleted"]}'
```

The response holds `secret` (`whsec_...`): store it now, it is never shown
again. `POST /admin/webhooks/{id}/secret` replaces it; the old one stops
signing at once.

Events: `user.created`, `user.email_verified`, `user.email_changed`,
`user.password_changed`, `user.sessions_revoked`, `user.suspended`,
`user.reactivated`, `user.deleted`, or `*` for all of them, including events
added later.

## What a delivery looks like

```http
POST /hooks/auth HTTP/1.1
Content-Type: application/json
webhook-id: 0192a7c4-5b1e-7c3a-9f0e-2d4c6b8a1e3f
webhook-timestamp: 1789582527
webhook-signature: v1,K5oZfzN95Z9UVu1EsfQmfVNQhnkZ2pj9o9NDN/H/pI4=

{"event":"user.deleted","user_id":"...","event_id":"0192a7c4-...","occurred_at":"2026-09-16T12:15:27.123456Z"}
```

Events carry the user id only; read anything else from the API. Answer with a
2xx status within 5 seconds (`WEBHOOK_TIMEOUT_MS`). Redirects are not followed.

## Verifying a delivery

The signature follows [Standard Webhooks](https://www.standardwebhooks.com/):
HMAC-SHA256, keyed with the base64-decoded part of the secret after `whsec_`,
over `{webhook-id}.{webhook-timestamp}.{raw body}`, base64-encoded after `v1,`.

```python
import base64, hmac, hashlib, time

def verify(secret: str, headers, body: bytes) -> bool:
    key = base64.b64decode(secret.removeprefix("whsec_"))
    signed = f"{headers['webhook-id']}.{headers['webhook-timestamp']}.".encode() + body
    expected = "v1," + base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
    fresh = abs(time.time() - int(headers["webhook-timestamp"])) < 300
    return fresh and hmac.compare_digest(expected, headers["webhook-signature"])
```

Compute the signature over the raw body, before parsing it; reject timestamps
more than five minutes away to refuse replays.

## Delivery guarantees

- **Only committed changes.** A delivery is recorded in the same transaction as
  the change: an endpoint never hears of a change that rolled back.
- **At least once.** A delivery can arrive twice (a timeout after your endpoint
  processed it). Deduplicate on `event_id`.
- **Unordered.** Deliveries are sent concurrently and retried independently.
  Use `occurred_at` to order them.
- **Retries.** A failure (non-2xx, timeout, unreachable) is retried after 30
  seconds, doubling up to 6 hours, 12 attempts in all (about fourteen hours).
  Then the delivery is given up and `AuthApiWebhooksFailing` fires.
- **Inspection.** `GET /admin/webhooks/{id}/deliveries` lists the latest
  deliveries with their attempts, status and error;
  `POST /admin/webhooks/{id}/deliveries/{delivery_id}/retry` sends one again
  with a fresh budget. A disabled endpoint (`"enabled": false`) records no new
  delivery.

## Network rules

An endpoint whose host resolves to a loopback, private, link-local, shared,
documentation, multicast or reserved address is never called, and the attempt
fails with `blocked address`. Outside production, `WEBHOOK_ALLOW_HTTP` and
`WEBHOOK_ALLOW_PRIVATE_NETWORKS` relax this for local testing.
