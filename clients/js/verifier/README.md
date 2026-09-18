# @auth-api/verifier

Verify auth-api access tokens in Node.js resource servers. Internal package,
not published: install it from the repository.

```bash
npm install "git+ssh://git@github.com/<org>/auth-api.git#path:clients/js/verifier"
```

No dependency: WebCrypto and `fetch` from Node.js 20 or later.

```js
import express from "express";
import { Verifier, middleware } from "@auth-api/verifier";

const verifier = new Verifier({
  issuer: "https://auth.example.com",   // auth-api's APP_PUBLIC_URL
  audience: "https://api.example.com",  // this service, in auth-api's JWT_AUDIENCE
});

const app = express();
app.get("/invoices", middleware(verifier), (req, res) => {
  if (!req.auth.hasPermission("invoices:read")) return res.sendStatus(403);
  res.json({ owner: req.auth.subject });
});
```

Outside Express, call `await verifier.verify(token)`: it returns the verified
token (`subject`, `sessionId`, `clientId`, `roles`, `permissions`, `expiresAt`)
or throws a `VerifyError` whose `code` is `malformed`, `unknown_key`, `invalid`,
`expired`, `revoked` or `unavailable`.

Checked on every call, without contacting auth-api: the ES256 signature against
the published keys (fetched once, refetched when a token names an unknown key,
at most once a minute), `iss`, `aud`, `exp` and `nbf`.

A revocation before expiry (logout, password change, revoked session) is only
seen with introspection: register the service as a confidential client in
auth-api, then

```js
const verifier = new Verifier({
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
  introspection: { clientId: "invoices-api", clientSecret: process.env.AUTH_CLIENT_SECRET },
});
```

Answers are cached 30 seconds per token (`cacheTtlMs`).

Tests: `make js-test`.
