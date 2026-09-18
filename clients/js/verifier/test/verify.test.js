import assert from "node:assert/strict";
import { createServer } from "node:http";
import { after, before, test } from "node:test";

import { Verifier, VerifyError, middleware } from "../src/index.js";

const { subtle } = globalThis.crypto;
const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://api.example.com";

let keyPair;
let otherKeyPair;
let server;
let base;
let jwksRequests = 0;
const revoked = new Set();

const b64 = (value) => Buffer.from(value).toString("base64url");

async function sign(claims, { kid = "k1", keys = keyPair, alg = "ES256" } = {}) {
  const header = b64(JSON.stringify({ alg, typ: "JWT", kid }));
  const payload = b64(JSON.stringify(claims));
  const signature = await subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keys.privateKey,
    new TextEncoder().encode(`${header}.${payload}`),
  );
  return `${header}.${payload}.${b64(new Uint8Array(signature))}`;
}

function claims(overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER,
    aud: [AUDIENCE, ISSUER],
    sub: "0f8fad5b-d9cb-469f-a165-70867728950e",
    sid: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    jti: crypto.randomUUID(),
    iat: now,
    nbf: now,
    exp: now + 900,
    roles: ["user"],
    permissions: ["invoices:read"],
    ...overrides,
  };
}

before(async () => {
  keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  otherKeyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await subtle.exportKey("jwk", keyPair.publicKey);
  server = createServer(async (request, response) => {
    if (request.url === "/.well-known/jwks.json") {
      jwksRequests += 1;
      response.setHeader("content-type", "application/json");
      return response.end(JSON.stringify({ keys: [{ ...jwk, kid: "k1", alg: "ES256", use: "sig" }] }));
    }
    if (request.url === "/oauth/introspect") {
      let body = "";
      for await (const chunk of request) body += chunk;
      const token = new URLSearchParams(body).get("token");
      const authorized = request.headers.authorization === `Basic ${Buffer.from("rs:secret").toString("base64")}`;
      response.statusCode = authorized ? 200 : 401;
      response.setHeader("content-type", "application/json");
      return response.end(JSON.stringify({ active: authorized && !revoked.has(token) }));
    }
    response.statusCode = 404;
    response.end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

function verifier(options = {}) {
  return new Verifier({
    issuer: ISSUER,
    audience: AUDIENCE,
    jwksUri: `${base}/.well-known/jwks.json`,
    ...options,
  });
}

test("a valid token verifies with its permissions, keys fetched once", async () => {
  const v = verifier();
  const before = jwksRequests;
  const token = await v.verify(await sign(claims()));
  assert.equal(token.subject, "0f8fad5b-d9cb-469f-a165-70867728950e");
  assert.ok(token.hasPermission("invoices:read"));
  assert.ok(token.hasRole("user"));
  assert.ok(!token.isClientToken());
  await v.verify(await sign(claims()));
  assert.equal(jwksRequests - before, 1);
});

test("expired, premature, foreign and forged tokens are refused", async () => {
  const v = verifier();
  const now = Math.floor(Date.now() / 1000);
  const refused = async (token, code) => {
    await assert.rejects(v.verify(token), (error) => error instanceof VerifyError && error.code === code);
  };
  await refused(await sign(claims({ exp: now - 60 })), "expired");
  await refused(await sign(claims({ nbf: now + 3600 })), "invalid");
  await refused(await sign(claims({ iss: "https://evil.example.com" })), "invalid");
  await refused(await sign(claims({ aud: ["https://other.example.com"] })), "invalid");
  await refused(await sign(claims(), { keys: otherKeyPair }), "invalid");
  await refused(await sign(claims(), { alg: "HS256" }), "invalid");
  await refused("not.a-token", "malformed");
  await refused("nope", "malformed");
});

test("an unknown key triggers one fetch, then waits before the next", async () => {
  const v = verifier();
  const before = jwksRequests;
  const forged = await sign(claims(), { kid: "unknown", keys: otherKeyPair });
  await assert.rejects(v.verify(forged), { code: "unknown_key" });
  await assert.rejects(v.verify(forged), { code: "unknown_key" });
  assert.equal(jwksRequests - before, 1);
});

test("introspection catches a revoked token", async () => {
  const v = verifier({
    introspection: { clientId: "rs", clientSecret: "secret", cacheTtlMs: 0, endpoint: `${base}/oauth/introspect` },
  });
  const token = await sign(claims());
  await v.verify(token);
  revoked.add(token);
  await assert.rejects(v.verify(token), { code: "revoked" });

  const unreachable = verifier({
    introspection: { clientId: "rs", clientSecret: "secret", endpoint: "http://127.0.0.1:1/oauth/introspect" },
  });
  await assert.rejects(unreachable.verify(await sign(claims())), { code: "unavailable" });
});

test("a client credentials token is recognized", async () => {
  const token = await verifier().verify(
    await sign(claims({ sid: "00000000-0000-0000-0000-000000000000", client_id: "backend", roles: undefined })),
  );
  assert.ok(token.isClientToken());
  assert.equal(token.clientId, "backend");
  assert.deepEqual(token.roles, []);
});

test("the middleware sets request.auth or answers 401", async () => {
  const handle = middleware(verifier());
  const call = async (authorization) => {
    const request = { headers: authorization ? { authorization } : {} };
    const response = {
      statusCode: 200,
      headers: {},
      setHeader(name, value) {
        this.headers[name] = value;
      },
      end() {},
    };
    let passed = false;
    await handle(request, response, () => {
      passed = true;
    });
    return { request, response, passed };
  };
  const ok = await call(`Bearer ${await sign(claims())}`);
  assert.ok(ok.passed);
  assert.ok(ok.request.auth.hasPermission("invoices:read"));
  const missing = await call();
  assert.equal(missing.response.statusCode, 401);
  assert.equal(missing.response.headers["www-authenticate"], "Bearer");
  const invalid = await call("Bearer nope");
  assert.equal(invalid.response.headers["www-authenticate"], 'Bearer error="invalid_token"');
});
