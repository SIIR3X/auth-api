// Verify auth-api access tokens in Node.js resource servers.
//
// Checked on every call, without contacting auth-api: the ES256 signature
// against the issuer's published keys (fetched once, refetched when a token
// names an unknown key, at most once a minute), `iss`, `aud`, `exp` and `nbf`.
// A revocation before expiry (logout, password change) is only seen with
// `introspection`, which asks auth-api and caches the answer briefly.
//
// No dependency: WebCrypto and fetch from Node.js 20.

const { subtle } = globalThis.crypto;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class VerifyError extends Error {
  /**
   * @param {"malformed" | "unknown_key" | "invalid" | "expired" | "revoked" | "unavailable"} code
   * @param {string} message
   */
  constructor(code, message) {
    super(message);
    this.name = "VerifyError";
    this.code = code;
  }
}

function base64UrlDecode(value) {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

function parseJson(bytes) {
  try {
    return JSON.parse(decoder.decode(bytes));
  } catch {
    throw new VerifyError("malformed", "the token is not a well-formed JWT");
  }
}

export class Verifier {
  /**
   * @param {import("./index.d.ts").VerifierOptions} options
   */
  constructor(options) {
    if (!options?.issuer || !options?.audience) {
      throw new TypeError("issuer and audience are required");
    }
    this.issuer = options.issuer.replace(/\/+$/, "");
    this.audience = options.audience;
    this.jwksUri = options.jwksUri ?? `${this.issuer}/.well-known/jwks.json`;
    this.leewaySeconds = options.leewaySeconds ?? 30;
    this.minRefreshIntervalMs = options.minRefreshIntervalMs ?? 60_000;
    this.introspection = options.introspection
      ? {
          cacheTtlMs: 30_000,
          endpoint: `${this.issuer}/oauth/introspect`,
          ...options.introspection,
        }
      : null;
    this.fetch = options.fetch ?? globalThis.fetch;
    this.now = options.now ?? (() => Date.now());
    /** @type {Map<string, CryptoKey>} */
    this.keys = new Map();
    this.fetchedAt = 0;
    /** @type {Promise<void> | null} */
    this.refreshing = null;
    /** @type {Map<string, { at: number, active: boolean }>} */
    this.introspected = new Map();
  }

  /**
   * Verify a token, without the `Bearer ` prefix.
   * @param {string} token
   * @returns {Promise<import("./index.d.ts").VerifiedToken>}
   */
  async verify(token) {
    const parts = typeof token === "string" ? token.split(".") : [];
    if (parts.length !== 3) {
      throw new VerifyError("malformed", "the token is not a well-formed JWT");
    }
    const header = parseJson(base64UrlDecode(parts[0]));
    const claims = parseJson(base64UrlDecode(parts[1]));
    if (header.alg !== "ES256") {
      throw new VerifyError("invalid", "only ES256 tokens are accepted");
    }
    if (typeof header.kid !== "string") {
      throw new VerifyError("unknown_key", "the token names no signing key");
    }
    const key = await this.#key(header.kid);
    const valid = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      base64UrlDecode(parts[2]),
      encoder.encode(`${parts[0]}.${parts[1]}`),
    );
    if (!valid) {
      throw new VerifyError("invalid", "the signature does not verify");
    }

    const now = Math.floor(this.now() / 1000);
    if (claims.iss !== this.issuer) {
      throw new VerifyError("invalid", "the token was issued by someone else");
    }
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audiences.includes(this.audience)) {
      throw new VerifyError("invalid", "the token is not meant for this audience");
    }
    if (typeof claims.exp !== "number" || claims.exp + this.leewaySeconds <= now) {
      throw new VerifyError("expired", "the token has expired");
    }
    if (typeof claims.nbf === "number" && claims.nbf - this.leewaySeconds > now) {
      throw new VerifyError("invalid", "the token is not valid yet");
    }

    const verified = {
      subject: claims.sub,
      sessionId: claims.sid,
      tokenId: claims.jti,
      clientId: claims.client_id ?? null,
      roles: claims.roles ?? [],
      permissions: claims.permissions ?? [],
      expiresAt: claims.exp,
      hasPermission(permission) {
        return this.permissions.includes(permission);
      },
      hasRole(role) {
        return this.roles.includes(role);
      },
      isClientToken() {
        return this.clientId !== null && this.sessionId === "00000000-0000-0000-0000-000000000000";
      },
    };
    if (this.introspection && !(await this.#active(token, verified.tokenId))) {
      throw new VerifyError("revoked", "the token was revoked");
    }
    return verified;
  }

  async #key(kid) {
    const known = this.keys.get(kid);
    if (known) return known;
    if (!this.refreshing) {
      if (this.fetchedAt && this.now() - this.fetchedAt < this.minRefreshIntervalMs) {
        throw new VerifyError("unknown_key", "the token is signed with a key the issuer does not publish");
      }
      this.refreshing = this.#refresh().finally(() => {
        this.refreshing = null;
      });
    }
    await this.refreshing;
    const key = this.keys.get(kid);
    if (!key) {
      throw new VerifyError("unknown_key", "the token is signed with a key the issuer does not publish");
    }
    return key;
  }

  async #refresh() {
    let set;
    try {
      const response = await this.fetch(this.jwksUri);
      if (!response.ok) throw new Error(`JWKS answered ${response.status}`);
      set = await response.json();
    } catch (error) {
      throw new VerifyError("unavailable", `auth-api could not be reached: ${error.message}`);
    }
    const keys = new Map();
    for (const jwk of set.keys ?? []) {
      if (jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.kid !== "string") continue;
      const key = await subtle.importKey(
        "jwk",
        { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
      keys.set(jwk.kid, key);
    }
    this.keys = keys;
    this.fetchedAt = this.now();
  }

  async #active(token, tokenId) {
    const { clientId, clientSecret, cacheTtlMs, endpoint } = this.introspection;
    const cached = this.introspected.get(tokenId);
    if (cached && this.now() - cached.at < cacheTtlMs) return cached.active;

    let answer;
    try {
      const response = await this.fetch(endpoint, {
        method: "POST",
        headers: {
          authorization: `Basic ${Buffer.from(
            `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`,
          ).toString("base64")}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({ token }),
      });
      if (!response.ok) throw new Error(`introspection answered ${response.status}`);
      answer = await response.json();
    } catch (error) {
      throw new VerifyError("unavailable", `auth-api could not be reached: ${error.message}`);
    }
    for (const [id, entry] of this.introspected) {
      if (this.now() - entry.at >= cacheTtlMs) this.introspected.delete(id);
    }
    this.introspected.set(tokenId, { at: this.now(), active: answer.active === true });
    return answer.active === true;
  }
}

/**
 * Express or Connect middleware: sets `request.auth` to the verified token, or
 * answers 401 (503 when auth-api cannot be reached for keys or introspection).
 * @param {Verifier} verifier
 */
export function middleware(verifier) {
  return async (request, response, next) => {
    const header = request.headers?.authorization ?? "";
    if (!header.startsWith("Bearer ")) {
      response.statusCode = 401;
      response.setHeader("www-authenticate", "Bearer");
      return response.end();
    }
    try {
      request.auth = await verifier.verify(header.slice("Bearer ".length));
      return next();
    } catch (error) {
      if (error instanceof VerifyError && error.code === "unavailable") {
        response.statusCode = 503;
        return response.end();
      }
      response.statusCode = 401;
      response.setHeader("www-authenticate", 'Bearer error="invalid_token"');
      return response.end();
    }
  };
}
