export interface IntrospectionOptions {
  clientId: string;
  clientSecret: string;
  /** Default: 30 000. */
  cacheTtlMs?: number;
  /** Default: `${issuer}/oauth/introspect`. */
  endpoint?: string;
}

export interface VerifierOptions {
  /** auth-api's APP_PUBLIC_URL, the `iss` of its tokens. */
  issuer: string;
  /** This service, one of auth-api's JWT_AUDIENCE. */
  audience: string;
  /** Default: `${issuer}/.well-known/jwks.json`. */
  jwksUri?: string;
  /** Default: 30. */
  leewaySeconds?: number;
  /** Default: 60 000. */
  minRefreshIntervalMs?: number;
  introspection?: IntrospectionOptions;
  /** For tests. */
  fetch?: typeof fetch;
  now?: () => number;
}

export interface VerifiedToken {
  /** The user, or for a client credentials token a UUID standing for the client. */
  subject: string;
  /** Nil UUID for a client credentials token. */
  sessionId: string;
  tokenId: string;
  clientId: string | null;
  roles: string[];
  permissions: string[];
  /** Unix seconds. */
  expiresAt: number;
  hasPermission(permission: string): boolean;
  hasRole(role: string): boolean;
  isClientToken(): boolean;
}

export type VerifyErrorCode =
  | "malformed"
  | "unknown_key"
  | "invalid"
  | "expired"
  | "revoked"
  | "unavailable";

export class VerifyError extends Error {
  code: VerifyErrorCode;
}

export class Verifier {
  constructor(options: VerifierOptions);
  verify(token: string): Promise<VerifiedToken>;
}

export function middleware(
  verifier: Verifier,
): (request: any, response: any, next: (error?: unknown) => void) => Promise<void>;
