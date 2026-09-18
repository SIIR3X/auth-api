# Versioning and Compatibility

[Index](../README.md)

auth-api follows [Semantic Versioning](https://semver.org/). The version in
`Cargo.toml`, the image tag, the release bundle and the `CHANGELOG.md` heading
are the same number.

## 1. What the version covers

The public contract is everything an integrator or operator relies on:

| Surface | Defined by |
|---------|------------|
| HTTP API: routes, request and response fields, status codes, error `code`s and OAuth `error`s | `docs/dev/api/openapi.yaml`, generated from the code and enforced by the contract tests |
| Tokens: access token and ID token claims, signing algorithm, JWKS | [Integration guide](integration.md), section 3 |
| Discovery documents | `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration` |
| Events: NATS subjects, stream name, payloads; webhook payloads, headers and signature | [Integration guide](integration.md), section 4; [webhook guide](webhooks.md) |
| Configuration: environment variables, their defaults and production checks | [Configuration](configuration.md) |
| Command line: `--register-client`, `--grant-role`, `--rotate-totp-keys`, `--healthcheck` | [Commands](commands.md) |
| Operations: metric names and labels, shipped alert rules, compose files and profiles | Operations runbook, monitoring guide |

Not covered: the database schema (read it through the API), log line formats,
internal Rust modules, the test harness, and the exact wording of `message`
and `error_description` fields.

## 2. What each part of the number means

**Major** (`2.0.0`): something integrators or operators rely on changes or
disappears. Removing or renaming a route, a field, an error code, a claim, an
event or a configuration variable; changing the meaning of an existing one;
making an optional input required; changing a default so that the behaviour of
an existing deployment changes; dropping a supported algorithm.

**Minor** (`1.3.0`): something is added and existing uses keep working. New
routes, optional request fields, response fields, events, error codes on new
behaviour, configuration variables whose defaults keep the previous behaviour,
additive migrations. Clients must ignore response fields and event fields they
do not know.

**Patch** (`1.3.1`): fixes and security fixes that change no contract. A
security fix that must change a contract (refusing an input that was unsafe to
accept) ships in a patch and is flagged under **Security** in the changelog.

## 3. Deprecation

A part of the contract to be removed is first deprecated in a minor release:

1. The changelog lists it under **Deprecated**, with its replacement.
2. A deprecated route is marked `deprecated` in the OpenAPI document and
   answers with `Deprecation` (RFC 9745) and `Sunset` (RFC 8594) headers; a
   deprecated configuration variable logs a warning at startup.
3. It keeps working for at least 90 days and one further minor release, then
   is removed in the next major release.

## 4. Upgrades

- Migrations run forward only and are frozen once released
  (`migrations/SHA256SUMS`). Every release migrates from any earlier 1.x
  release: skipping versions is supported, one release at a time is not needed.
- A minor or patch upgrade is a rolling update: instances of the previous and
  the new release run side by side during it. A release never needs a
  migration that the previous release cannot run against, within a major
  version.
- Downgrading after migrations have run is not supported: restore the backup
  taken before the upgrade (update guide).
- Read the **Upgrading** section of the changelog before a major upgrade.

## 5. Support

| Release | Receives |
|---------|----------|
| The latest minor release | Fixes and security fixes |
| The previous minor release | Security fixes for 90 days after the latest one |
| Older releases | Nothing: upgrade |

Security issues are reported as described in [SECURITY.md](../../../SECURITY.md).
