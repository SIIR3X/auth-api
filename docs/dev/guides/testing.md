# Testing

Every behaviour of the service is pinned by a test that fails when the behaviour
changes. This guide says where a test belongs, which tools the harness gives
it, and what the gate enforces.

## Suites

| Suite | Where | Needs | Runs with | Covers |
|-------|-------|-------|-----------|--------|
| Unit | `src/**` (`#[cfg(test)]`), `crates/testkit` | nothing | `make test-unit` | Pure decisions: domain rules, validators, token and cipher handling, configuration checks |
| Integration | `tests/integration/` | PostgreSQL, Redis, NATS | `make test-integration` | `api/`: every flow over HTTP; `repositories/`, `services/`: code against the real stores; `schema/`: constraints, triggers and SQL functions; `migrations/`: files, extensions, query plans |
| Security | `tests/security/` | PostgreSQL, Redis, NATS | `make test-security` | Authorization matrix, forged tokens, rate limits, headers, logs, audit regressions, static guards, control catalog; fuzz corpus replay |
| Simulation | `tests/simulation/` | PostgreSQL, Redis, NATS | `make test-sim` | The service while dependencies fail, under concurrency and over time |
| Fuzzing | `fuzz/` | nightly toolchain | `make fuzz` | Parsers of untrusted input, under libFuzzer and sanitizers |

`make ci` runs formatting, Clippy (every target, every feature), the dependency
policy, every suite but the long simulations, and the fuzz corpus replay.

### Where a new test goes

- A decision that needs no I/O: a unit test next to the code. If the decision
  hides inside an async service, extract it into a function taking plain
  values (and `now`), then test that function.
- Behaviour visible through the API: `tests/integration/api/<area>/`.
- A SQL constraint, trigger or function: `tests/integration/schema/`.
- An attack, or a control of the [security model](../security-model.md):
  `tests/security/`, and cite the test in the control catalog.
- A fixed bug: a test that fails before the fix, in the suite matching the
  bug, named after the behaviour rather than the ticket.

## The harness: `crates/testkit`

### `TestApp`

`TestApp::spawn().await` starts the real router on a random port with:

- **its own database**, cloned from a template migrated once per migration set
  (the template is rebuilt when a migration changes, under an advisory lock);
- **a `TestClock`** as the application clock (`app.clock.advance(..)`);
- **a `MailOutbox`** capturing every message (`app.mail.wait_for(address,
  subject).await`, then `six_digit_code()` or `value_after("token=")`);
- **a client address of its own**, forwarded through the trusted loopback
  proxy, so per-address budgets never leak between tests;
- **the OpenAPI contract** checked on every response (see below).

`TestApp::spawn_with_config(|config| ..)` adjusts the configuration;
`TestApp::builder().fault_proxies().spawn()` routes PostgreSQL, Redis and NATS
through `FaultProxy`s (`app.dependencies`), which add latency, hang or refuse
connections on demand. `spawn_with_mailpit()` keeps real SMTP for the tests of
the transport itself.

Tests never sleep to wait for time: advance the clock. Only what the service
decides in Rust follows `TestClock` (token expiry, TOTP steps, lockout,
lifetimes); SQL `NOW()` and Redis TTLs keep real time, so a test covering those
ages the stored rows or deletes the key.

### Databases without the API

`TestDb::new().await` gives a migrated database (`db.pool`); `TestDb::empty()`
an empty one. `testkit::sql` has row fixtures, `assert_constraint_error`,
`explain_plan` (sequential scans disabled) and `pg_args!` for mixed binds.

A database is dropped with its value. A test process killed before that leaves
its database behind; the next process drops databases whose creating process no
longer exists.

### Forged credentials and logs

`app.access_claims(user, session)` and `app.sign(&claims)` mint tokens as the
API does; `testkit::tokens` forges the rest (foreign key, `alg: none`, HS256
keyed with the public key). `LogCapture::install(filter)` records the logs of
a test process, to assert what never reaches them.

## The OpenAPI contract

`docs/dev/api/openapi.yaml` is generated from the handlers
(`cargo run --quiet --bin openapi`) and a unit test fails when it is stale or
misses a route. Every `TestApp` also validates each response against it: the
status must be documented for the operation and a JSON body must match its
schema. A violation fails the test when its app is dropped.

`TEST_CONTRACT=report` records violations in `target/contract-report/` instead,
to survey a change; `TEST_CONTRACT=off` disables the check. Neither is used by
the gate.

## Security tests

- **Authorization matrix** (`tests/security/authorization.rs`): every
  documented operation outside a short `PUBLIC` list is called anonymously, with
  malformed credentials and with nine forged tokens for a live session; each
  must answer 401 before reading its input. The list of operations comes from
  the document, so a new route is covered as soon as it exists.
- **Control catalog**: each control of the security model lists the tests that
  pin it; `tests/security/catalog.rs` fails when a cited test disappears.
- **Static guards**: SQL built from strings, `unsafe`, disabled TLS
  verification, prints and `unwrap()` on request paths are refused in the
  service code; `migrations/SHA256SUMS` freezes released migrations. A new
  migration is appended to it:
  `sha256sum migrations/NNNN_name.sql | sed 's|migrations/||' >> migrations/SHA256SUMS`.
- **Logs**: flows handling passwords, tokens and codes run with trace logging,
  and none of those values may appear.

## Fuzzing

Each target in `fuzz/fuzz_targets/` calls an entry point of `src/fuzzing.rs`,
compiled only with the `fuzzing` feature. An entry point feeds raw bytes to a
production parser and asserts a security property (a tampered token never
verifies to other claims, an untrusted peer always is the client address, an
accepted redirect is registered...).

```bash
make fuzz                 # every target, 60 s each (FUZZ_SECS=600 for longer)
cargo +nightly fuzz run --fuzz-dir fuzz redirect_uri   # one target, until stopped
```

Inputs worth keeping live in `fuzz/seeds/<target>/`. When the fuzzer finds a
crash (`fuzz/artifacts/`), fix the code, then copy the input to
`fuzz/regressions/<target>/` with a descriptive name: `tests/fuzz_corpus.rs`
replays seeds and regressions on stable in `make ci`, together with random
inputs from proptest.
