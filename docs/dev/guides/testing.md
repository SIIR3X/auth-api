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
- An invariant over many inputs (a round trip, a bound, a rule restated): a
  property test in a `mod properties` block next to the code.
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

## Property tests

Examples pin the cases someone thought of; properties state what must hold for
every input and let proptest search for the exception.

- **Next to the code** (`mod properties` in `src/`): pure functions with an
  invariant. Audit cursors round-trip over the whole timestamp range; every
  address of an IPv6 bucket network maps to the same bucket; any secret
  survives encryption and a key rotation, and a rewritten ciphertext no longer
  needs the old key; the password policy is exactly its definition; a lockout
  follows its threshold and never ends in the past; a device label is bounded,
  free of control characters and stable.
- **Against the database** (`tests/integration/api/auth/properties.rs`): inputs
  generated around the validators' and the SQL constraints' boundaries go
  through the real API. What the API accepts must be stored exactly as sent;
  what the database would refuse must be refused first, as a `422`, never as a
  `500`. These sample a few hundred inputs with a random seed and print the one
  that fails.

The fuzz targets complement them: fuzzing searches raw bytes for crashes and
broken security properties, properties search typed inputs for broken rules.

## Mutation testing

Coverage says a line ran; mutation testing says a test would notice if that
line were wrong. `make mutants` asks `cargo-mutants` to break the
security-relevant pure code one change at a time (a `<` turned into `<=`, a
function returning a default, a match arm deleted) and runs the unit tests
against each broken copy. A mutant no test catches is a fault that would ship.

Scope: `src/domain`, the crypto, token, TOTP, password, time and backoff
utilities, the client address and error body middlewares, configuration
validation and the audit cursor. The campaign runs serially (about 40 minutes)
and writes `reports/mutants.out/`; `missed.txt` lists the survivors.

`src/domain` also holds the decisions the services take, as plain functions of
plain values: the refresh verdict and the per-request token state, the
brute-force ceilings, consent and the claims a client token carries, device
polling and the finality of a decision, the steps of an email change, the
CAPTCHA and rate limiter verdicts, and the one-time token verdict. The services
do the I/O and map each verdict to its error, so unit tests and mutants reach
every branch without Redis, PostgreSQL or HTTP. Their own campaign, on
2026-09-15, produced 96 mutants: 80 caught, 16 unviable, none missed.

On 2026-09-15 the first campaign caught 196 of 246 viable mutants (79.7 %).
The survivors pointed at untested behaviour: the encryption key validator
masked by the production checks, the entropy floor, the 254-byte email bound,
backoff delays, OTP and token generation, re-encryption, key ids, the audit
pagination, the plain-text error codes. Tests now pin each of them. The final
campaign caught 265 of 272; its one new survivor, `decrypt` refusing the
28-byte ciphertext of an empty secret, is pinned too, which leaves **266 of
272 (97.8 %)**. The remaining survivors are accepted, each for a stated reason:

| Survivor | Why no unit test kills it |
|----------|---------------------------|
| `TrustedProxySource for AppState` returning no proxy | Covered by every integration test: without the loopback proxy, each `TestApp` would lose its own client address and the per-address budget tests would fail |
| `record_argon2_permits` doing nothing | Sets a Prometheus gauge; no recorder is installed in unit tests |
| `log_capacity` doing nothing | Writes a startup log line; its arithmetic lives in tested functions |
| `cgroup_memory_limit_mib` returning a constant (3 mutants) | Reads the host's `/sys/fs/cgroup/memory.max`; parsing it is tested in `parse_memory_max` |

A new survivor in this scope needs a test, or a line in this table.

## Coverage

`make coverage` runs every suite under `cargo-llvm-cov` (the binaries and the
harness excluded), writes an HTML report to `reports/coverage/`, and fails
under 93 % of lines, 89 % of regions or 83 % of functions.

| | Before this work | After the test plan | Final, 2026-09-15 |
|---|---:|---:|---:|
| Lines | 90.5 % | 92.1 % | 93.9 % |
| Regions | 85.4 % | 87.4 % | 90.1 % |
| Functions | 78.5 % | 81.3 % | 83.8 % |

By area (lines): domain 99.9 %, middleware 98.6 %, repositories 98.2 %,
utilities 97.3 %, configuration 96.7 %, handlers 95.6 %, services 92.2 %.
`state.rs` (68.2 %) is the weakest: its failures are tested, but building the
production database pool and clients from nothing only happens at startup;
`main.rs` is not measured by tests. The floors sit just under these figures, so
a change that lowers coverage fails the target.

## Simulations

`tests/simulation/` runs the service through what production eventually
throws at it:

- **Dependency failures** (`dependencies.rs`): the app reaches PostgreSQL, Redis
  and NATS through `FaultProxy`s. A test refuses connections, hangs them or
  adds latency, checks what clients receive and what was (not) written through
  a direct pool, then restores the dependency and checks the service recovers
  without a restart. An outage must answer `503 service_unavailable`, never
  `500`, and must leave no half-written state.
- **Time** (`clock.rs`): session lifetimes, lockouts and token expiry, driven by
  `app.clock.advance(..)` rather than sleeps.
- **Redis without Redis** (`redis_outage.rs`): flows that must keep working, or
  fail closed, when Redis is unreachable from the start.
- **Account lifecycles** (`lifecycle.rs`): proptest generates sequences of
  sign-ins, refreshes, sign-outs, password changes, sign-outs everywhere and
  deletions for several accounts, played against the API. After every step, each
  session a model knows must answer as the model says, the database must hold
  exactly the live sessions the model counts, and the audit log must not shrink.
  A failure prints the sequence.
- **Timing** (`timing.rs`, long): wrong-password sign-ins and password recoveries
  for existing and unknown accounts, interleaved in the same batches. The median
  times of both sides must stay within 25 ms.

Scenarios that take tens of seconds (a hung database bounded by the request
timeout) are marked `#[ignore = "long: ..."]`: `make test-sim` runs them,
`make ci` does not.

These scenarios found two defects the rest of the suites could not see: a
database outage answered `500` instead of `503`, and the Redis pool never
replaced a connection that failed under traffic, so a Redis restart kept every
authenticated request failing until traffic paused. The lifecycle model then
found two operations documented as revoking the *other* sessions, a password
change and signing out everywhere, when both revoke the current one too; the
contract now says so.

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
