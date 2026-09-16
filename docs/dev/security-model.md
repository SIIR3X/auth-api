# Security Model

What the service protects, against whom, and how. Each control below is pinned
by tests (`tests/http/`) so that a regression fails the build.

## Assets and adversaries

| Asset | Worst outcome |
|-------|---------------|
| Passwords | Offline cracking after a database leak |
| Sessions and tokens | Account takeover without the password |
| Second factors | Bypass by someone who holds the password |
| Account existence | Enumeration for phishing or credential stuffing |
| Security history, addresses | Personal data exposure |

Adversaries considered: an anonymous attacker on the network, an attacker
holding a leaked password, an attacker holding a stolen access or refresh
token, a malicious client application, and a read-only database leak.
An attacker with code execution on the host, or with the `ENCRYPTION_KEY` and
the database together, is out of scope.

## Credentials

- **Argon2id**, 64 MiB and 3 iterations by default; hashes run on a bounded
  pool (`ARGON2_MAX_CONCURRENCY`) so a login storm queues instead of exhausting
  memory.
- **No account oracle.** An unknown identifier still pays a full hash against a
  decoy. A locked account answers the same whatever the password. Registration
  answers `202` identically whether or not the address is taken (the owner is
  emailed instead; a pending one gets its verification again). Forgot-password
  and verification resends take a constant minimum time and answer identically.
- **Addresses cannot be squatted.** A password reset proves ownership of the
  address: it verifies a pending account with the password its owner chose, so
  an account someone else registered with the address is taken back. Accounts
  never verified are deleted after `CLEANUP_UNVERIFIED_ACCOUNT_DAYS`.
- **Lockout** after `LOCKOUT_THRESHOLD` consecutive wrong passwords. Failed
  second factors never count: whoever fails a second factor already holds the
  password, and letting them lock the account would let them shut the owner out.
- **Brute force** is bounded per identifier and per address (database counters),
  across identifiers from one address (HyperLogLog), and per submitted token.
  Budgets are consumed atomically in Redis before the guarded check runs, so
  parallel requests cannot all pass; they fail closed when Redis is down.

## Sessions and tokens

- **Access tokens** are ES256 JWTs (15 minutes) carrying `iss`, `aud`, `sid` and
  `jti`. Every authenticated request checks, in one Redis round trip, that the
  `jti` was not revoked by a logout and that the session is still active. A
  Redis failure refuses the request: revocation cannot be proven.
- **Refresh tokens** are opaque, stored as SHA-256 digests, and rotated on every
  use. Presenting a rotated token again revokes the whole session family;
  within 2 seconds of the rotation it is treated as a concurrent refresh from
  the same client (two tabs) and refused without revocation.
- **Absolute lifetime.** A sign-in ends after `JWT_MAX_SESSION_LIFETIME_SECS`
  however often it is refreshed, and no rotation dates a session past that
  moment. `JWT_STRICT_SESSION_BINDING` refuses a refresh
  from another address.
- **Sensitive actions require a recent re-authentication**: changing the
  password, username or email, deleting the account, revoking sessions, and
  adding or removing a second factor. A fresh sign-in does not count - a stolen
  refresh token or an approved device must not change the credentials.

## Second factors

- A pre-auth token (5 minutes) is bound to the method it was issued for: a TOTP
  challenge cannot be completed with an email code or vice versa.
- TOTP codes are accepted once (durable replay table), with per-challenge and
  per-account failure budgets. Confirming a new TOTP method consumes its code
  in the same table, under its own budget. Email codes have their own budgets;
  recovery codes share one per-account budget between the sign-in challenge and
  the authenticated route.
- A second factor answers an account status exactly as the password sign-in
  does.
- Adding or removing a method notifies the account's address. Removing the last
  method deletes the recovery codes; removing a primary method promotes another.
- TOTP secrets are encrypted with AES-256-GCM. Ciphertexts name their key, so
  the key can be rotated without downtime and the rotation can be resumed.

## Client applications

- Only registered clients can obtain sessions through the device or
  authorization code flows.
- **Device flow (RFC 8628):** user codes are reserved atomically, polling is
  paced, an approval is collected exactly once, and account status and session
  limits are rechecked when tokens are issued.
- **Authorization code with PKCE:** S256 only, exact redirect URIs (loopback on
  any port only for a registered path, never `localhost`), single-use codes
  consumed atomically, a replayed code revokes its session. Consenting to a
  third-party client requires a re-authentication.
- **Scopes:** a client's tokens carry only the consented permissions, re-derived
  from the user's current permissions on every refresh, and no roles.

## Data

- Every token, code and refresh token is stored as a digest.
- The audit log is append-only (enforced by a trigger) and holds no personal
  data such as addresses in its metadata. Users read their own history through
  `GET /users/me/audit`.
- An email change is confirmed on both addresses, revokes the other sessions,
  and notifies the previous address.
- Account deletion records `user.deleted` in the event outbox in the same
  transaction as the deletion, so downstream erasure cannot be lost and is
  never announced for an account that still exists; the relay delivers it to
  JetStream, waiting for the broker when it is down.

## Network edge

- Client addresses come from forwarding headers only when the direct peer is a
  trusted proxy (`TRUSTED_PROXY_CIDRS`); IPv6 clients are limited per `/64`.
- Rate limits: a sliding-window estimate per client, one script per request,
  fail closed in production.
- Request bodies are capped at 64 KB and handlers at 30 seconds. Responses carry
  HSTS, CSP `default-src 'none'`, `nosniff`, `DENY` framing and `no-store`.
- Logs record route templates, never raw paths carrying codes. Metrics are served
  on a loopback-only listener.

## Configuration

Production refuses to start with a configuration that disables a control: HTTP
public or frontend URLs, no trusted proxy, committed development keys, a
wildcard CORS origin, fail-open rate limiting or CAPTCHA, and more. The full
list is in [Configuration](guides/configuration.md#production-checks).

## Known limits

- An administrative revocation outside the API (a direct database update) takes
  effect within the 5-second session cache.
- Email codes are 6 digits; their strength is the attempt budgets and short
  lifetime, not their entropy.
- Outside production, rate limiting and CAPTCHA fail open by default.
- Anyone holding both `ENCRYPTION_KEY` and a database dump can read TOTP secrets.
- A logout racing a refresh of the same session, more than 2 seconds after
  its rotation, reads as a replay: the family is revoked and a replay audited.
  Kept on purpose, since the audit signal outweighs this rare race.
- A refresh does not check the account lockout. A lockout can be triggered by
  anyone who knows the identifier; cutting the owner's live sessions would
  turn it into a way to sign them out. Suspending the account does end them.

## Control catalog

Each control names the tests that pin it; `tests/security/catalog.rs` fails
when a cited test no longer exists.

| ID | Control | Tests |
|----|---------|-------|
| SEC-01 | Passwords are hashed with Argon2id, salted per hash | `hash_and_verify_correct_password`, `same_password_produces_different_hashes`, `async_hash_and_verify_match_sync_behavior` |
| SEC-02 | No account oracle: unknown identifiers, locked accounts, taken addresses, forgotten passwords and verification resends answer alike | `locked_account_answers_the_same_whatever_the_password`, `registering_a_taken_email_looks_like_a_new_signup`, `forgot_password_takes_the_same_minimum_time_either_way`, `forgot_password_returns_200_for_unknown_email`, `resending_the_verification_looks_the_same_for_every_address`, `login_unknown_user` |
| SEC-03 | Lockout after consecutive wrong passwords, never after failed second factors | `account_locked_after_threshold_failures`, `account_unlocked_after_lockout_expires`, `second_factor_failures_do_not_lock_the_account`, `a_zero_threshold_never_locks`, `validate_rejects_zero_lockout_threshold` |
| SEC-04 | Attempt budgets are consumed atomically and fail closed | `concurrent_attempts_never_exceed_the_budget`, `unreachable_redis_fails_closed`, `refresh_rate_limited_after_20_invalid_tokens`, `forgot_password_is_capped_per_account`, `concurrent_reauthentication_guesses_never_exceed_the_budget`, `rotating_ipv6_addresses_within_a_64_does_not_reset_the_failure_budget` |
| SEC-05 | Access tokens: ES256 only, issuer, audience and time claims checked, revocation checked on every request | `missing_or_malformed_credentials_are_refused`, `forged_tokens_for_a_live_session_are_refused`, `a_token_outlives_neither_its_expiry_nor_its_logout`, `time_claims_follow_the_supplied_clock`, `decode_rejects_non_es256_alg`, `a_rotation_keeps_every_published_key_valid`, `a_kid_does_not_lend_its_key_to_another_signature` |
| SEC-06 | Every operation outside a short public list requires an access token | `the_public_list_matches_the_document`, `a_valid_token_passes_authentication_everywhere` |
| SEC-07 | Refresh tokens rotate; a replay revokes the family, a concurrent refresh does not | `refresh_token_replay_is_rejected`, `refresh_token_theft_invalidates_entire_session_family`, `concurrent_refreshes_keep_the_family_alive`, `rotated_within_accepts_the_grace_boundary_only` |
| SEC-08 | Absolute session lifetime and optional address binding | `session_lifetime_counts_from_the_first_sign_in`, `a_rotation_inherits_the_family_start`, `refresh_rejects_mismatched_ip_with_strict_binding`, `rotations_never_outlive_the_absolute_lifetime`, `a_rotated_session_is_never_dated_past_its_absolute_lifetime` |
| SEC-09 | Sensitive actions need a recent re-authentication; signing in does not count | `signing_in_does_not_grant_sensitive_actions`, `revoke_session_requires_recent_reauth`, `delete_account_without_password_and_no_recent_reauth_rejected`, `a_device_session_cannot_change_the_password_without_reauthentication`, `enrolling_a_second_factor_requires_reauthentication` |
| SEC-10 | A pre-auth token completes only the method it was issued for | `totp_challenge_cannot_be_completed_with_an_email_code`, `a_pre_auth_state_without_a_method_cannot_complete_with_a_recovery_code`, `seeds_and_regressions_hold` |
| SEC-11 | Second-factor codes are single-use and budgeted per challenge and per account | `totp_replay_within_window_rejected`, `totp_replay_rejected_even_after_redis_key_loss`, `concurrent_totp_guesses_never_exceed_the_token_budget`, `account_budget_blocks_fresh_pre_auth_tokens`, `recovery_challenge_rate_limited_after_max_failures`, `email_2fa_lockout_after_max_failures`, `recovery_login_replay_rejected`, `a_code_confirming_a_new_method_cannot_complete_a_sign_in`, `confirming_a_new_method_has_an_attempt_budget`, `recovery_code_guesses_share_one_budget_across_routes`, `a_challenge_owns_its_state_and_every_failure_budget` |
| SEC-12 | Changes to second factors are notified and keep a usable configuration | `removing_the_last_method_drops_recovery_codes`, `removing_the_primary_method_promotes_the_remaining_one`, `disable_totp_sends_two_factor_disabled_email` |
| SEC-13 | TOTP secrets are encrypted with named keys; rotation is resumable | `keyring_writes_versioned_ciphertexts_it_can_read`, `keyring_refuses_a_key_it_does_not_hold`, `encrypt_produces_different_output_each_call`, `rotate_is_idempotent_when_run_twice`, `rotate_re_encrypts_totp_secret_with_new_key` |
| SEC-14 | Only registered clients obtain sessions through client flows | `a_flow_needs_a_registered_client` |
| SEC-15 | Device flow: user codes reserved atomically, polling paced, approval collected once, account and session limit rechecked under lock | `a_live_user_code_is_never_handed_out_twice`, `polling_faster_than_the_interval_is_slowed_down`, `an_approval_is_collected_exactly_once_under_concurrent_polls`, `a_suspended_account_cannot_collect_approved_tokens`, `a_non_primary_client_is_capped_without_a_quota_row`, `unknown_user_codes_are_rate_limited`, `concurrent_approvals_never_exceed_the_session_limit`, `a_second_factor_answers_an_inactive_account_like_the_password_sign_in` |
| SEC-16 | Authorization code: S256 only, exact or loopback redirects, single use, replay revokes, third-party consent re-authenticates | `only_s256_challenges_are_accepted`, `only_registered_or_loopback_redirects_are_accepted`, `loopback_redirects_accept_any_port_on_a_registered_path`, `a_replayed_code_is_refused_and_revokes_its_session`, `a_wrong_verifier_burns_the_code`, `a_code_is_bound_to_its_client_and_redirect`, `a_third_party_client_requires_a_fresh_reauthentication`, `challenges_and_verifiers_follow_rfc_7636` |
| SEC-17 | Client tokens carry only consented permissions, re-derived on refresh | `tokens_carry_only_the_consented_scopes_even_after_refresh`, `granted_is_an_intersection_unless_unrestricted` |
| SEC-18 | Tokens and codes are stored as digests | `sessions_require_32_byte_hashes`, `email_verification_tokens_are_fixed_length` |
| SEC-19 | The audit log is append-only and holds no personal data | `audit_log_is_append_only`, `audit_log_delete_blocked_by_trigger`, `account_deletion_leaves_no_identity_in_the_audit_log`, `an_email_change_keeps_the_status_and_audits_no_address`, `a_forged_cursor_is_refused_and_the_history_needs_a_session` |
| SEC-20 | An email change is confirmed on both addresses by the user who started it | `email_change_full_flow_success`, `email_change_steps_cannot_be_skipped`, `email_change_token_bound_to_initiating_user` |
| SEC-21 | Account deletion is acknowledged downstream before the row goes | `account_deletion_publishes_user_deleted_through_jetstream` |
| SEC-22 | Forwarding headers count only from trusted proxies; IPv6 clients share their /64 | `direct_peer_ignores_forwarded_headers`, `trusted_proxy_uses_forwarded_client_ip`, `ipv6_addresses_share_their_64`, `every_forwarded_line_counts_as_one_list`, `an_unreadable_hop_stops_the_walk_at_the_proxy`, `sql_budgets_group_addresses_like_redis_budgets` |
| SEC-23 | Rate limits per client, failing closed in production | `auth_rate_limit_blocks_requests_exceeding_limit`, `auth_routes_fail_closed_when_rate_limiter_backend_is_down`, `a_refused_request_consumes_nothing`, `validate_rejects_production_config_with_rate_limit_fail_open` |
| SEC-24 | Bounded bodies, security headers, CORS allowlist, one error format | `an_oversized_body_is_refused_before_the_handler`, `security_headers_present_on_200_response`, `security_headers_enable_hsts_for_https_production`, `cross_origin_access_is_limited_to_the_allowlist`, `plain_text_errors_become_error_bodies_with_their_headers`, `parser_details_do_not_leak` |
| SEC-25 | Logs carry route templates and never a secret | `access_logs_carry_route_templates_not_codes`, `account_flows_never_log_their_secrets` |
| SEC-26 | Production refuses a configuration that disables a control | `validate_accepts_hardened_production_config`, `validate_rejects_committed_dev_key_in_production`, `validate_rejects_wildcard_cors_in_production`, `validate_rejects_non_https_public_url_in_production`, `validate_rejects_zero_device_poll_interval`, `validate_rejects_poll_interval_not_below_device_ttl`, `validate_rejects_zero_session_lifetime` |
| SEC-27 | Code hygiene: bound SQL parameters, no unsafe code, no panics on request paths, released migrations frozen | `sql_is_never_assembled_from_strings`, `there_is_no_unsafe_code`, `request_paths_never_unwrap`, `released_migrations_are_never_edited` |
| SEC-28 | Every response matches the published OpenAPI contract | `schemas_are_enforced_through_references`, `undocumented_statuses_and_bodies_are_violations` |
