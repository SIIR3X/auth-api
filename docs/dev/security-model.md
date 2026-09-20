# Security Model

What the service protects, against whom, and how. Each control below is pinned
by tests (the control catalog at the end) so that a regression fails the build.
The [threat model](threat-model.md) maps threats to these controls.

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

- **Argon2id**, 64 MiB and 3 iterations by default, never under 19 MiB and 2
  iterations in production; hashes run on a bounded pool
  (`ARGON2_MAX_CONCURRENCY`) so a login storm queues instead of exhausting
  memory. A stored hash weaker than the configured parameters is replaced after
  the next successful sign-in.
- **No account oracle.** An unknown identifier still pays a full hash against a
  decoy. A locked account answers the same whatever the password. Registration
  answers `202` identically, in a constant minimum time, whether or not the
  address is taken (the owner is emailed instead, at most three times an hour;
  a pending one gets a verification link of its own). Forgot-password and
  verification resends take a constant minimum time and answer identically. An
  email change to an address that belongs to another account answers like any
  other and sends nothing; new addresses are budgeted per account and per
  target.
- **Links mailed earlier stop working** when the password changes, is reset,
  or the address changes: reset and sign-in links go with the old secret or the
  old mailbox.
- **CAPTCHA** verifications carry the client's address and the site key, and a
  challenge solved on another hostname is refused.
- **Addresses cannot be squatted.** A pending account belongs to nobody yet: a
  registration on its address gets its own verification link, carrying the
  password, username and locale that registration chose, and the link applies
  them when it verifies the account. Whoever registered the address first does
  not decide the password its owner activates. Links of a pending account
  coexist (a resend repeats the latest registration) until one verifies it.
  A password reset also proves ownership of the address: it verifies a pending
  account with the password its owner chose. Accounts never verified are
  deleted after `CLEANUP_UNVERIFIED_ACCOUNT_DAYS`.
- **Breached passwords are refused** at registration, change and reset, through
  the Pwned Passwords range API: only the first five characters of the SHA-1
  leave the service, answers are padded, and the check runs before the address
  is looked up so it costs the same whether the address is taken.
- **Access that outlives the password is visible.** Passkeys, personal access
  tokens and external identities survive a password reset, and anyone holding
  the password can add one. Each addition mails the owner; every password
  change or reset mails the list of what still opens the account. A pending
  account taken back by a reset loses all of them.
- **Lockout** after `LOCKOUT_THRESHOLD` consecutive wrong passwords. Failed
  second factors never count: whoever fails a second factor already holds the
  password, and letting them lock the account would let them shut the owner out.
- **Brute force** is bounded per identifier and per address (database counters),
  across identifiers from one address (HyperLogLog), and per submitted token.
  Budgets are consumed atomically in Redis before the guarded check runs, so
  parallel requests cannot all pass; they fail closed when Redis is down.

## Sessions and tokens

- **New devices** are announced: a sign-in from a browser and operating system
  family the account never used e-mails its owner and is audited as
  `new_device_login`. The first sign-in of an account and browser updates do not
  alert.
- **Access tokens** are ES256 JWTs (15 minutes) carrying `iss`, `aud`, `sid` and
  `jti`. Every authenticated request checks, in one Redis round trip, that the
  `jti` was not revoked by a logout and that the session is still active. A
  Redis failure refuses the request: revocation cannot be proven. A revocation
  writes an "ended" marker into the validity cache, which a check racing it
  cannot overwrite with a stale "active".
- **Refresh tokens** are opaque, stored as SHA-256 digests, and rotated on every
  use. Presenting a rotated token again revokes the whole session family and
  ends the cached validity of its access tokens at once; within 1 second of
  the rotation it is treated as a concurrent refresh from the same client (two
  tabs), refused without revocation and counted
  (`auth_refresh_concurrent_total`). Refused refreshes (unknown token, another
  client's session, a replay, another address) count against the address.
- **Absolute lifetime.** A sign-in ends after `JWT_MAX_SESSION_LIFETIME_SECS`
  however often it is refreshed, and no rotation dates a session past that
  moment. `JWT_STRICT_SESSION_BINDING` refuses a refresh
  from another address.
- **Delegated tokens act within their grant.** A session issued to a client
  other than the instance's own application, a session restricted to consented
  scopes, and the session of a personal access token are delegated: their
  tokens reach resource servers, `/oauth/userinfo` and logout, but the account
  routes (`/users/me/*`), the approval routes (`/oauth/authorization-requests/*`,
  `/oauth/device/*`) and the administration answer
  `403 first_party_session_required`. Otherwise a delegated token could approve
  on its own a flow of the instance's application and obtain an unrestricted
  session. The kind is read from the session, cached with its validity.
- **Re-authentication resists a stolen session.** Every route that accepts the
  current password shares the strict bucket of `/users/me/reauth`, and wrong
  passwords are counted per session and per account (three times the session
  budget): a stolen session guessing the password locks itself out, while the
  owner's sessions still re-authenticate, revoke it and change the password.
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
  recovery codes have a per-challenge and per-account budget at sign-in, and a
  per-session one on the authenticated route, so a stolen token cannot keep the
  owner from signing in with a recovery code.
- A second factor answers an account status exactly as the password sign-in
  does.
- Adding or removing a method notifies the account's address. Removing the last
  method deletes the recovery codes; removing a primary method promotes another.
- TOTP secrets are encrypted with AES-256-GCM. Ciphertexts name their key, so
  the key can be rotated without downtime and the rotation can be resumed, and
  each is bound to its account (webhook secrets to their endpoint) as
  associated data: a ciphertext copied onto another row does not decrypt. The
  service refuses to start while a secret names a key it no longer holds.
- Email codes (sign-in and email change) are stored as HMAC-SHA256 digests
  under a key derived from `ENCRYPTION_KEY` (HKDF), bound to the flow and the
  account: a copy of the database or of Redis does not give live codes away,
  where a bare hash of six digits falls in milliseconds. Every secret is
  compared in constant time, and every random value comes from the operating
  system's generator.

## External identities

- An external identity signs in only after the signed-in owner of an account
  linked it, with a recent re-authentication. No account is found or created
  from an email address, verified or not: an attacker controlling an address at
  a provider gains nothing.
- The flow uses PKCE, `state` and `nonce`; the ID token's signature is checked
  against the provider's published keys, and its issuer, audience, authorized
  party, expiry and nonce against the flow.
- The callback's outcome is redeemed once, within two minutes, only with the
  binding secret the starting browser kept: a callback URL forwarded to a victim
  cannot sign the victim in to the attacker's account. The callback writes
  nothing: a link is made only when that browser completes the flow, so an
  attacker sending a victim the provider URL of a link they started does not
  get the victim's identity linked to their account.
- The identity stands for the password: a second factor enrolled on the account
  is still required.

## Passkeys

- Registration needs a recent re-authentication. A response is accepted only
  for the challenge issued to the session, from an allowed origin, for this
  relying party, with user presence and verification; attestation is not
  requested nor trusted.
- A sign-in challenge is used once, whatever the outcome. The assertion must
  verify against the stored key, come from an allowed origin with user
  verification, carry the credential's user handle, and make a kept signature
  counter grow; a counter that does not grow refuses the sign-in (possible
  clone). Every refusal answers `invalid_credentials` and counts against the
  client address.

## Client applications

- Only registered clients can obtain sessions, through the standard OAuth 2.1
  endpoints. A confidential client proves its secret at every token and device
  authorization request; the secret (256 random bits) is stored as a digest and
  compared in constant time.
- **Authorization endpoint:** an unknown client or an unregistered redirect URI
  is answered directly, never redirected; the stored request lives ten minutes
  and is decided once. Consenting to a third-party client requires a
  re-authentication, checked before the request is used up.
- **Device flow (RFC 8628):** user codes are reserved atomically, polling is
  paced, an approval is collected exactly once and only by the client that
  started the flow, and account status and session limits are rechecked when
  tokens are issued. Approving a device of a client other than the instance's
  own application requires a re-authentication, like consenting to it.
- **Authorization code with PKCE:** S256 only, exact redirect URIs (loopback on
  any port only for a registered path, never `localhost`), single-use codes
  consumed atomically, a replayed code revokes its session. The redemption
  holds the code until its session is linked, so even a replay racing it finds
  the session to revoke.
- **Scopes:** a request may narrow the client's registered scopes, never widen
  them; a client's tokens carry only the consented permissions, re-derived from
  the user's current permissions on every refresh, and no roles.
- **Refresh:** a client's session is refreshed only by that client at the token
  endpoint, with its authentication; the first-party route refuses it.
- **OpenID Connect:** identity scopes grant no permission and release only
  their own claims; the ID token is bound to the client (`aud`), the request
  (`nonce`) and the access token (`at_hash`).
- **Client credentials:** only a confidential client with scopes that has the
  grant turned on obtains tokens for itself; they carry no user, so account
  routes refuse them, and they stop being active when the grant is turned off.
- **Introspection and revocation:** only confidential clients introspect, and
  an inactive token reveals nothing but `active: false`. A client revokes its
  own tokens only; any other token gets the same answer and is left alone.

## Administration

- `/admin` routes require a first-party token carrying an administrative
  permission, from a session whose sign-in proved a second factor (TOTP, email
  code, recovery code, or a passkey with user verification), and the
  permission of the action still granted in the database: revoking a role
  takes effect on the next request, not when the token expires. An enrolled
  factor is not enough: a password or a sign-in link alone never opens it.
- An administrative role goes only to an active account that has a verified
  second factor or a passkey, over HTTP and from the command line; nobody
  grants a role to their own account.
- Administrators cannot suspend, sign out, reset or delete their own account
  from `/admin`, and deleting an account needs their recent re-authentication.
- Every change is audited on the account it changed, with the administrator's
  id, so owners see it in their own history; changes to roles and clients are
  audited in the administrator's own history.
- Granting a role, changing what a role grants, saving a client or changing its
  secret, creating, redirecting or re-keying a webhook, suspending an account
  and forcing its reset need a recent re-authentication: a stolen administrator
  token alone can neither send account events elsewhere nor shut owners out.
  Every change is audited in the same transaction; a webhook's audit keeps the
  host it points to (never the path or query), and redeliveries are audited. No change may leave the deployment without an
  active account holding `roles:manage`: not a change of roles, not suspending
  or deleting that account, by an administrator or by its owner. These checks
  take a shared lock, so two concurrent withdrawals cannot both pass.

## Webhooks

- Deliveries are recorded in the transaction of the change, like events: an
  endpoint never hears of a change that rolled back.
- Each delivery is signed with the endpoint's secret (HMAC-SHA256 over id,
  timestamp and body); secrets are encrypted with the keyring and shown once.
- Before each delivery the host is resolved and every address checked: loopback,
  private, link-local, shared, documentation, multicast and reserved ranges,
  and IPv6 forms embedding them, are refused. The connection is pinned to the
  checked address and redirects are not followed, so a DNS answer or a
  redirect cannot turn a webhook against the internal network.

## Data

- Every token, code and refresh token is stored as a digest.
- The audit log is append-only (enforced by a trigger) and holds no personal
  data such as addresses in its metadata. Its client addresses keep only their
  network after 90 days and are removed when the account is deleted, with its
  sign-in attempts ([personal data](privacy.md)). Users read their own history
  through `GET /users/me/audit`.
- An email change is confirmed on both addresses, revokes the other sessions,
  and notifies the previous address.
- Account deletion records `user.deleted` in the event outbox in the same
  transaction as the deletion, so downstream erasure cannot be lost and is
  never announced for an account that still exists; the relay delivers it to
  JetStream, waiting for the broker when it is down.
- **Least privilege in the database.** The schema belongs to `auth_api_owner`,
  which runs the migrations; the API connects as `auth_api`, limited to
  reading and writing data (`deploy/db/auth-api-grants.sql`). The audit log is
  append-only for it, the permission catalog and migration history read-only;
  creating and dropping audit partitions, coarsening addresses, erasing an
  account's traces and purging unverified accounts run in functions holding
  the owner's privileges. PostgreSQL logs slow statements without their bound
  values.

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
- A logout racing a refresh of the same session, more than 1 second after
  its rotation, reads as a replay: the family is revoked and a replay audited.
  Kept on purpose, since the audit signal outweighs this rare race.
- Webhook signing secrets, like TOTP secrets, are readable by anyone holding
  `ENCRYPTION_KEY` and a database dump.
- Passkey attestation is not verified: the account's re-authentication vouches
  for a new passkey, not the authenticator's make.
- An access token revoked through `POST /oauth/revoke` is remembered in Redis
  only, until it expires; a Redis failover can forget it.
- Resource servers verifying tokens offline accept a revoked access token until
  it expires, unless they introspect.
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
| SEC-11 | Second-factor codes are single-use and budgeted per challenge and per account | `totp_replay_within_window_rejected`, `totp_replay_rejected_even_after_redis_key_loss`, `concurrent_totp_guesses_never_exceed_the_token_budget`, `account_budget_blocks_fresh_pre_auth_tokens`, `recovery_challenge_rate_limited_after_max_failures`, `email_2fa_lockout_after_max_failures`, `recovery_login_replay_rejected`, `a_code_confirming_a_new_method_cannot_complete_a_sign_in`, `confirming_a_new_method_has_an_attempt_budget`, `recovery_code_guesses_through_the_account_leave_the_sign_in_budget`, `a_challenge_owns_its_state_and_every_failure_budget` |
| SEC-12 | Changes to second factors are notified and keep a usable configuration | `removing_the_last_method_drops_recovery_codes`, `removing_the_primary_method_promotes_the_remaining_one`, `disable_totp_sends_two_factor_disabled_email` |
| SEC-13 | TOTP secrets are encrypted with named keys; rotation is resumable | `keyring_writes_versioned_ciphertexts_it_can_read`, `keyring_refuses_a_key_it_does_not_hold`, `encrypt_produces_different_output_each_call`, `rotate_is_idempotent_when_run_twice`, `rotate_re_encrypts_totp_secret_with_new_key` |
| SEC-14 | Only registered clients obtain sessions through client flows | `a_flow_needs_a_registered_client` |
| SEC-15 | Device flow: user codes reserved atomically, polling paced, approval collected once, account and session limit rechecked under lock | `a_live_user_code_is_never_handed_out_twice`, `polling_faster_than_the_interval_is_slowed_down`, `an_approval_is_collected_exactly_once_under_concurrent_polls`, `a_suspended_account_cannot_collect_approved_tokens`, `a_non_primary_client_is_capped_without_a_quota_row`, `unknown_user_codes_are_rate_limited`, `concurrent_approvals_never_exceed_the_session_limit`, `a_second_factor_answers_an_inactive_account_like_the_password_sign_in` |
| SEC-16 | Authorization code: S256 only, exact or loopback redirects, single use, replay revokes, third-party consent re-authenticates | `only_s256_challenges_are_accepted`, `only_registered_or_loopback_redirects_are_accepted`, `loopback_redirects_accept_any_port_on_a_registered_path`, `a_replayed_code_is_refused_and_revokes_its_session`, `a_wrong_verifier_burns_the_code`, `a_code_is_bound_to_its_client_and_redirect`, `a_third_party_client_requires_a_fresh_reauthentication`, `challenges_and_verifiers_follow_rfc_7636` |
| SEC-17 | Client tokens carry only consented permissions, re-derived on refresh | `tokens_carry_only_the_consented_scopes_even_after_refresh`, `granted_is_an_intersection_unless_unrestricted` |
| SEC-18 | Tokens and codes are stored as digests | `sessions_require_32_byte_hashes`, `email_verification_tokens_are_fixed_length` |
| SEC-19 | The audit log is append-only and holds no personal data | `audit_log_is_append_only`, `audit_log_delete_blocked_by_trigger`, `account_deletion_leaves_no_identity_in_the_audit_log`, `an_email_change_keeps_the_status_and_audits_no_address`, `a_forged_cursor_is_refused_and_the_history_needs_a_session`, `audit_addresses_can_only_be_forgotten_or_coarsened`, `a_deleted_account_leaves_no_address_or_sign_in_attempt_behind`, `old_audit_addresses_keep_only_their_network` |
| SEC-20 | An email change is confirmed on both addresses by the user who started it | `email_change_full_flow_success`, `email_change_steps_cannot_be_skipped`, `email_change_token_bound_to_initiating_user` |
| SEC-21 | Account deletion and its `user.deleted` event commit together, and the event goes out once the broker is back | `account_deletion_publishes_user_deleted_through_jetstream` |
| SEC-22 | Forwarding headers count only from trusted proxies; IPv6 clients share their /64 | `direct_peer_ignores_forwarded_headers`, `trusted_proxy_uses_forwarded_client_ip`, `ipv6_addresses_share_their_64`, `every_forwarded_line_counts_as_one_list`, `an_unreadable_hop_stops_the_walk_at_the_proxy`, `sql_budgets_group_addresses_like_redis_budgets` |
| SEC-23 | Rate limits per client, failing closed in production | `auth_rate_limit_blocks_requests_exceeding_limit`, `auth_routes_fail_closed_when_rate_limiter_backend_is_down`, `a_refused_request_consumes_nothing`, `validate_rejects_production_config_with_rate_limit_fail_open` |
| SEC-24 | Bounded bodies, security headers, CORS allowlist, one error format | `an_oversized_body_is_refused_before_the_handler`, `security_headers_present_on_200_response`, `security_headers_enable_hsts_for_https_production`, `cross_origin_access_is_limited_to_the_allowlist`, `plain_text_errors_become_error_bodies_with_their_headers`, `parser_details_do_not_leak` |
| SEC-25 | Logs carry route templates and never a secret | `access_logs_carry_route_templates_not_codes`, `account_flows_never_log_their_secrets` |
| SEC-26 | Production refuses a configuration that disables a control | `validate_accepts_hardened_production_config`, `validate_rejects_committed_dev_key_in_production`, `validate_rejects_wildcard_cors_in_production`, `validate_rejects_non_https_public_url_in_production`, `validate_rejects_zero_device_poll_interval`, `validate_rejects_poll_interval_not_below_device_ttl`, `validate_rejects_zero_session_lifetime` |
| SEC-27 | Code hygiene: bound SQL parameters, no unsafe code, no panics on request paths, released migrations frozen | `sql_is_never_assembled_from_strings`, `there_is_no_unsafe_code`, `request_paths_never_unwrap`, `released_migrations_are_never_edited` |
| SEC-28 | Every response matches the published OpenAPI contract | `schemas_are_enforced_through_references`, `undocumented_statuses_and_bodies_are_violations`, `documented_schemas_have_unique_names` |
| SEC-29 | Passwords found in known data breaches are refused, and only a hash prefix leaves the service | `registration_refuses_a_breached_password`, `only_the_hash_prefix_leaves_the_service_with_padding_asked`, `a_breached_password_is_refused_on_change_and_on_reset`, `the_range_key_splits_the_uppercase_sha1` |
| SEC-30 | A sign-in from a new device is announced to the owner | `a_sign_in_from_a_new_device_alerts_the_owner`, `the_first_sign_in_and_a_browser_update_raise_no_alert`, `versions_do_not_make_a_new_device` |
| SEC-31 | Administration needs the permission in the token and in the database, and a second factor | `an_account_without_administrative_permission_is_refused`, `an_administrator_without_a_second_factor_is_refused`, `a_permission_revoked_in_the_database_stops_working_before_the_token_expires`, `each_action_requires_its_own_permission`, `an_administrator_cannot_suspend_their_own_account_or_a_pending_one`, `deleting_an_account_needs_a_recent_reauthentication_and_announces_it`, `granting_a_role_needs_a_recent_reauthentication`, `nobody_can_remove_the_last_way_to_manage_roles_or_the_default_role` |
| SEC-32 | The data export needs a recent re-authentication and holds no secret and no other account | `the_export_holds_the_account_its_history_and_no_secret`, `exporting_needs_a_recent_reauthentication` |
| SEC-33 | Sign-in links are single-use, short-lived, replaced by the next one, off by default, and never skip the second factor | `a_link_signs_in_once`, `a_new_link_replaces_the_previous_one_and_an_old_link_expires`, `a_second_factor_is_still_required`, `unknown_pending_and_suspended_addresses_answer_alike_and_get_nothing`, `links_are_capped_per_account_and_off_unless_enabled` |
| SEC-34 | Personal access tokens are stored as digests, shown once, scoped to permissions the account holds, and end with their session or account | `a_token_is_exchanged_for_access_tokens_carrying_its_scopes_only`, `a_revoked_token_and_its_access_tokens_stop_working`, `tokens_expire_and_follow_the_account_status`, `creation_is_checked`, `scopes_are_limited_to_the_permissions_held` |
| SEC-35 | Webhooks are signed, never reach internal addresses or follow redirects, and deliver exactly the committed events | `a_subscribed_endpoint_receives_signed_events`, `internal_addresses_are_never_called`, `internal_addresses_are_refused`, `only_plain_https_urls_are_registered`, `endpoints_are_checked_updated_rotated_and_removed`, `validate_rejects_production_webhooks_to_http_or_internal_addresses` |
| SEC-36 | Confidential clients authenticate at every token request, and client sessions are refreshed only by their client | `a_confidential_client_must_authenticate_with_its_secret`, `a_public_client_has_no_secret_to_present`, `a_device_code_works_for_its_client_only`, `tokens_carry_only_the_consented_scopes_even_after_refresh`, `basic_credentials_are_form_decoded`, `a_request_asks_for_a_subset_of_the_client_scopes` |
| SEC-37 | Introspection is reserved to confidential clients and says nothing of inactive tokens; revocation reaches only the requesting client's tokens | `a_resource_server_learns_what_a_token_is_worth`, `revoking_a_refresh_token_ends_its_session`, `revoking_an_access_token_ends_that_token_only`, `a_client_cannot_revoke_the_tokens_of_another` |
| SEC-38 | The client credentials grant is limited to confidential, scoped clients that enable it, and its tokens never act as a user | `a_client_obtains_a_token_for_itself_with_its_scopes`, `the_grant_is_reserved_to_confidential_clients_that_enable_it`, `a_client_token_is_introspected_and_revoked`, `a_client_subject_is_stable_and_never_a_user_id` |
| SEC-39 | ID tokens are bound to their client, nonce and access token, and identity scopes release only their claims | `an_openid_request_gets_an_id_token_bound_to_its_nonce_and_access_token`, `userinfo_releases_the_claims_of_the_granted_scopes`, `scopes_release_their_claims_only` |
| SEC-40 | Passkeys: registration re-authenticated and verified, sign-in challenges single use, signatures verified, cloned counters refused | `a_registration_is_verified_before_it_is_stored`, `forged_replayed_or_cloned_assertions_are_refused`, `a_passkey_signs_in_without_password_or_second_factor`, `a_removed_passkey_no_longer_signs_in`, `assertions_verify_against_the_stored_key_only`, `client_data_answers_the_challenge_from_an_allowed_origin`, `validate_rejects_production_passkey_origins_outside_the_relying_party` |
| SEC-41 | External identities sign in only once linked by the owner, bound to the starting browser, with verified ID tokens | `a_linked_identity_signs_in_and_an_unlinked_one_never_does`, `an_outcome_is_used_once_by_the_browser_that_started_it`, `an_id_token_that_does_not_verify_identifies_nobody`, `a_token_for_something_else_is_refused`, `a_callback_alone_links_nothing` |
| SEC-42 | Delegated tokens (third-party clients, scoped sessions, personal access tokens) never act as the account: refused on account, approval and administration routes; approving another client's device needs a re-authentication | `delegated_tokens_are_refused_on_every_account_approval_and_admin_route`, `a_delegated_token_cannot_approve_itself_an_unrestricted_session`, `the_instance_application_without_scopes_acts_as_the_account`, `approving_another_client_needs_a_recent_reauthentication`, `only_sign_ins_and_the_primary_application_act_as_the_account` |
| SEC-43 | A registration on a pending address carries its own credentials in its link: registering someone's address first does not choose the password they activate | `the_owner_activates_the_account_with_the_password_they_chose`, `a_resend_repeats_the_latest_registration_not_the_first`, `resent_links_coexist_until_one_verifies_the_account`, `email_verification_tokens_carry_complete_credentials_or_none` |
| SEC-44 | Ways into an account that outlive its password are announced: adding a passkey, a personal access token or an external identity mails the owner, a password change or reset lists what still opens the account, and a pending account taken back by a reset keeps none | `adding_a_passkey_or_a_token_is_announced_to_the_owner`, `a_reset_lists_what_still_opens_the_account`, `a_pending_account_taken_back_by_a_reset_keeps_no_other_access` |
| SEC-45 | The administration requires a session whose sign-in proved a second factor, not merely an enrolled one; an administrative role goes only to an active account with a second factor, never to oneself | `an_administrator_whose_sign_in_skipped_the_second_factor_is_refused`, `only_a_sign_in_with_a_second_factor_marks_its_session`, `an_administrative_role_goes_only_to_an_active_account_with_a_second_factor`, `an_administrator_never_grants_a_role_to_their_own_account`, `granting_a_role_assigns_it_once_and_audits_it` |
| SEC-46 | Administrative actions that redirect events or lock owners out need a recent re-authentication (webhooks, suspension, forced reset, client secrets), and every change is audited in its own transaction, redeliveries and webhook hosts included | `pointing_a_webhook_somewhere_needs_a_reauthentication_and_is_traced`, `a_redelivery_is_audited`, `suspending_or_forcing_a_reset_needs_a_recent_reauthentication` |
| SEC-47 | No change leaves the deployment without an active account able to manage roles: role changes, suspension and deletion (by an administrator or by the owner) are refused, and concurrent withdrawals are serialized | `nobody_can_remove_the_last_way_to_manage_roles_or_the_default_role`, `the_last_role_manager_is_neither_suspended_nor_deleted`, `concurrent_withdrawals_never_leave_nobody_managing_roles` |
| SEC-48 | The API connects with a role that reads and writes data only: it cannot alter the schema, truncate or rewrite the audit log, or change the permission catalog and migration history; maintenance needing more runs in owner-privileged functions | `the_runtime_role_cannot_erase_the_audit_trail_or_alter_the_schema`, `the_runtime_role_does_everything_the_service_needs` |
| SEC-49 | Secrets at rest resist a database copy: email codes are keyed digests, ciphertexts are bound to their row, secrets are compared in constant time, and a secret under a removed key stops the start-up | `otp_digests_are_keyed_bound_and_survive_a_rotation`, `a_ciphertext_moved_to_another_row_no_longer_decrypts`, `constant_time_equality_compares_contents_and_lengths`, `secrets_under_a_removed_key_are_detected`, `email_code_lookup_is_scoped_to_the_challenged_user`, `debug_output_never_shows_the_password_hash` |
| SEC-50 | Settings that would weaken a control are refused at start-up (TOTP skew beyond the replay window, Argon2 under the OWASP floor in production, lifetimes and windows out of range, a zero rate limit), and weaker stored hashes are replaced as accounts sign in | `validate_bounds_the_totp_skew_to_what_the_replay_table_covers`, `validate_refuses_weak_argon2_parameters_in_production_only`, `validate_bounds_lifetimes_windows_and_limits`, `a_hash_weaker_than_the_configuration_is_rehashed`, `a_weaker_password_hash_is_replaced_after_sign_in` |
| SEC-51 | Password guesses with a stolen token are bounded without locking the owner out: every route taking the current password is strict, re-authentication failures count per session, the authenticated recovery route has its own budget, and client endpoints are bounded per client rather than per address | `routes_taking_the_current_password_count_against_the_strict_bucket`, `a_stolen_session_guessing_the_password_does_not_lock_the_owner_out`, `the_authenticated_recovery_route_spends_its_own_budget`, `client_endpoints_are_bounded_per_client_and_per_wrong_secret` |
| SEC-52 | Revocations take effect at once: a revoked family loses its cached validity, a racing check cannot restore it, a pre-auth token is consumed before its session is issued, refused refreshes are counted, and token responses forbid every cache | `a_revoked_family_loses_its_cached_validity_at_once`, `replayed_refresh_tokens_count_against_the_address`, `token_responses_forbid_every_cache`, `a_cached_session_reads_back_as_it_was_stored` |
| SEC-53 | Checks and the actions they guard cannot be raced apart: a replayed authorization code waits for its redemption and revokes what it produced, cooldowns are claimed before acting, and the token quota is counted under a lock | `a_code_redeemed_twice_at_once_leaves_no_session_alive`, `concurrent_recovery_code_regenerations_run_once`, `concurrent_creations_respect_the_token_limit` |
| SEC-54 | Email flows reveal nothing and flood no one: registration is padded and budgets its notices, an email change to a taken address answers like any other, new-address codes are budgeted, earlier links die with the password or address, and CAPTCHA tokens are bound to the site | `registration_takes_a_constant_minimum_time`, `registering_a_taken_address_repeatedly_notifies_its_owner_a_few_times`, `email_change_submit_taken_email_answers_like_a_free_one`, `email_change_submissions_are_budgeted`, `a_password_change_ends_the_links_already_mailed`, `a_token_solved_on_another_site_is_refused` |
| SEC-55 | Identifiers are unambiguous and not over-collected: usernames are unique whatever their case, and a failed sign-in records the identifier only when it is an address or a username | `usernames_differing_only_in_case_cannot_coexist`, `an_unrecognized_identifier_is_not_recorded`, `only_addresses_and_usernames_are_recorded` |
