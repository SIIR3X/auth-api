-- Deterministic, incremental data set for performance runs.
--
-- Seeds users :from..:to (inclusive) with the history an account accumulates
-- in production. Identifiers derive from the user index, so the load
-- generator can address any user without reading the database:
--
--   user id          perf_uuid('perf-user-' || i)
--   email            perf<i>@example.com
--   active sessions  perf_uuid('perf-session-' || i || '-' || k), k = 1..2
--   refresh tokens   'perf-rt-' || i || '-' || k
--
-- Per user: 2 active sessions and 3 expired or revoked ones, 10 login
-- attempts over 90 days (2 failures), 15 audit entries over 25 days, a used
-- email verification token. Every 5th user has TOTP with 10 recovery codes,
-- every 20th (offset 1) email two-factor, every 10th a used reset token.
-- Every user shares one Argon2id hash (:'hash') computed with production
-- parameters, so verifying a password costs what it costs in production.
--
-- psql -v from=1 -v to=50000 -v hash='$argon2id$...' -f perf/seed.sql

\set ON_ERROR_STOP on
SET synchronous_commit = off;

-- First 16 bytes of the SHA-256 of a seed string, as a UUID: the load
-- generator derives the same identifiers without querying the database.
CREATE OR REPLACE FUNCTION perf_uuid(seed text) RETURNS uuid
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$ SELECT substr(encode(sha256(convert_to(seed, 'UTF8')), 'hex'), 1, 32)::uuid $$;

BEGIN;

INSERT INTO users (id, created_at, email_verified_at, last_login_at, status,
                   preferred_locale, username, email, password_hash)
SELECT perf_uuid('perf-user-' || i),
       now() - ((i % 365) + 1) * interval '1 day',
       now() - ((i % 365) + 1) * interval '1 day' + interval '1 minute',
       now() - (i % 720) * interval '1 hour',
       'active',
       CASE WHEN i % 4 = 0 THEN 'fr' ELSE 'en' END,
       'perf_' || i,
       'perf' || i || '@example.com',
       :'hash'
FROM generate_series(:from, :to) i;

INSERT INTO user_roles (user_id, role_id)
SELECT perf_uuid('perf-user-' || i), r.id
FROM generate_series(:from, :to) i
CROSS JOIN (SELECT id FROM roles WHERE is_default) r;

-- Active sessions: the ones access tokens and refresh tokens point at.
INSERT INTO sessions (id, user_id, session_family_id, family_created_at, created_at,
                      last_used_at, expires_at, ip_address, device_name, remember_me,
                      token_hash, user_agent, session_type)
SELECT perf_uuid('perf-session-' || i || '-' || k),
       perf_uuid('perf-user-' || i),
       perf_uuid('perf-family-' || i || '-' || k),
       now() - interval '5 days',
       now() - interval '1 day',
       now() - ((i + k) % 600) * interval '1 minute',
       now() + interval '25 days',
       ('10.' || (i % 250) || '.' || ((i / 250) % 250) || '.' || k)::inet,
       CASE k WHEN 1 THEN 'Laptop' ELSE 'Phone' END,
       k = 1,
       sha256(convert_to('perf-rt-' || i || '-' || k, 'UTF8')),
       'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',
       'web'
FROM generate_series(:from, :to) i
CROSS JOIN generate_series(1, 2) k;

-- History: expired and revoked sessions, past the cleanup grace period.
INSERT INTO sessions (user_id, session_family_id, family_created_at, created_at, last_used_at,
                      expires_at, revoked_at, ip_address, remember_me, token_hash, user_agent)
SELECT perf_uuid('perf-user-' || i),
       perf_uuid('perf-old-family-' || i || '-' || k),
       now() - interval '60 days',
       now() - (30 + k) * interval '1 day',
       now() - (29 + k) * interval '1 day',
       now() - (5 + k) * interval '1 day',
       now() - (20 + k) * interval '1 day',
       '198.51.100.7',
       false,
       sha256(convert_to('perf-old-' || i || '-' || k, 'UTF8')),
       'Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0'
FROM generate_series(:from, :to) i
CROSS JOIN generate_series(1, 3) k;

INSERT INTO login_attempts (user_id, attempted_at, attempted_identifier, was_successful,
                            failure_reason, request_ip, request_user_agent)
SELECT perf_uuid('perf-user-' || i),
       now() - interval '1 hour' - ((i * 7 + k * 13) % (90 * 24)) * interval '1 hour',
       'perf' || i || '@example.com',
       k > 2,
       CASE WHEN k <= 2 THEN 'invalid_password'::login_failure_reason END,
       ('10.' || (i % 250) || '.' || ((i / 250) % 250) || '.' || (k * 20))::inet,
       CASE WHEN k <= 2 THEN 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Firefox/140.0' END
FROM generate_series(:from, :to) i
CROSS JOIN generate_series(1, 10) k;

INSERT INTO audit_log (user_id, request_id, created_at, action, ip_address, metadata)
SELECT perf_uuid('perf-user-' || i),
       perf_uuid('perf-request-' || i || '-' || k),
       now() - ((i * 11 + k * 97) % (25 * 24 * 60)) * interval '1 minute',
       (ARRAY['login', 'login', 'login', 'logout', 'reauthenticated', 'password_changed',
              'session_revoked', 'two_factor_verified']::audit_action[])[1 + (i + k) % 8],
       ('10.' || (i % 250) || '.' || ((i / 250) % 250) || '.9')::inet,
       '{}'::jsonb
FROM generate_series(:from, :to) i
CROSS JOIN generate_series(1, 15) k;

INSERT INTO two_factor_methods (user_id, method_type, is_primary, is_verified, totp_secret,
                                created_at, last_used_at)
SELECT perf_uuid('perf-user-' || i), 'totp', true, true,
       'v1:perfseed:' || encode(sha256(convert_to('perf-totp-' || i, 'UTF8')), 'base64'),
       now() - interval '100 days',
       now() - (i % 20) * interval '1 day'
FROM generate_series(:from, :to) i
WHERE i % 5 = 0;

INSERT INTO two_factor_methods (user_id, method_type, is_primary, is_verified, created_at)
SELECT perf_uuid('perf-user-' || i), 'email', true, true, now() - interval '50 days'
FROM generate_series(:from, :to) i
WHERE i % 20 = 1;

INSERT INTO recovery_codes (user_id, code_position, code_hash, created_at, expires_at, used_at)
SELECT perf_uuid('perf-user-' || i), p,
       sha256(convert_to('perf-rc-' || i || '-' || p, 'UTF8')),
       now() - interval '100 days',
       now() + interval '265 days',
       CASE WHEN p <= 2 THEN now() - interval '10 days' END
FROM generate_series(:from, :to) i
CROSS JOIN generate_series(1, 10) p
WHERE i % 5 = 0;

INSERT INTO email_verification_tokens (user_id, token_hash, target_email, created_at,
                                       expires_at, used_at)
SELECT perf_uuid('perf-user-' || i),
       sha256(convert_to('perf-evt-' || i, 'UTF8')),
       'perf' || i || '@example.com',
       now() - ((i % 365) + 1) * interval '1 day',
       now() - ((i % 365) + 1) * interval '1 day' + interval '1 day',
       now() - ((i % 365) + 1) * interval '1 day' + interval '10 minutes'
FROM generate_series(:from, :to) i;

INSERT INTO password_reset_tokens (user_id, token_hash, created_at, expires_at, used_at)
SELECT perf_uuid('perf-user-' || i),
       sha256(convert_to('perf-prt-' || i, 'UTF8')),
       now() - interval '40 days',
       now() - interval '40 days' + interval '30 minutes',
       now() - interval '40 days' + interval '5 minutes'
FROM generate_series(:from, :to) i
WHERE i % 10 = 0;

COMMIT;
