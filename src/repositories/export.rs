//! Everything stored about one account, as one JSON document: what
//! `GET /users/me/export` returns. Built in one statement, so the parts are
//! consistent with each other. Secrets (password hash, TOTP secret, token and
//! code digests) are left out. Timestamps are Unix seconds, like the API.

use sqlx::PgPool;
use uuid::Uuid;

const EXPORT_SQL: &str = "
SELECT jsonb_build_object(
    'account', (
        SELECT jsonb_build_object(
            'id', u.id,
            'username', u.username,
            'email', u.email,
            'status', u.status,
            'preferred_locale', u.preferred_locale,
            'created_at', floor(extract(epoch FROM u.created_at))::bigint,
            'updated_at', floor(extract(epoch FROM u.updated_at))::bigint,
            'email_verified_at', floor(extract(epoch FROM u.email_verified_at))::bigint,
            'last_login_at', floor(extract(epoch FROM u.last_login_at))::bigint,
            'locked_until', floor(extract(epoch FROM u.locked_until))::bigint
        )
        FROM users u WHERE u.id = $1
    ),
    'roles', COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
            'name', r.name,
            'granted_at', floor(extract(epoch FROM ur.granted_at))::bigint
        ) ORDER BY r.name)
        FROM user_roles ur JOIN roles r ON r.id = ur.role_id
        WHERE ur.user_id = $1
    ), '[]'::jsonb),
    'sessions', COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
            'id', s.id,
            'session_type', s.session_type,
            'client_id', s.client_id,
            'device_name', s.device_name,
            'user_agent', s.user_agent,
            'ip_address', host(s.ip_address),
            'created_at', floor(extract(epoch FROM s.created_at))::bigint,
            'last_used_at', floor(extract(epoch FROM s.last_used_at))::bigint,
            'expires_at', floor(extract(epoch FROM s.expires_at))::bigint,
            'revoked_at', floor(extract(epoch FROM s.revoked_at))::bigint
        ) ORDER BY s.created_at)
        FROM sessions s WHERE s.user_id = $1
    ), '[]'::jsonb),
    'two_factor_methods', COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
            'id', m.id,
            'method_type', m.method_type,
            'is_primary', m.is_primary,
            'is_verified', m.is_verified,
            'created_at', floor(extract(epoch FROM m.created_at))::bigint,
            'last_used_at', floor(extract(epoch FROM m.last_used_at))::bigint
        ) ORDER BY m.created_at)
        FROM two_factor_methods m WHERE m.user_id = $1
    ), '[]'::jsonb),
    'recovery_codes', (
        SELECT jsonb_build_object(
            'total', COUNT(*),
            'used', COUNT(*) FILTER (WHERE c.used_at IS NOT NULL)
        )
        FROM recovery_codes c WHERE c.user_id = $1
    ),
    'known_devices', COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
            'first_seen_at', floor(extract(epoch FROM d.first_seen_at))::bigint,
            'last_seen_at', floor(extract(epoch FROM d.last_seen_at))::bigint
        ) ORDER BY d.first_seen_at)
        FROM known_devices d WHERE d.user_id = $1
    ), '[]'::jsonb),
    'client_quotas', COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
            'client_id', q.client_id,
            'max_sessions', q.max_sessions,
            'created_at', floor(extract(epoch FROM q.created_at))::bigint
        ) ORDER BY q.client_id)
        FROM user_client_quotas q WHERE q.user_id = $1
    ), '[]'::jsonb),
    'sign_in_attempts', COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
            'attempted_at', floor(extract(epoch FROM a.attempted_at))::bigint,
            'identifier', a.attempted_identifier,
            'successful', a.was_successful,
            'failure_reason', a.failure_reason,
            'ip_address', host(a.request_ip),
            'user_agent', a.request_user_agent
        ) ORDER BY a.attempted_at)
        FROM login_attempts a WHERE a.user_id = $1
    ), '[]'::jsonb),
    'audit_log', COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
            'id', l.id,
            'created_at', floor(extract(epoch FROM l.created_at))::bigint,
            'action', l.action,
            'ip_address', host(l.ip_address),
            'request_id', l.request_id,
            'metadata', l.metadata
        ) ORDER BY l.created_at, l.id)
        FROM audit_log l WHERE l.user_id = $1 AND l.created_at <= NOW()
    ), '[]'::jsonb)
)
FROM users WHERE id = $1";

/// The document, or `None` when the account does not exist.
pub async fn account_document(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<serde_json::Value>, sqlx::Error> {
    sqlx::query_scalar(EXPORT_SQL)
        .bind(user_id)
        .fetch_optional(pool)
        .await
}
