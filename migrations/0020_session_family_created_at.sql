-- 0020_session_family_created_at.sql
-- Records when a session family started, so the absolute session lifetime
-- (JWT_MAX_SESSION_LIFETIME_SECS) is measured from the original sign-in. Every
-- refresh rotation inserts a new row with a fresh created_at, so measuring from
-- the current row let a regularly refreshed family live forever.
ALTER TABLE sessions ADD COLUMN family_created_at TIMESTAMPTZ;

UPDATE sessions s
SET family_created_at = f.started
FROM (
    SELECT session_family_id, MIN(created_at) AS started
    FROM sessions
    GROUP BY session_family_id
) f
WHERE s.session_family_id = f.session_family_id;

ALTER TABLE sessions
    ALTER COLUMN family_created_at SET DEFAULT NOW(),
    ALTER COLUMN family_created_at SET NOT NULL;
