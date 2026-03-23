-- 0015_login_locations.sql
-- Login location history used for behavioral risk scoring.
-- One row per distinct (user, country, city, user_agent); refreshed on each
-- successful login so recent vs. stale observations can be distinguished.
CREATE TABLE login_locations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    country TEXT NOT NULL,
    city TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    ip_address INET NOT NULL,
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_login_locations_upsert
    ON login_locations (user_id, country, city, user_agent);
CREATE INDEX idx_login_locations_last_seen
    ON login_locations (user_id, last_seen DESC);
