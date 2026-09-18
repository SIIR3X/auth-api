-- Devices an account signed in from, to tell its owner about a sign-in from a
-- new one. A device is its browser and operating system families, hashed:
-- versions and network addresses are left out, so updates and mobile networks
-- do not raise false alarms.
CREATE TABLE known_devices (
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    fingerprint BYTEA NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (user_id, fingerprint),
    CONSTRAINT known_devices_fingerprint_length CHECK (octet_length(fingerprint) = 32)
);

-- Retention deletes devices unseen for a while.
CREATE INDEX idx_known_devices_last_seen ON known_devices (last_seen_at);

-- Bounded like the other retention functions.
CREATE OR REPLACE FUNCTION cleanup_stale_known_devices(
    age INTERVAL,
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM known_devices WHERE ctid = ANY (ARRAY(
        SELECT ctid FROM known_devices
        WHERE last_seen_at < NOW() - age
        LIMIT batch_size
    ));
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;
