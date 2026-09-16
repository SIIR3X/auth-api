-- Accounts whose address was never verified are purged after a configurable
-- age, so an address registered by mistake (or by someone else) becomes free
-- again. Each purge is audited and announced with `user.deleted`, like a
-- deletion by the user, in the same transaction as the deletion.
CREATE OR REPLACE FUNCTION purge_unverified_accounts(
    age INTERVAL,
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    doomed UUID[];
    purged INTEGER;
BEGIN
    SELECT array_agg(id) INTO doomed
    FROM (
        SELECT id FROM users
        WHERE status = 'pending_verification' AND created_at < NOW() - age
        ORDER BY created_at
        LIMIT batch_size
        FOR UPDATE SKIP LOCKED
    ) oldest;

    IF doomed IS NULL THEN
        RETURN 0;
    END IF;

    -- Written before the deletion: the foreign key then sets user_id to NULL.
    INSERT INTO audit_log (user_id, action, metadata)
    SELECT id, 'account_deleted', '{"reason": "never_verified"}'::JSONB
    FROM unnest(doomed) AS id;

    INSERT INTO event_outbox (subject, payload)
    SELECT 'events.auth.user.deleted', jsonb_build_object('user_id', id)
    FROM unnest(doomed) AS id;

    DELETE FROM users WHERE id = ANY (doomed);
    GET DIAGNOSTICS purged = ROW_COUNT;
    RETURN purged;
END;
$$ LANGUAGE plpgsql;

-- The purge reads pending accounts by age.
CREATE INDEX idx_users_pending_created
    ON users (created_at) WHERE status = 'pending_verification';
