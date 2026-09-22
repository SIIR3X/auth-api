-- Personal data: what a deleted or never-verified account leaves behind, and
-- how long the audit log keeps full client addresses. These functions rewrite
-- audit rows and delete accounts, so they run with their owner's privileges
-- like rotate_audit_log_partitions.

-- Forget what an account leaves outside its own rows, in the transaction that
-- deletes it and before its row goes: the client addresses of its audit
-- entries, and its sign-in attempts, recorded under its id or under the
-- identifiers typed for it before it existed. The audit entries themselves stay,
-- without identity, for the retention period.
CREATE OR REPLACE FUNCTION forget_account_traces(p_user_id UUID)
RETURNS VOID AS $$
DECLARE
    identity RECORD;
BEGIN
    SELECT email, username INTO identity FROM users WHERE id = p_user_id;

    UPDATE audit_log SET ip_address = NULL
    WHERE user_id = p_user_id AND ip_address IS NOT NULL;

    DELETE FROM login_attempts WHERE user_id = p_user_id;

    IF identity.email IS NOT NULL THEN
        -- Attempts without an account id are failures: their partial index serves this.
        DELETE FROM login_attempts
        WHERE was_successful = FALSE
          AND attempted_identifier IN (identity.email, identity.username::CITEXT);
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

REVOKE EXECUTE ON FUNCTION forget_account_traces(UUID) FROM PUBLIC;

-- Accounts whose address was never verified are purged after a configurable
-- age, so an address registered by mistake (or by someone else) becomes free
-- again. Each purge forgets the account's traces, is audited and announced with
-- `user.deleted`, like a deletion by the user, in the same transaction.
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
        WHERE status = 'pending_verification'
          AND created_at < NOW() - GREATEST(age, (SELECT unverified_account_min_age FROM maintenance_floors))
        ORDER BY created_at
        LIMIT batch_size
        FOR UPDATE SKIP LOCKED
    ) oldest;

    IF doomed IS NULL THEN
        RETURN 0;
    END IF;

    PERFORM forget_account_traces(id) FROM unnest(doomed) AS id;

    -- Written before the deletion: the foreign key then sets user_id to NULL.
    INSERT INTO audit_log (user_id, action, metadata)
    SELECT id, 'account_deleted', '{"reason": "never_verified"}'::JSONB
    FROM unnest(doomed) AS id;

    -- Announced like any deletion, webhooks included: an endpoint erasing the
    -- account's data downstream hears of every deletion, not only the others.
    WITH event AS (
        INSERT INTO event_outbox (subject, payload)
        SELECT 'events.auth.user.deleted', jsonb_build_object('user_id', id)
        FROM unnest(doomed) AS id
        RETURNING id, payload, created_at
    )
    INSERT INTO webhook_deliveries (endpoint_id, event_id, event_name, payload, occurred_at)
    SELECT endpoint.id, event.id, 'user.deleted', event.payload, event.created_at
    FROM event CROSS JOIN webhook_endpoints endpoint
    WHERE endpoint.enabled
      AND ('user.deleted' = ANY (endpoint.events) OR '*' = ANY (endpoint.events));

    DELETE FROM users WHERE id = ANY (doomed);
    GET DIAGNOSTICS purged = ROW_COUNT;
    RETURN purged;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

REVOKE EXECUTE ON FUNCTION purge_unverified_accounts(INTERVAL, INTEGER) FROM PUBLIC;

-- Audit entries still holding a full client address: the coarsening job reads
-- them by age, and a row leaves the index once coarsened.
CREATE INDEX idx_audit_log_full_address
    ON audit_log (created_at)
    WHERE ip_address IS NOT NULL
      AND masklen(ip_address) = CASE WHEN family(ip_address) = 4 THEN 32 ELSE 128 END;

-- Keep the network of an address older than `age` and drop the host part:
-- /24 for IPv4, /48 for IPv6. Enough to investigate abuse from a network,
-- no longer an identifier of a subscriber. Batched by primary key, since
-- ctid is not unique across partitions.
CREATE OR REPLACE FUNCTION coarsen_audit_addresses(
    age INTERVAL,
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    coarsened INTEGER;
BEGIN
    UPDATE audit_log AS entry
    SET ip_address = network(set_masklen(
        entry.ip_address,
        CASE WHEN family(entry.ip_address) = 4 THEN 24 ELSE 48 END
    ))
    FROM (
        SELECT created_at, id FROM audit_log
        WHERE ip_address IS NOT NULL
          AND masklen(ip_address) = CASE WHEN family(ip_address) = 4 THEN 32 ELSE 128 END
          AND created_at < NOW() - GREATEST(age, (SELECT audit_address_min_age FROM maintenance_floors))
        LIMIT batch_size
    ) AS due
    WHERE entry.created_at = due.created_at AND entry.id = due.id;
    GET DIAGNOSTICS coarsened = ROW_COUNT;
    RETURN coarsened;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

REVOKE EXECUTE ON FUNCTION coarsen_audit_addresses(INTERVAL, INTEGER) FROM PUBLIC;
