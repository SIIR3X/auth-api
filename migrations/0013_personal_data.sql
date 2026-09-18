-- Personal data: what a deleted account leaves behind, and how long the audit
-- log keeps full client addresses.

-- The audit log stays append-only. Two narrowing updates are allowed and
-- nothing else: detaching a deleted user (user_id to NULL), and forgetting or
-- coarsening a client address (ip_address to NULL, or to a network containing
-- it).
CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.id = OLD.id
       AND NEW.request_id IS NOT DISTINCT FROM OLD.request_id
       AND NEW.created_at = OLD.created_at
       AND NEW.action = OLD.action
       AND NEW.metadata = OLD.metadata
       AND (NEW.user_id IS NOT DISTINCT FROM OLD.user_id OR NEW.user_id IS NULL)
       AND (
           NEW.ip_address IS NOT DISTINCT FROM OLD.ip_address
           OR NEW.ip_address IS NULL
           OR (masklen(NEW.ip_address) < masklen(OLD.ip_address)
               AND OLD.ip_address <<= NEW.ip_address)
       )
       AND (NEW.user_id IS DISTINCT FROM OLD.user_id
            OR NEW.ip_address IS DISTINCT FROM OLD.ip_address) THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

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
$$ LANGUAGE plpgsql;

-- Purge of never-verified accounts (0012), forgetting their traces too.
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

    PERFORM forget_account_traces(id) FROM unnest(doomed) AS id;

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
          AND created_at < NOW() - age
        LIMIT batch_size
    ) AS due
    WHERE entry.created_at = due.created_at AND entry.id = due.id;
    GET DIAGNOSTICS coarsened = ROW_COUNT;
    RETURN coarsened;
END;
$$ LANGUAGE plpgsql;
