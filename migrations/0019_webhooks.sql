-- Webhooks: domain events delivered over HTTPS to endpoints registered by an
-- administrator, signed with a per-endpoint secret (Standard Webhooks).
CREATE TABLE webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url TEXT NOT NULL,
    description VARCHAR(200),
    -- Event names such as `user.deleted`, or `*` for every event.
    events TEXT[] NOT NULL,
    -- Signing secret, encrypted with the application keyring.
    secret TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT webhook_endpoints_url_length CHECK (char_length(url) BETWEEN 1 AND 2000),
    CONSTRAINT webhook_endpoints_events_not_empty CHECK (cardinality(events) > 0)
);

CREATE TRIGGER webhook_endpoints_set_updated_at
    BEFORE UPDATE ON webhook_endpoints
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- One delivery per endpoint and event, recorded in the transaction of the
-- change, like the event itself.
CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints (id) ON DELETE CASCADE,
    event_id UUID NOT NULL,
    event_name TEXT NOT NULL,
    payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    -- Set when the last attempt failed: no retry follows.
    failed_at TIMESTAMPTZ,
    last_status SMALLINT,
    last_error TEXT,

    CONSTRAINT webhook_deliveries_event_key UNIQUE (endpoint_id, event_id),
    CONSTRAINT webhook_deliveries_one_outcome CHECK (delivered_at IS NULL OR failed_at IS NULL)
);

-- The dispatcher's queue: deliveries still to attempt, soonest first.
CREATE INDEX idx_webhook_deliveries_due ON webhook_deliveries (next_attempt_at)
    WHERE delivered_at IS NULL AND failed_at IS NULL;
CREATE INDEX idx_webhook_deliveries_endpoint ON webhook_deliveries (endpoint_id, created_at DESC);
CREATE INDEX idx_webhook_deliveries_finished ON webhook_deliveries (created_at)
    WHERE delivered_at IS NOT NULL OR failed_at IS NOT NULL;

-- Finished deliveries are kept a while for inspection, then deleted.
CREATE OR REPLACE FUNCTION cleanup_finished_webhook_deliveries(
    retention INTERVAL,
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM webhook_deliveries WHERE ctid = ANY (ARRAY(
        SELECT ctid FROM webhook_deliveries
        WHERE (delivered_at IS NOT NULL OR failed_at IS NOT NULL)
          AND created_at < NOW() - retention
        LIMIT batch_size
    ));
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'webhook_created';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'webhook_updated';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'webhook_deleted';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'webhook_secret_rotated';
