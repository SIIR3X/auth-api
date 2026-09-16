-- Transactional outbox of the domain events delivered to NATS JetStream.
--
-- An event is inserted in the transaction of the change it announces: a
-- committed change always has its event, and a rolled-back change announces
-- nothing. A background relay publishes pending events in `seq` order, waits
-- for JetStream to store each one, and uses the event id as the message id so a
-- publication repeated after a crash is deduplicated.
CREATE TABLE event_outbox (
    seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    subject TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error TEXT,

    CONSTRAINT event_outbox_id_key UNIQUE (id),
    CONSTRAINT event_outbox_subject_format CHECK (subject ~ '^events\.auth\.[a-z_]+(\.[a-z_]+)*$'),
    CONSTRAINT event_outbox_payload_object CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT event_outbox_attempts_non_negative CHECK (attempts >= 0)
);

-- The relay reads the head of the queue.
CREATE INDEX idx_event_outbox_pending ON event_outbox (seq) WHERE published_at IS NULL;
-- Retention deletes published events by age.
CREATE INDEX idx_event_outbox_published_at
    ON event_outbox (published_at) WHERE published_at IS NOT NULL;

-- Published events are kept a while for investigation, then swept by the
-- application's cleanup task, in batches like the other retention functions.
CREATE OR REPLACE FUNCTION cleanup_published_events(
    retention INTERVAL DEFAULT '7 days',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM event_outbox WHERE ctid = ANY (ARRAY(
        SELECT ctid FROM event_outbox
        WHERE published_at < NOW() - retention
        LIMIT batch_size
    ));
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;
