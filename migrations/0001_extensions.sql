-- Extensions and the trigger function shared by tables with an updated_at column.
-- - pgcrypto: gen_random_uuid()
-- - citext: case-insensitive text for e-mail addresses and sign-in identifiers
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
