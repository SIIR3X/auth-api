-- Usernames are unique whatever their case: `Alice` and `alice` no longer
-- coexist, one impersonating the other. The sign-in lookup and the brute-force
-- counters already treat them as one identifier.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM users GROUP BY lower(username) HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'usernames differing only in case exist; rename all but one of each before migrating. List them with: SELECT lower(username), array_agg(username) FROM users GROUP BY 1 HAVING count(*) > 1';
    END IF;
END
$$;

CREATE UNIQUE INDEX users_username_lower_key ON users (lower(username));
