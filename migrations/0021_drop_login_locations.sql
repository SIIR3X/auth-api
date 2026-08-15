-- 0021_drop_login_locations.sql
-- Removes the login location history. It only fed behavioural risk scoring,
-- which is retired: without a GeoIP database just "new user agent" and "unusual
-- hour" could fire, producing noisy alerts, and the table grew with no retention.
-- The `suspicious_login` and `new_device_login` audit actions stay in the enum
-- (Postgres cannot drop enum values in place) so historical rows remain readable.
DROP TABLE IF EXISTS login_locations;
