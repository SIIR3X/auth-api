-- Autovacuum for the two plain tables that change fastest. With the default
-- scale factors (a vacuum once 20 % of the rows changed, an analyze at 10 %),
-- 6 million sessions wait for 1.2 million dead rows: the table bloats and the
-- planner's statistics drift between runs. 2 % and 1 % keep both current.
-- audit_log is partitioned and append-only: its partitions keep the defaults,
-- which suit inserts.
ALTER TABLE sessions SET (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_analyze_scale_factor = 0.01
);

ALTER TABLE login_attempts SET (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_vacuum_insert_scale_factor = 0.02,
    autovacuum_analyze_scale_factor = 0.01
);
