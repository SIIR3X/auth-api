-- Account owners download what the service stores about them.
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'data_exported';
