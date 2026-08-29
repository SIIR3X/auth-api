-- 0025_encryption_key_rotated.sql
-- Key rotations were audited as `two_factor_enabled`, the closest existing
-- action: an operator reading the log saw a user enabling 2FA with no user.
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'encryption_key_rotated';
