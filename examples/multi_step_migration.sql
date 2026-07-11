-- Multi-step expand/contract migration for adding a required column
-- Recommended pattern for zero-downtime schema changes

-- Phase 1: EXPAND — add nullable column
ALTER TABLE users ADD COLUMN display_name VARCHAR(255);

-- Phase 2: Deploy app code that writes display_name on new records

-- Phase 3: Backfill in batches (comments document safe execution)
-- BATCH: UPDATE users SET display_name = name WHERE id > :last_id AND display_name IS NULL ORDER BY id LIMIT 5000;
-- BATCH: sleep between batches; monitor replication lag

-- Phase 4: Deploy app code that reads display_name with fallback to name

-- Phase 5: Validate backfill complete
-- SELECT COUNT(*) FROM users WHERE display_name IS NULL;  -- expect 0

-- Phase 6: CONTRACT — add NOT NULL after validation (separate migration)
-- ALTER TABLE users ALTER COLUMN display_name SET NOT NULL;

-- Phase 7: CONTRACT — stop writing to old column, then drop later
-- ROLLBACK: backup users table before any drop
-- ALTER TABLE users DROP COLUMN name;  -- only after all app instances migrated
