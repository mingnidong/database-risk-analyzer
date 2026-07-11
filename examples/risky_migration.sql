-- Risky migration: demonstrates multiple dangerous patterns
-- WARNING: Do not run in production without review

BEGIN;

-- 1. NOT NULL column without backfill path
ALTER TABLE users ADD COLUMN age INTEGER NOT NULL;

-- 2. Column with default on large table
ALTER TABLE users ADD COLUMN tier TEXT DEFAULT 'free';

-- 3. Volatile default
ALTER TABLE users ADD COLUMN session_id UUID DEFAULT gen_random_uuid();

-- 4. Index without CONCURRENTLY on huge events table
CREATE INDEX idx_events_type ON events(event_type);

-- 5. Unique constraint on large table
ALTER TABLE users ADD CONSTRAINT unique_phone UNIQUE(phone);

-- 6. Foreign key without NOT VALID
ALTER TABLE orders ADD CONSTRAINT fk_orders_user_new FOREIGN KEY (user_id) REFERENCES users(id);

-- 7. Column type change
ALTER TABLE users ALTER COLUMN status TYPE INTEGER USING status::integer;

-- 8. Destructive operations
ALTER TABLE users DROP COLUMN legacy_token;
DROP TABLE invoices;

-- 9. Rename
ALTER TABLE users RENAME COLUMN name TO full_name;

-- 10. Full table update/delete
DELETE FROM events;
UPDATE users SET status = 'inactive';

-- 11. Unbatched backfill
UPDATE users SET tier = 'standard' WHERE tier IS NULL;

COMMIT;
