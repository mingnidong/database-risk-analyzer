-- Safe migration patterns for PostgreSQL
-- Demonstrates expand/contract and low-lock DDL

-- Step 1: Add nullable column (no NOT NULL yet)
ALTER TABLE users ADD COLUMN phone VARCHAR(20);

-- Step 2: Create index concurrently (must run outside transaction)
-- migrate-risk: run separately, not inside BEGIN/COMMIT
CREATE INDEX CONCURRENTLY idx_users_phone ON users(phone);

-- Step 3: Add foreign key with NOT VALID to avoid immediate validation
ALTER TABLE orders
    ADD CONSTRAINT fk_orders_user_safe
    FOREIGN KEY (user_id) REFERENCES users(id) NOT VALID;

-- Step 4: Validate constraint during low-traffic window
ALTER TABLE orders VALIDATE CONSTRAINT fk_orders_user_safe;

-- Step 5: Batched backfill (run in application or script)
-- BATCH: UPDATE users SET phone = 'unknown' WHERE id BETWEEN 1 AND 10000 AND phone IS NULL;
-- BATCH: sleep 100ms between batches; track progress in migration_log table

-- Step 6: After backfill complete, add NOT NULL in separate migration
-- ALTER TABLE users ALTER COLUMN phone SET NOT NULL;
