-- Migration: Unify PaymentOrder and LockPaymentOrder tables
-- This migration merges lock_payment_orders, payment_order_recipients, and receive_addresses into payment_orders
-- Based on Atlas-generated schema changes with data migration steps added
--
-- ⚠️  ROLLBACK WARNING:
-- This migration is NOT easily reversible. It drops tables (lock_payment_orders, payment_order_recipients, receive_addresses).
-- Before running this migration:
-- 1. Ensure you have a full database backup
-- 2. Test in staging environment first
-- 3. Verify all data migrations completed successfully
-- 
-- Manual rollback would require:
-- - Restoring from backup, OR
-- - Recreating dropped tables and re-separating data (very complex)
-- 
-- This migration includes verification steps that will prevent table drops if data migration fails.

-- Step 0: Schema changes (matching Atlas migration - must happen before data migration)
-- Drop default from sender_order_tokens.max_fee_cap
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'sender_order_tokens' AND column_name = 'max_fee_cap') THEN
        ALTER TABLE "sender_order_tokens" ALTER COLUMN "max_fee_cap" DROP DEFAULT;
    END IF;
END $$;

-- Drop lock_payment_order_transactions from transaction_logs (migrate data first in Step 7)
-- We'll drop the column after migrating data

-- Rename receive_address_text to receive_address (if it exists)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'payment_orders' AND column_name = 'receive_address_text') THEN
        ALTER TABLE "payment_orders" RENAME COLUMN "receive_address_text" TO "receive_address";
    END IF;
END $$;

-- Drop linked_address_payment_orders column (no longer needed)
ALTER TABLE "payment_orders" DROP COLUMN IF EXISTS "linked_address_payment_orders";

-- Step 1: Add new columns to payment_orders if they don't exist
-- Note: Some columns may already exist, so we use IF NOT EXISTS pattern via DO block

DO $$
BEGIN
    -- Add protocol_fee if it doesn't exist (it was removed in a previous migration)
    -- Atlas shows NOT NULL without default, but we add default for data migration safety
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'protocol_fee') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "protocol_fee" double precision NOT NULL DEFAULT 0;
    END IF;

    -- Add order_percent if it doesn't exist
    -- Atlas shows NOT NULL without default, but we add default for data migration safety
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'order_percent') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "order_percent" double precision NOT NULL DEFAULT 0;
    END IF;

    -- receive_address should already exist (renamed from receive_address_text in Step 0)
    -- But add it if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'receive_address') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "receive_address" character varying(60) NULL;
    END IF;

    -- Add receive_address_salt if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'receive_address_salt') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "receive_address_salt" bytea NULL;
    END IF;

    -- Add receive_address_expiry if it doesn't exist
    -- Note: Schema shows it as required, but we'll add as nullable initially for data migration
    -- Provider orders don't have receive addresses, so we'll handle this after data migration
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'receive_address_expiry') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "receive_address_expiry" timestamptz NULL;
    END IF;

    -- Add institution if it doesn't exist
    -- Note: Schema shows it as required, but we'll add as nullable initially for data migration
    -- Add institution if it doesn't exist
    -- Note: Added as nullable initially for data migration, will be set to NOT NULL in Step 9.6
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'institution') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "institution" character varying(255) NULL;
    END IF;

    -- Add account_identifier if it doesn't exist
    -- Note: Schema shows it as required, but we'll add as nullable initially for data migration
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'account_identifier') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "account_identifier" character varying(255) NULL;
    END IF;

    -- Add account_name if it doesn't exist
    -- Note: Schema shows it as required, but we'll add as nullable initially for data migration
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'account_name') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "account_name" character varying(255) NULL;
    END IF;

    -- Add memo if it doesn't exist (may already exist)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'memo') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "memo" character varying(255) NULL;
    END IF;

    -- Add metadata if it doesn't exist (may already exist)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'metadata') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "metadata" jsonb NULL;
    END IF;

    -- Add sender if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'sender') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "sender" character varying(255) NULL;
    END IF;

    -- Add cancellation_count if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'cancellation_count') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "cancellation_count" bigint NULL DEFAULT 0;
    END IF;

    -- Add cancellation_reasons if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'cancellation_reasons') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "cancellation_reasons" jsonb NULL;
    END IF;

    -- Add provider_profile_assigned_orders if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'provider_profile_assigned_orders') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "provider_profile_assigned_orders" character varying NULL;
    END IF;

    -- Add provision_bucket_payment_orders if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'provision_bucket_payment_orders') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "provision_bucket_payment_orders" bigint NULL;
    END IF;

    -- Add order_type if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'order_type') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "order_type" character varying NOT NULL DEFAULT 'regular';
    END IF;
END $$;

-- Step 1b: Add foreign key constraints
DO $$
BEGIN
    -- Add foreign key for provider_profile_assigned_orders if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints 
                   WHERE constraint_name = 'payment_orders_provider_profiles_assigned_orders') THEN
        ALTER TABLE "payment_orders" ADD CONSTRAINT "payment_orders_provider_profiles_assigned_orders" 
            FOREIGN KEY ("provider_profile_assigned_orders") REFERENCES "provider_profiles" ("id") 
            ON UPDATE NO ACTION ON DELETE CASCADE;
    END IF;

    -- Add foreign key for provision_bucket_payment_orders if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints 
                   WHERE constraint_name = 'payment_orders_provision_buckets_payment_orders') THEN
        ALTER TABLE "payment_orders" ADD CONSTRAINT "payment_orders_provision_buckets_payment_orders" 
            FOREIGN KEY ("provision_bucket_payment_orders") REFERENCES "provision_buckets" ("id") 
            ON UPDATE NO ACTION ON DELETE SET NULL;
    END IF;
END $$;

-- Step 1c: Create payment_order_fulfillments table if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'payment_order_fulfillments') THEN
        CREATE TABLE "payment_order_fulfillments" (
          "id" uuid NOT NULL,
          "created_at" timestamptz NOT NULL,
          "updated_at" timestamptz NOT NULL,
          "tx_id" character varying NULL,
          "psp" character varying NULL,
          "validation_status" character varying NOT NULL DEFAULT 'pending',
          "validation_error" character varying NULL,
          "payment_order_fulfillments" uuid NOT NULL,
          PRIMARY KEY ("id"),
          CONSTRAINT "payment_order_fulfillments_payment_orders_fulfillments" FOREIGN KEY ("payment_order_fulfillments") REFERENCES "payment_orders" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
        );
        INSERT INTO "ent_types" ("type") VALUES ('payment_order_fulfillments');
    END IF;
END $$;

-- Step 2: Migrate receive_address data to payment_orders
-- Handle both receive_addresses table and receive_address column (already renamed from receive_address_text)
UPDATE "payment_orders" po
SET 
    "receive_address" = COALESCE(po."receive_address", ra."address"),
    "receive_address_salt" = COALESCE(po."receive_address_salt", ra."salt"),
    "receive_address_expiry" = COALESCE(po."receive_address_expiry", ra."valid_until")
FROM "receive_addresses" ra
WHERE po."receive_address_payment_orders" = ra."id"
  AND po."receive_address" IS NULL;

-- Step 3: Migrate payment_order_recipients data to payment_orders
UPDATE "payment_orders" po
SET 
    "institution" = por."institution",
    "account_identifier" = por."account_identifier",
    "account_name" = por."account_name",
    "memo" = COALESCE(po."memo", por."memo")
FROM "payment_order_recipients" por
WHERE por."payment_order_recipient" = po."id"
  AND po."institution" IS NULL;

-- Step 3.5: Pre-migration verification - Check for duplicate matches
-- Verify no lock_payment_order matches multiple payment_orders (would cause UPDATE to fail)
DO $$
DECLARE
    duplicate_matches bigint;
BEGIN
    SELECT COUNT(*) INTO duplicate_matches
    FROM (
        SELECT lpo."id", COUNT(DISTINCT po."id") as match_count
        FROM "lock_payment_orders" lpo
        LEFT JOIN "payment_orders" po ON (
            (po."message_hash" IS NOT NULL AND po."message_hash" = lpo."message_hash")
            OR (po."gateway_id" IS NOT NULL AND po."gateway_id" = lpo."gateway_id")
            OR (po."tx_hash" IS NOT NULL AND po."tx_hash" = lpo."tx_hash")
        ) AND po."token_payment_orders" = lpo."token_lock_payment_orders"
        GROUP BY lpo."id"
        HAVING COUNT(DISTINCT po."id") > 1
    ) duplicates;

    IF duplicate_matches > 0 THEN
        RAISE EXCEPTION 'Pre-migration check failed: % lock_payment_orders match multiple payment_orders. Review matching logic.', duplicate_matches;
    END IF;
    
    RAISE NOTICE 'Pre-migration check passed: No duplicate matches found';
END $$;

-- Step 4: Migrate lock_payment_orders data to payment_orders
-- Match by message_hash, gateway_id, or tx_hash
UPDATE "payment_orders" po
SET 
    "protocol_fee" = lpo."protocol_fee",
    "order_percent" = lpo."order_percent",
    "gateway_id" = COALESCE(po."gateway_id", lpo."gateway_id"),
    "tx_hash" = COALESCE(po."tx_hash", lpo."tx_hash"),
    "block_number" = COALESCE(po."block_number", lpo."block_number"),
    "institution" = COALESCE(po."institution", lpo."institution"),
    "account_identifier" = COALESCE(po."account_identifier", lpo."account_identifier"),
    "account_name" = COALESCE(po."account_name", lpo."account_name"),
    "memo" = COALESCE(po."memo", lpo."memo"),
    "cancellation_count" = lpo."cancellation_count",
    "cancellation_reasons" = lpo."cancellation_reasons",
    "order_type" = COALESCE(po."order_type", lpo."order_type"),
    "provider_profile_assigned_orders" = COALESCE(po."provider_profile_assigned_orders", lpo."provider_profile_assigned_orders"),
    "provision_bucket_payment_orders" = COALESCE(po."provision_bucket_payment_orders", lpo."provision_bucket_lock_payment_orders"),
    "status" = CASE 
        WHEN po."status" = 'initiated' AND lpo."status" IN ('pending', 'processing', 'fulfilled', 'validated', 'settled', 'refunded', 'cancelled') 
        THEN lpo."status"
        ELSE po."status"
    END,
    "updated_at" = GREATEST(po."updated_at", lpo."updated_at")
FROM "lock_payment_orders" lpo
WHERE (
    (po."message_hash" IS NOT NULL AND po."message_hash" = lpo."message_hash")
    OR (po."gateway_id" IS NOT NULL AND po."gateway_id" = lpo."gateway_id")
    OR (po."tx_hash" IS NOT NULL AND po."tx_hash" = lpo."tx_hash")
)
AND po."token_payment_orders" = lpo."token_lock_payment_orders";

-- Step 5: Insert lock_payment_orders that don't have matching payment_orders
-- These are provider orders that were never linked to a sender order
INSERT INTO "payment_orders" (
    "id",
    "created_at",
    "updated_at",
    "amount",
    "rate",
    "amount_in_usd",
    "amount_paid",
    "amount_returned",
    "percent_settled",
    "sender_fee",
    "network_fee",
    "protocol_fee",
    "order_percent",
    "fee_percent",
    "tx_hash",
    "block_number",
    "message_hash",
    "gateway_id",
    "from_address",
    "return_address",
    "receive_address",
    "receive_address_salt",
    "receive_address_expiry",
    "fee_address",
    "institution",
    "account_identifier",
    "account_name",
    "memo",
    "metadata",
    "sender",
    "reference",
    "cancellation_count",
    "cancellation_reasons",
    "status",
    "order_type",
    "token_payment_orders",
    "provider_profile_assigned_orders",
    "provision_bucket_payment_orders"
)
SELECT 
    lpo."id",
    lpo."created_at",
    lpo."updated_at",
    lpo."amount",
    lpo."rate",
    COALESCE(lpo."amount_in_usd", 0),
    0, -- amount_paid
    0, -- amount_returned
    0, -- percent_settled
    0, -- sender_fee
    0, -- network_fee
    lpo."protocol_fee",
    lpo."order_percent",
    0, -- fee_percent
    lpo."tx_hash",
    lpo."block_number",
    lpo."message_hash",
    lpo."gateway_id",
    NULL, -- from_address
    NULL, -- return_address
    NULL, -- receive_address (provider orders don't have receive addresses)
    NULL, -- receive_address_salt
    NULL, -- receive_address_expiry
    NULL, -- fee_address
    lpo."institution",
    lpo."account_identifier",
    lpo."account_name",
    lpo."memo",
    COALESCE(lpo."metadata", '{}'::jsonb), -- metadata
    NULL, -- sender
    NULL, -- reference
    lpo."cancellation_count",
    lpo."cancellation_reasons",
    lpo."status",
    lpo."order_type",
    lpo."token_lock_payment_orders",
    lpo."provider_profile_assigned_orders",
    lpo."provision_bucket_lock_payment_orders"
FROM "lock_payment_orders" lpo
WHERE NOT EXISTS (
    SELECT 1 FROM "payment_orders" po
    WHERE (
        (po."message_hash" IS NOT NULL AND po."message_hash" = lpo."message_hash")
        OR (po."gateway_id" IS NOT NULL AND po."gateway_id" = lpo."gateway_id")
        OR (po."tx_hash" IS NOT NULL AND po."tx_hash" = lpo."tx_hash")
    )
    AND po."token_payment_orders" = lpo."token_lock_payment_orders"
);

-- Step 6: Migrate lock_order_fulfillments to payment_order_fulfillments
-- The payment_order_fulfillments table should already exist (created in Step 1c)
INSERT INTO "payment_order_fulfillments" (
    "id",
    "created_at",
    "updated_at",
    "tx_id",
    "validation_status",
    "validation_error",
    "psp",
    "payment_order_fulfillments"
)
SELECT 
    lof."id",
    lof."created_at",
    lof."updated_at",
    lof."tx_id",
    lof."validation_status",
    lof."validation_error",
    lof."psp",
    lof."lock_payment_order_fulfillments"
FROM "lock_order_fulfillments" lof
WHERE EXISTS (
    SELECT 1 FROM "payment_orders" po
    WHERE po."id" = lof."lock_payment_order_fulfillments"
)
ON CONFLICT ("id") DO NOTHING;

-- Step 7: Migrate transaction_logs.lock_payment_order_transactions to payment_order_transactions
UPDATE "transaction_logs" tl
SET "payment_order_transactions" = tl."lock_payment_order_transactions"
WHERE tl."lock_payment_order_transactions" IS NOT NULL
  AND tl."payment_order_transactions" IS NULL
  AND EXISTS (
      SELECT 1 FROM "payment_orders" po
      WHERE po."id" = tl."lock_payment_order_transactions"
  );

-- Now drop the lock_payment_order_transactions column
ALTER TABLE "transaction_logs" DROP COLUMN IF EXISTS "lock_payment_order_transactions";

-- Step 8: Add unique constraints and indexes (matching Atlas migration)
-- Add unique constraint on receive_address (matching Atlas index name)
CREATE UNIQUE INDEX IF NOT EXISTS "payment_orders_receive_address_key" ON "payment_orders" ("receive_address") WHERE "receive_address" IS NOT NULL;

-- Add composite unique index (matching Atlas index name)
CREATE UNIQUE INDEX IF NOT EXISTS "paymentorder_gateway_id_rate_t_57e75f781063c0a1f3a65de50acf4d66" 
    ON "payment_orders" ("gateway_id", "rate", "tx_hash", "block_number", "institution", "account_identifier", "account_name", "memo", "token_payment_orders")
    WHERE "gateway_id" IS NOT NULL;

-- Step 9: Update foreign key constraints
-- Drop old foreign keys from lock_order_fulfillments (if they exist)
-- Note: We drop the table in Step 10, so this is mainly for cleanup
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.table_constraints 
               WHERE constraint_name = 'lock_order_fulfillments_lock_payment_orders_fulfillments') THEN
        ALTER TABLE "lock_order_fulfillments" DROP CONSTRAINT "lock_order_fulfillments_lock_payment_orders_fulfillments";
    END IF;
END $$;

-- Step 9.5: Verification - Check data integrity before dropping tables
-- This step will raise an error if verification fails, preventing table drops
DO $$
DECLARE
    payment_order_count bigint;
    lock_payment_order_count bigint;
    fulfillment_count bigint;
    lock_fulfillment_count bigint;
    recipient_count bigint;
    receive_address_count bigint;
    migrated_fulfillment_count bigint;
    migrated_transaction_count bigint;
    expected_transaction_count bigint;
    orphaned_recipients bigint;
    orphaned_addresses bigint;
    duplicate_matches bigint;
    mismatched_tokens bigint;
BEGIN
    -- Count records in each table
    SELECT COUNT(*) INTO payment_order_count FROM "payment_orders";
    SELECT COUNT(*) INTO lock_payment_order_count FROM "lock_payment_orders";
    SELECT COUNT(*) INTO fulfillment_count FROM "payment_order_fulfillments";
    SELECT COUNT(*) INTO lock_fulfillment_count FROM "lock_order_fulfillments";
    SELECT COUNT(*) INTO recipient_count FROM "payment_order_recipients";
    SELECT COUNT(*) INTO receive_address_count FROM "receive_addresses";
    
    -- Count migrated fulfillments
    SELECT COUNT(*) INTO migrated_fulfillment_count
    FROM "payment_order_fulfillments" pof
    WHERE EXISTS (
        SELECT 1 FROM "lock_order_fulfillments" lof
        WHERE lof."id" = pof."id"
    );
    
    -- Count transaction logs that should have been migrated
    SELECT COUNT(*) INTO expected_transaction_count
    FROM "transaction_logs"
    WHERE "lock_payment_order_transactions" IS NOT NULL;
    
    -- Count migrated transaction logs
    SELECT COUNT(*) INTO migrated_transaction_count
    FROM "transaction_logs"
    WHERE "payment_order_transactions" IS NOT NULL
      AND "lock_payment_order_transactions" IS NOT NULL;
    
    -- Check for orphaned recipients (recipients that weren't migrated)
    SELECT COUNT(*) INTO orphaned_recipients
    FROM "payment_order_recipients" por
    WHERE NOT EXISTS (
        SELECT 1 FROM "payment_orders" po 
        WHERE po."id" = por."payment_order_recipient" 
        AND po."institution" IS NOT NULL
    );
    
    -- Check for orphaned receive addresses (addresses that weren't migrated)
    SELECT COUNT(*) INTO orphaned_addresses
    FROM "receive_addresses" ra
    WHERE NOT EXISTS (
        SELECT 1 FROM "payment_orders" po 
        WHERE po."receive_address_payment_orders" = ra."id"
        AND po."receive_address" IS NOT NULL
    );
    
    -- Verify no duplicate matches (post-migration check)
    SELECT COUNT(*) INTO duplicate_matches
    FROM (
        SELECT lpo."id", COUNT(DISTINCT po."id") as match_count
        FROM "lock_payment_orders" lpo
        LEFT JOIN "payment_orders" po ON (
            (po."message_hash" IS NOT NULL AND po."message_hash" = lpo."message_hash")
            OR (po."gateway_id" IS NOT NULL AND po."gateway_id" = lpo."gateway_id")
            OR (po."tx_hash" IS NOT NULL AND po."tx_hash" = lpo."tx_hash")
        ) AND po."token_payment_orders" = lpo."token_lock_payment_orders"
        GROUP BY lpo."id"
        HAVING COUNT(DISTINCT po."id") > 1
    ) duplicates;
    
    -- Verify matched records have consistent tokens
    SELECT COUNT(*) INTO mismatched_tokens
    FROM "lock_payment_orders" lpo
    INNER JOIN "payment_orders" po ON (
        (po."message_hash" IS NOT NULL AND po."message_hash" = lpo."message_hash")
        OR (po."gateway_id" IS NOT NULL AND po."gateway_id" = lpo."gateway_id")
        OR (po."tx_hash" IS NOT NULL AND po."tx_hash" = lpo."tx_hash")
    )
    WHERE po."token_payment_orders" != lpo."token_lock_payment_orders";
    
    -- Verify all fulfillments were migrated
    IF lock_fulfillment_count > 0 AND migrated_fulfillment_count != lock_fulfillment_count THEN
        RAISE EXCEPTION 'Verification failed: Not all fulfillments migrated. Expected %, migrated %', 
            lock_fulfillment_count, migrated_fulfillment_count;
    END IF;
    
    -- Verify all transaction logs were migrated
    IF expected_transaction_count > 0 AND migrated_transaction_count != expected_transaction_count THEN
        RAISE EXCEPTION 'Verification failed: Not all transaction logs migrated. Expected %, migrated %', 
            expected_transaction_count, migrated_transaction_count;
    END IF;
    
    -- Verify no orphaned recipients
    IF orphaned_recipients > 0 THEN
        RAISE EXCEPTION 'Verification failed: % recipient records not migrated to payment_orders', orphaned_recipients;
    END IF;
    
    -- Verify no orphaned receive addresses
    IF orphaned_addresses > 0 THEN
        RAISE EXCEPTION 'Verification failed: % receive addresses not migrated to payment_orders', orphaned_addresses;
    END IF;
    
    -- Verify no duplicate matches (should be 0 since we checked before migration)
    IF duplicate_matches > 0 THEN
        RAISE EXCEPTION 'Verification failed: % lock_payment_orders match multiple payment_orders after migration', duplicate_matches;
    END IF;
    
    -- Verify matched records have consistent tokens
    IF mismatched_tokens > 0 THEN
        RAISE EXCEPTION 'Verification failed: % matched records have mismatched tokens', mismatched_tokens;
    END IF;
    
    -- Verify payment orders count is reasonable (should be >= lock_payment_orders since we merge)
    -- Note: payment_order_count should be >= lock_payment_order_count because we merge data
    -- But it could be less if some lock_payment_orders matched existing payment_orders
    -- So we just check that payment_orders exist
    IF payment_order_count = 0 THEN
        RAISE EXCEPTION 'Verification failed: No payment orders found after migration';
    END IF;
    
    -- Log verification results (these will appear in migration logs)
    RAISE NOTICE 'Verification results:';
    RAISE NOTICE '  payment_orders: %', payment_order_count;
    RAISE NOTICE '  lock_payment_orders: %', lock_payment_order_count;
    RAISE NOTICE '  payment_order_fulfillments: %', fulfillment_count;
    RAISE NOTICE '  lock_order_fulfillments: %', lock_fulfillment_count;
    RAISE NOTICE '  payment_order_recipients: %', recipient_count;
    RAISE NOTICE '  receive_addresses: %', receive_address_count;
    RAISE NOTICE '  migrated fulfillments: %', migrated_fulfillment_count;
    RAISE NOTICE '  expected transaction logs: %', expected_transaction_count;
    RAISE NOTICE '  migrated transaction logs: %', migrated_transaction_count;
    RAISE NOTICE '  orphaned recipients: %', orphaned_recipients;
    RAISE NOTICE '  orphaned receive addresses: %', orphaned_addresses;
    RAISE NOTICE '  duplicate matches: %', duplicate_matches;
    RAISE NOTICE '  mismatched tokens: %', mismatched_tokens;
END $$;

-- Step 9.6: Set recipient fields to NOT NULL after data migration
-- First verify all records have these fields populated
DO $$
DECLARE
    missing_institution bigint;
    missing_account_identifier bigint;
    missing_account_name bigint;
BEGIN
    -- Check for records missing institution
    SELECT COUNT(*) INTO missing_institution
    FROM "payment_orders"
    WHERE "institution" IS NULL;
    
    -- Check for records missing account_identifier
    SELECT COUNT(*) INTO missing_account_identifier
    FROM "payment_orders"
    WHERE "account_identifier" IS NULL;
    
    -- Check for records missing account_name
    SELECT COUNT(*) INTO missing_account_name
    FROM "payment_orders"
    WHERE "account_name" IS NULL;
    
    -- Raise exception if any records are missing required fields
    IF missing_institution > 0 THEN
        RAISE EXCEPTION 'Cannot set institution to NOT NULL: % payment orders have NULL institution', missing_institution;
    END IF;
    
    IF missing_account_identifier > 0 THEN
        RAISE EXCEPTION 'Cannot set account_identifier to NOT NULL: % payment orders have NULL account_identifier', missing_account_identifier;
    END IF;
    
    IF missing_account_name > 0 THEN
        RAISE EXCEPTION 'Cannot set account_name to NOT NULL: % payment orders have NULL account_name', missing_account_name;
    END IF;
    
    RAISE NOTICE 'All recipient fields are populated. Setting to NOT NULL.';
END $$;

-- Now set the columns to NOT NULL
ALTER TABLE "payment_orders" ALTER COLUMN "institution" SET NOT NULL;
ALTER TABLE "payment_orders" ALTER COLUMN "account_identifier" SET NOT NULL;
ALTER TABLE "payment_orders" ALTER COLUMN "account_name" SET NOT NULL;

-- Step 10: Drop old tables (in reverse dependency order)
-- Drop fulfillments first
DROP TABLE IF EXISTS "lock_order_fulfillments" CASCADE;

-- Drop lock_payment_orders
DROP TABLE IF EXISTS "lock_payment_orders" CASCADE;

-- Drop payment_order_recipients
DROP TABLE IF EXISTS "payment_order_recipients" CASCADE;

-- Drop receive_addresses (if not already dropped)
DROP TABLE IF EXISTS "receive_addresses" CASCADE;

-- Step 11: Clean up old foreign key columns and old column names that are no longer needed
ALTER TABLE "payment_orders" DROP COLUMN IF EXISTS "receive_address_payment_orders";
-- linked_address_payment_orders was already dropped in Step 0

-- Step 12: Update ent_types to remove old table types
DELETE FROM "ent_types" WHERE "type" IN ('lock_payment_orders', 'lock_order_fulfillments', 'payment_order_recipients', 'receive_addresses');
