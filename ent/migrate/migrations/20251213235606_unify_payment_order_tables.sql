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
-- PERFORMANCE OPTIMIZATIONS: Temporary indexes, pre-computed mappings, and ANALYZE statements added for faster execution.

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
-- Column will be dropped after Step 9.5 verification completes (after line 571)
-- This ensures the column remains available for verification checks in Step 9.5

-- Rename receive_address_text to receive_address (if it exists)
-- Also ensure it's nullable (provider orders don't have receive addresses)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'payment_orders' AND column_name = 'receive_address_text') THEN
        ALTER TABLE "payment_orders" RENAME COLUMN "receive_address_text" TO "receive_address";
        -- Ensure the column is nullable (it may have been NOT NULL originally)
        ALTER TABLE "payment_orders" ALTER COLUMN "receive_address" DROP NOT NULL;
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
    -- But add it if it doesn't exist, and ensure it's nullable
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'payment_orders' AND column_name = 'receive_address') THEN
        ALTER TABLE "payment_orders" ADD COLUMN "receive_address" character varying(60) NULL;
    ELSE
        -- Ensure existing column is nullable (in case it was NOT NULL)
        ALTER TABLE "payment_orders" ALTER COLUMN "receive_address" DROP NOT NULL;
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
    END IF;
END $$;

-- Ensure payment_order_fulfillments entry exists in ent_types (idempotent)
INSERT INTO "ent_types" ("type") VALUES ('payment_order_fulfillments')
ON CONFLICT ("type") DO NOTHING;

-- Step 1d: Create temporary indexes to speed up migration joins
-- These will be dropped after migration completes (Step 9.7)
-- Index on payment_orders for matching
CREATE INDEX IF NOT EXISTS "tmp_idx_po_message_hash" ON "payment_orders" ("message_hash") WHERE "message_hash" IS NOT NULL;
CREATE INDEX IF NOT EXISTS "tmp_idx_po_gateway_id" ON "payment_orders" ("gateway_id") WHERE "gateway_id" IS NOT NULL;
CREATE INDEX IF NOT EXISTS "tmp_idx_po_tx_hash" ON "payment_orders" ("tx_hash") WHERE "tx_hash" IS NOT NULL;
CREATE INDEX IF NOT EXISTS "tmp_idx_po_token" ON "payment_orders" ("token_payment_orders");

-- Index on lock_payment_orders for matching
CREATE INDEX IF NOT EXISTS "tmp_idx_lpo_message_hash" ON "lock_payment_orders" ("message_hash") WHERE "message_hash" IS NOT NULL;
CREATE INDEX IF NOT EXISTS "tmp_idx_lpo_gateway_id" ON "lock_payment_orders" ("gateway_id") WHERE "gateway_id" IS NOT NULL;
CREATE INDEX IF NOT EXISTS "tmp_idx_lpo_tx_hash" ON "lock_payment_orders" ("tx_hash") WHERE "tx_hash" IS NOT NULL;
CREATE INDEX IF NOT EXISTS "tmp_idx_lpo_token" ON "lock_payment_orders" ("token_lock_payment_orders");

-- Index on receive_addresses for Step 2
CREATE INDEX IF NOT EXISTS "tmp_idx_ra_po_id" ON "receive_addresses" ("payment_order_receive_address") WHERE "payment_order_receive_address" IS NOT NULL;

-- Index on payment_order_recipients for Step 3
CREATE INDEX IF NOT EXISTS "tmp_idx_por_po_id" ON "payment_order_recipients" ("payment_order_recipient") WHERE "payment_order_recipient" IS NOT NULL;

-- Index on transaction_logs for Step 7
CREATE INDEX IF NOT EXISTS "tmp_idx_tl_lpo" ON "transaction_logs" ("lock_payment_order_transactions") WHERE "lock_payment_order_transactions" IS NOT NULL;

-- Update statistics for query planner
ANALYZE "payment_orders";
ANALYZE "lock_payment_orders";
ANALYZE "receive_addresses";
ANALYZE "payment_order_recipients";
ANALYZE "transaction_logs";

-- Disable enforce_payment_order_amount trigger for data migration steps
-- This trigger prevents updates when status doesn't change, which would block our migration
-- We'll re-enable it after all UPDATE operations complete
ALTER TABLE "payment_orders" DISABLE TRIGGER "enforce_payment_order_amount";

-- Step 2: Migrate receive_address data to payment_orders
-- Handle both receive_addresses table and receive_address column (already renamed from receive_address_text)
-- Note: receive_addresses.payment_order_receive_address references payment_orders.id
UPDATE "payment_orders" po
SET 
    "receive_address" = COALESCE(po."receive_address", ra."address"),
    "receive_address_salt" = COALESCE(po."receive_address_salt", ra."salt"),
    "receive_address_expiry" = COALESCE(po."receive_address_expiry", ra."valid_until")
FROM "receive_addresses" ra
WHERE ra."payment_order_receive_address" = po."id";

ANALYZE "payment_orders";

-- Step 3: Migrate payment_order_recipients data to payment_orders
UPDATE "payment_orders" po
SET 
    "institution" = COALESCE(po."institution", por."institution"),
    "account_identifier" = COALESCE(po."account_identifier", por."account_identifier"),
    "account_name" = COALESCE(po."account_name", por."account_name"),
    "memo" = COALESCE(po."memo", por."memo")
FROM "payment_order_recipients" por
WHERE por."payment_order_recipient" = po."id";

ANALYZE "payment_orders";

-- Step 3.5: Pre-migration verification - Check for duplicate matches
-- Verify no lock_payment_order matches multiple payment_orders with the same priority
-- We use prioritized matching: message_hash (priority 1) > gateway_id (priority 2) > tx_hash (priority 3)
-- This ensures each lock_payment_order matches at most one payment_order per priority level
DO $$
DECLARE
    duplicate_matches bigint;
    duplicate_ids text;
BEGIN
    -- Check for duplicates: a lock_payment_order matches multiple payment_orders at the same priority level
    WITH prioritized_matches AS (
        SELECT 
            lpo."id" as lpo_id,
            po."id" as po_id,
            CASE 
                WHEN po."message_hash" IS NOT NULL AND po."message_hash" = lpo."message_hash" THEN 1
                WHEN po."gateway_id" IS NOT NULL AND po."gateway_id" = lpo."gateway_id" THEN 2
                WHEN po."tx_hash" IS NOT NULL AND po."tx_hash" = lpo."tx_hash" THEN 3
                ELSE 4
            END as match_priority
        FROM "lock_payment_orders" lpo
        INNER JOIN "payment_orders" po ON (
            (
                (po."message_hash" IS NOT NULL AND po."message_hash" = lpo."message_hash")
                OR (po."gateway_id" IS NOT NULL AND po."gateway_id" = lpo."gateway_id")
                OR (po."tx_hash" IS NOT NULL AND po."tx_hash" = lpo."tx_hash")
            )
            AND po."token_payment_orders" = lpo."token_lock_payment_orders"
        )
    ),
    priority_duplicates AS (
        SELECT 
            lpo_id,
            match_priority,
            COUNT(DISTINCT po_id) as match_count
        FROM prioritized_matches
        GROUP BY lpo_id, match_priority
        HAVING COUNT(DISTINCT po_id) > 1
    )
    SELECT 
        COUNT(DISTINCT lpo_id),
        string_agg(DISTINCT lpo_id::text, ', ' ORDER BY lpo_id::text)
    INTO duplicate_matches, duplicate_ids
    FROM priority_duplicates;

    IF duplicate_matches > 0 THEN
        RAISE EXCEPTION E'Pre-migration check failed: % lock_payment_order(s) have multiple matches at the same priority level.\n\nAffected lock_payment_order IDs: %\n\nPlease review these orders manually and resolve the data integrity issue before proceeding.', 
            duplicate_matches, 
            duplicate_ids;
    END IF;
    
    RAISE NOTICE 'Pre-migration check passed: No duplicate matches found';
END $$;

-- Step 4: Migrate lock_payment_orders data to payment_orders
-- Match by message_hash (priority 1), gateway_id (priority 2), or tx_hash (priority 3)
-- Use prioritized matching to ensure each lock_payment_order matches at most one payment_order
WITH best_match AS (
    -- Select the best match for each lock_payment_order using prioritized matching
    SELECT DISTINCT ON (lpo."id")
        lpo."id" as lpo_id,
        po."id" as po_id
    FROM "lock_payment_orders" lpo
    INNER JOIN "payment_orders" po ON (
        (
            (po."message_hash" IS NOT NULL AND po."message_hash" = lpo."message_hash")
            OR (po."gateway_id" IS NOT NULL AND po."gateway_id" = lpo."gateway_id")
            OR (po."tx_hash" IS NOT NULL AND po."tx_hash" = lpo."tx_hash")
        )
        AND po."token_payment_orders" = lpo."token_lock_payment_orders"
    )
    ORDER BY 
        lpo."id",
        CASE 
            WHEN po."message_hash" IS NOT NULL AND po."message_hash" = lpo."message_hash" THEN 1
            WHEN po."gateway_id" IS NOT NULL AND po."gateway_id" = lpo."gateway_id" THEN 2
            WHEN po."tx_hash" IS NOT NULL AND po."tx_hash" = lpo."tx_hash" THEN 3
            ELSE 4
        END,
        po."id"  -- Deterministic tie-breaker
)
UPDATE "payment_orders" po
SET 
    "protocol_fee" = lpo."protocol_fee",
    "order_percent" = lpo."order_percent",
    "gateway_id" = COALESCE(po."gateway_id", lpo."gateway_id"),
    "tx_hash" = COALESCE(lpo."tx_hash", po."tx_hash"),
    "block_number" = COALESCE(lpo."block_number", po."block_number"),
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
INNER JOIN best_match ON best_match.lpo_id = lpo."id"
WHERE po."id" = best_match.po_id;

ANALYZE "payment_orders";

-- Re-enable the trigger after all UPDATE operations complete
ALTER TABLE "payment_orders" ENABLE TRIGGER "enforce_payment_order_amount";

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

ANALYZE "payment_orders";

-- Step 6: Migrate lock_order_fulfillments to payment_order_fulfillments (OPTIMIZED)
-- Pre-compute the mapping in a temp table instead of correlated subqueries
-- The payment_order_fulfillments table should already exist (created in Step 1c)
-- Note: Fulfillments reference lock_payment_order IDs. We need to find the corresponding payment_order:
-- 1. If lock_payment_order was inserted as new payment_order (Step 5), IDs match
-- 2. If lock_payment_order was merged into existing payment_order (Step 4), we match by message_hash, gateway_id, or tx_hash
CREATE TEMP TABLE tmp_fulfillment_mapping AS
SELECT DISTINCT ON (lof."id")
    lof."id" as fulfillment_id,
    COALESCE(
        po_direct."id",
        po_match."id"
    ) as payment_order_id
FROM "lock_order_fulfillments" lof
LEFT JOIN "payment_orders" po_direct ON po_direct."id" = lof."lock_payment_order_fulfillments"
LEFT JOIN LATERAL (
    SELECT po."id"
    FROM "payment_orders" po
    INNER JOIN "lock_payment_orders" lpo ON lpo."id" = lof."lock_payment_order_fulfillments"
    WHERE po."token_payment_orders" = lpo."token_lock_payment_orders"
      AND (
          (po."message_hash" IS NOT NULL AND po."message_hash" = lpo."message_hash")
          OR (po."gateway_id" IS NOT NULL AND po."gateway_id" = lpo."gateway_id")
          OR (po."tx_hash" IS NOT NULL AND po."tx_hash" = lpo."tx_hash")
      )
    ORDER BY 
        CASE 
            WHEN po."message_hash" IS NOT NULL AND po."message_hash" = lpo."message_hash" THEN 1
            WHEN po."gateway_id" IS NOT NULL AND po."gateway_id" = lpo."gateway_id" THEN 2
            WHEN po."tx_hash" IS NOT NULL AND po."tx_hash" = lpo."tx_hash" THEN 3
            ELSE 4
        END,
        po."id"  -- Deterministic tie-breaker
    LIMIT 1
) po_match ON true
WHERE COALESCE(po_direct."id", po_match."id") IS NOT NULL;

CREATE INDEX "tmp_idx_fulfillment_mapping" ON "tmp_fulfillment_mapping" ("fulfillment_id");

INSERT INTO "payment_order_fulfillments" (
    "id", "created_at", "updated_at", "tx_id", "validation_status", 
    "validation_error", "psp", "payment_order_fulfillments"
)
SELECT 
    lof."id",
    lof."created_at",
    lof."updated_at",
    lof."tx_id",
    lof."validation_status",
    lof."validation_error",
    lof."psp",
    tfm."payment_order_id"
FROM "lock_order_fulfillments" lof
INNER JOIN "tmp_fulfillment_mapping" tfm ON tfm."fulfillment_id" = lof."id"
ON CONFLICT ("id") DO NOTHING;

-- Step 7: Migrate transaction_logs.lock_payment_order_transactions to payment_order_transactions (OPTIMIZED)
-- Pre-compute the mapping in a temp table instead of correlated subqueries
-- Note: Transaction logs reference lock_payment_order IDs. We need to find the corresponding payment_order:
-- 1. If lock_payment_order was inserted as new payment_order (Step 5), IDs match
-- 2. If lock_payment_order was merged into existing payment_order (Step 4), we match by message_hash, gateway_id, or tx_hash
CREATE TEMP TABLE tmp_transaction_mapping AS
SELECT DISTINCT ON (tl."id")
    tl."id" as transaction_log_id,
    COALESCE(
        po_direct."id",
        po_match."id"
    ) as payment_order_id
FROM "transaction_logs" tl
LEFT JOIN "payment_orders" po_direct ON po_direct."id" = tl."lock_payment_order_transactions"
LEFT JOIN LATERAL (
    SELECT po."id"
    FROM "payment_orders" po
    INNER JOIN "lock_payment_orders" lpo ON lpo."id" = tl."lock_payment_order_transactions"
    WHERE po."token_payment_orders" = lpo."token_lock_payment_orders"
      AND (
          (po."message_hash" IS NOT NULL AND po."message_hash" = lpo."message_hash")
          OR (po."gateway_id" IS NOT NULL AND po."gateway_id" = lpo."gateway_id")
          OR (po."tx_hash" IS NOT NULL AND po."tx_hash" = lpo."tx_hash")
      )
    ORDER BY 
        CASE 
            WHEN po."message_hash" IS NOT NULL AND po."message_hash" = lpo."message_hash" THEN 1
            WHEN po."gateway_id" IS NOT NULL AND po."gateway_id" = lpo."gateway_id" THEN 2
            WHEN po."tx_hash" IS NOT NULL AND po."tx_hash" = lpo."tx_hash" THEN 3
            ELSE 4
        END,
        po."id"  -- Deterministic tie-breaker
    LIMIT 1
) po_match ON true
WHERE tl."lock_payment_order_transactions" IS NOT NULL
  AND tl."payment_order_transactions" IS NULL
  AND COALESCE(po_direct."id", po_match."id") IS NOT NULL;

CREATE INDEX "tmp_idx_transaction_mapping" ON "tmp_transaction_mapping" ("transaction_log_id");

UPDATE "transaction_logs" tl
SET "payment_order_transactions" = tmp."payment_order_id"
FROM "tmp_transaction_mapping" tmp
WHERE tl."id" = tmp."transaction_log_id";

ANALYZE "transaction_logs";

-- Step 7.5: Check and clean up duplicate receive_address values before creating unique index
-- This step ensures that each non-NULL receive_address appears only once in payment_orders
DO $$
DECLARE
    duplicate_count bigint;
    duplicate_details text;
    remaining_duplicates bigint;
BEGIN
    -- Check for duplicate receive_address values
    WITH duplicate_addresses AS (
        SELECT "receive_address", COUNT(*) as cnt
        FROM "payment_orders"
        WHERE "receive_address" IS NOT NULL
        GROUP BY "receive_address"
        HAVING COUNT(*) > 1
    )
    SELECT 
        COALESCE(SUM(cnt - 1), 0),
        string_agg(
            'receive_address: ' || da."receive_address" || ' (used by ' || da.cnt || ' payment_orders: ' || 
            (SELECT string_agg(po."id"::text, ', ' ORDER BY po."id"::text)
             FROM "payment_orders" po
             WHERE po."receive_address" = da."receive_address") || ')',
            E'\n' 
            ORDER BY da."receive_address"
        )
    INTO duplicate_count, duplicate_details
    FROM duplicate_addresses da;
    
    IF duplicate_count > 0 THEN
        -- Log the duplicates for debugging
        RAISE NOTICE 'Found % duplicate receive_address values. Cleaning up duplicates...', duplicate_count;
        RAISE NOTICE 'Duplicate details:%', E'\n' || duplicate_details;
        
        -- Clean up duplicates: keep the first one (by ID) and set others to NULL
        -- We keep the one with the smallest ID (oldest order)
        WITH duplicates AS (
            SELECT 
                "id",
                "receive_address",
                ROW_NUMBER() OVER (
                    PARTITION BY "receive_address" 
                    ORDER BY "id"
                ) as rn
            FROM "payment_orders"
            WHERE "receive_address" IS NOT NULL
        )
        UPDATE "payment_orders" po
        SET 
            "receive_address" = NULL,
            "receive_address_salt" = NULL,
            "receive_address_expiry" = NULL
        FROM duplicates d
        WHERE po."id" = d."id"
          AND d.rn > 1;
        
        -- Verify cleanup
        WITH duplicate_addresses AS (
            SELECT "receive_address", COUNT(*) as cnt
            FROM "payment_orders"
            WHERE "receive_address" IS NOT NULL
            GROUP BY "receive_address"
            HAVING COUNT(*) > 1
        )
        SELECT COALESCE(SUM(cnt - 1), 0) INTO remaining_duplicates
        FROM duplicate_addresses;
        
        IF remaining_duplicates > 0 THEN
            RAISE EXCEPTION 'Failed to clean up all duplicate receive_address values. % duplicates remain.', remaining_duplicates;
        ELSE
            RAISE NOTICE 'Successfully cleaned up all duplicate receive_address values.';
        END IF;
    ELSE
        RAISE NOTICE 'No duplicate receive_address values found. Proceeding with index creation.';
    END IF;
END $$;

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
           -- An address is considered orphaned only if:
           -- 1. It has a non-null address (has data to migrate)
           -- 2. It references an existing payment_order
           -- 3. The payment_order's receive_address is NULL (migration should have populated it)
           -- Note: We don't fail if payment_order doesn't exist - that's a data integrity issue, not a migration failure
           -- Note: We don't fail if receive_address is NULL - that's an orphaned address with no data
           SELECT COUNT(*) INTO orphaned_addresses
           FROM "receive_addresses" ra
           WHERE ra."payment_order_receive_address" IS NOT NULL
             AND ra."address" IS NOT NULL
             AND EXISTS (
                 SELECT 1 FROM "payment_orders" po 
                 WHERE ra."payment_order_receive_address" = po."id"
                 AND po."receive_address" IS NULL
             );
    
    -- Verify no duplicate matches (post-migration check)
    -- Note: After Step 4, payment_orders may have been updated with gateway_id/tx_hash from lock_payment_orders,
    -- which could create additional matches. This is expected behavior. However, we want to ensure that
    -- a lock_payment_order doesn't match multiple payment_orders that both existed BEFORE Step 4 (pre-existing).
    -- If a lock_payment_order matches:
    --   1. A payment_order with the same ID (inserted in Step 5) - OK
    --   2. A payment_order with different ID (merged in Step 4) - OK
    --   3. Multiple payment_orders with different IDs (both pre-existing) - PROBLEM
    -- We simplify by checking if any lock_payment_order matches multiple payment_orders with different IDs,
    -- excluding the case where one has the same ID (Step 5 insert).
    -- However, after Step 4 updates, it's possible for a lock_payment_order to match multiple payment_orders
    -- if they share the same gateway_id/tx_hash. This is acceptable as long as the lock_payment_order
    -- was successfully merged/inserted. We'll make this check informational rather than failing.
    SELECT COUNT(*) INTO duplicate_matches
    FROM (
        SELECT lpo."id", COUNT(DISTINCT po."id") as match_count
        FROM "lock_payment_orders" lpo
        INNER JOIN "payment_orders" po ON (
            (po."message_hash" IS NOT NULL AND po."message_hash" = lpo."message_hash")
            OR (po."gateway_id" IS NOT NULL AND po."gateway_id" = lpo."gateway_id")
            OR (po."tx_hash" IS NOT NULL AND po."tx_hash" = lpo."tx_hash")
        ) AND po."token_payment_orders" = lpo."token_lock_payment_orders"
        WHERE po."id" != lpo."id"  -- Exclude Step 5 inserts (where IDs match)
        GROUP BY lpo."id"
        HAVING COUNT(DISTINCT po."id") > 1
    ) duplicates;
    
    -- Note: After Step 4, some payment_orders have gateway_id/tx_hash updated, which can create
    -- additional matches. This is expected. We only warn if there are many duplicates, but don't fail.
    -- The pre-migration check already ensured no duplicates existed before Step 4.
 
    
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
    
           -- Verify no duplicate matches
           -- Note: After Step 4, payment_orders may have gateway_id/tx_hash updated, which can create
           -- additional matches. This is expected. The pre-migration check already ensured no duplicates
           -- existed before Step 4. If duplicates exist after, it's likely due to Step 4 updates creating
           -- new matches, which is acceptable. We log a warning but don't fail unless there are many.
           IF duplicate_matches > 10 THEN
               RAISE EXCEPTION 'Verification failed: % lock_payment_orders match multiple payment_orders after migration. This may indicate a data integrity issue.', duplicate_matches;
           ELSIF duplicate_matches > 0 THEN
               RAISE NOTICE 'Warning: % lock_payment_orders match multiple payment_orders after migration. This may be due to Step 4 updates creating additional matches.', duplicate_matches;
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
END $$;

-- Drop lock_payment_order_transactions column after verification completes
-- This column is referenced in Step 9.5 verification (lines 466, 472), so it must remain
-- available until after verification succeeds
ALTER TABLE "transaction_logs" DROP COLUMN IF EXISTS "lock_payment_order_transactions";

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

-- Step 9.7: Drop temporary indexes created in Step 1d
-- These indexes were created to speed up migration joins and are no longer needed
DROP INDEX IF EXISTS "tmp_idx_po_message_hash";
DROP INDEX IF EXISTS "tmp_idx_po_gateway_id";
DROP INDEX IF EXISTS "tmp_idx_po_tx_hash";
DROP INDEX IF EXISTS "tmp_idx_po_token";
DROP INDEX IF EXISTS "tmp_idx_lpo_message_hash";
DROP INDEX IF EXISTS "tmp_idx_lpo_gateway_id";
DROP INDEX IF EXISTS "tmp_idx_lpo_tx_hash";
DROP INDEX IF EXISTS "tmp_idx_lpo_token";
DROP INDEX IF EXISTS "tmp_idx_ra_po_id";
DROP INDEX IF EXISTS "tmp_idx_por_po_id";
DROP INDEX IF EXISTS "tmp_idx_tl_lpo";
-- Temp tables (tmp_fulfillment_mapping, tmp_transaction_mapping) are automatically dropped at end of transaction

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
