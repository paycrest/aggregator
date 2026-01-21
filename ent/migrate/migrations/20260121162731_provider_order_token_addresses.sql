-- Rename address column to settlement_address
ALTER TABLE "provider_order_tokens" RENAME COLUMN "address" TO "settlement_address";

-- Add payout_address column
ALTER TABLE "provider_order_tokens" ADD COLUMN "payout_address" character varying NULL;
