-- Modify "provider_order_tokens" table
ALTER TABLE "provider_order_tokens" ALTER COLUMN "max_order_amount_otc" DROP DEFAULT, ALTER COLUMN "min_order_amount_otc" DROP DEFAULT;
-- Modify "sender_order_tokens" table
ALTER TABLE "sender_order_tokens" ADD COLUMN "max_fee_cap" double precision NOT NULL DEFAULT 0;
