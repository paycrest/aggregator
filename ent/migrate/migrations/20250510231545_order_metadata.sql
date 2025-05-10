-- Modify "linked_addresses" table
ALTER TABLE "linked_addresses" ADD COLUMN "metadata" jsonb NULL;
-- Modify "lock_payment_orders" table
ALTER TABLE "lock_payment_orders" ADD COLUMN "metadata" jsonb NULL;
-- Modify "payment_order_recipients" table
ALTER TABLE "payment_order_recipients" ADD COLUMN "metadata" jsonb NULL;
-- Modify "provider_order_tokens" table
ALTER TABLE "provider_order_tokens" ALTER COLUMN "rate_slippage" DROP DEFAULT;
