-- Modify "provider_order_tokens" table
ALTER TABLE "provider_order_tokens" ADD COLUMN "rate_slippage" double precision NOT NULL DEFAULT 0;
