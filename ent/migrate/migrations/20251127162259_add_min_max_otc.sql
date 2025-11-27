-- Modify "lock_payment_orders" table
ALTER TABLE "lock_payment_orders" ADD COLUMN "order_type" character varying NOT NULL DEFAULT 'regular';
-- Modify "payment_orders" table
ALTER TABLE "payment_orders" ADD COLUMN "order_type" character varying NOT NULL DEFAULT 'regular';
-- Modify "provider_order_tokens" table
ALTER TABLE "provider_order_tokens" ADD COLUMN "max_order_amount_otc" double precision NOT NULL DEFAULT 0, ADD COLUMN "min_order_amount_otc" double precision NOT NULL DEFAULT 0;
