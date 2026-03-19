-- Add provider_fee column to payment_orders for tracking provider's portion of transaction fee
ALTER TABLE "payment_orders" ADD COLUMN "provider_fee" numeric NOT NULL DEFAULT 0;
