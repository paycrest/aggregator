-- Modify "payment_orders" table
ALTER TABLE "payment_orders" ADD COLUMN "fallback_tried_at" timestamptz NULL;
