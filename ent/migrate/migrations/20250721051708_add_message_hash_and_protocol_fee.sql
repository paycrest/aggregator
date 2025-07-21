-- Modify "lock_payment_orders" table
ALTER TABLE "lock_payment_orders" ADD COLUMN "protocol_fee" double precision NOT NULL DEFAULT 0, ADD COLUMN "message_hash" character varying NULL;
-- Modify "payment_orders" table
ALTER TABLE "payment_orders" DROP COLUMN "protocol_fee";
