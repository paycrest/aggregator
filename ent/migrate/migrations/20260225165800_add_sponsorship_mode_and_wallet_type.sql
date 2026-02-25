-- Modify "networks" table
ALTER TABLE "networks" ADD COLUMN "sponsorship_mode" character varying NOT NULL DEFAULT 'thirdweb';
-- Modify "payment_orders" table
ALTER TABLE "payment_orders" ADD COLUMN "wallet_type" character varying NOT NULL DEFAULT 'smart_wallet';
