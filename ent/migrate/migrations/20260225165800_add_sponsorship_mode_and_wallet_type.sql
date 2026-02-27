-- Modify "networks" table
ALTER TABLE "networks" ADD COLUMN "delegation_contract_address" character varying NOT NULL DEFAULT '';
ALTER TABLE "networks" ADD COLUMN "wallet_service" character varying NOT NULL DEFAULT 'engine';
ALTER TABLE "networks" ADD CONSTRAINT "networks_wallet_service_check" CHECK ("wallet_service" IN ('engine', 'native'));
-- Modify "payment_orders" table
ALTER TABLE "payment_orders" ADD COLUMN "wallet_type" character varying NOT NULL DEFAULT 'smart_wallet';
