-- Modify "networks" table
ALTER TABLE "networks" ADD COLUMN "delegation_contract_address" character varying NOT NULL DEFAULT '', ADD COLUMN "wallet_service" character varying NOT NULL DEFAULT 'engine';
-- Modify "provider_balances" table
ALTER TABLE "provider_balances" ALTER COLUMN "peak_balance" DROP DEFAULT;
