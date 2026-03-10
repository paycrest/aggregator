-- Modify "provider_balances" table
ALTER TABLE "provider_balances" ADD COLUMN "peak_balance" double precision NOT NULL DEFAULT 0.0;
