-- Modify "provider_balances" table
ALTER TABLE "provider_balances" ADD COLUMN IF NOT EXISTS "commitment_balance" double precision NOT NULL DEFAULT 0;
UPDATE "provider_balances" SET "commitment_balance" = "total_balance"
WHERE "commitment_balance" = 0 OR "commitment_balance" < "total_balance";
