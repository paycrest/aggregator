-- Rename sponsorship_mode to wallet_service and update enum values (thirdweb -> engine, self_sponsored -> native)
-- 1. Drop the existing CHECK constraint that references sponsorship_mode
ALTER TABLE "networks" DROP CONSTRAINT IF EXISTS "networks_self_sponsored_requires_delegation_contract";

-- 2. Update existing values to new enum
UPDATE "networks" SET "sponsorship_mode" = 'engine' WHERE "sponsorship_mode" = 'thirdweb';
UPDATE "networks" SET "sponsorship_mode" = 'native' WHERE "sponsorship_mode" = 'self_sponsored';

-- 3. Rename column
ALTER TABLE "networks" RENAME COLUMN "sponsorship_mode" TO "wallet_service";

-- 4. Re-add CHECK: when wallet_service is 'native', delegation_contract_address must be non-empty
ALTER TABLE "networks" ADD CONSTRAINT "networks_native_requires_delegation_contract" CHECK (
  (wallet_service <> 'native') OR (delegation_contract_address <> '')
);
