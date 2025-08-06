-- Modify "lock_payment_orders" table
ALTER TABLE "lock_payment_orders" ALTER COLUMN "protocol_fee" DROP DEFAULT;
-- Create "provider_currencies" table
CREATE TABLE "provider_currencies" ("id" uuid NOT NULL, "available_balance" double precision NOT NULL, "total_balance" double precision NOT NULL, "reserved_balance" double precision NOT NULL, "is_available" boolean NOT NULL DEFAULT true, "updated_at" timestamptz NOT NULL, "fiat_currency_provider_currencies" uuid NOT NULL, "provider_profile_provider_currencies" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "provider_currencies_fiat_currencies_provider_currencies" FOREIGN KEY ("fiat_currency_provider_currencies") REFERENCES "fiat_currencies" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "provider_currencies_provider_profiles_provider_currencies" FOREIGN KEY ("provider_profile_provider_currencies") REFERENCES "provider_profiles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);

-- Create index "providercurrencies_provider_pr_236d8a9c6dae22d91e5ad2a70e016e3e" to table: "provider_currencies"
CREATE UNIQUE INDEX "providercurrencies_provider_pr_236d8a9c6dae22d91e5ad2a70e016e3e" ON "provider_currencies" ("provider_profile_provider_currencies", "fiat_currency_provider_currencies");

-- Migrate existing data from fiat_currency_providers to provider_currencies
-- Initialize all balances to 0 and availability to true for existing relationships
INSERT INTO "provider_currencies" (
    "id",
    "available_balance",
    "total_balance", 
    "reserved_balance",
    "is_available",
    "updated_at",
    "fiat_currency_provider_currencies",
    "provider_profile_provider_currencies"
)
SELECT 
    gen_random_uuid() as "id",
    0.0 as "available_balance",
    0.0 as "total_balance",
    0.0 as "reserved_balance",
    true as "is_available",
    NOW() as "updated_at",
    fcp."fiat_currency_id" as "fiat_currency_provider_currencies",
    fcp."provider_profile_id" as "provider_profile_provider_currencies"
FROM "fiat_currency_providers" fcp;

-- Drop "fiat_currency_providers" table
DROP TABLE "fiat_currency_providers";

-- Modify "provider_profiles" table
ALTER TABLE "provider_profiles" DROP COLUMN "is_available";
