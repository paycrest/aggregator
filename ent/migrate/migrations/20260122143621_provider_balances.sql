-- Rename a column from "address" to "settlement_address"
ALTER TABLE "provider_order_tokens" RENAME COLUMN "address" TO "settlement_address";
-- Modify "provider_order_tokens" table
ALTER TABLE "provider_order_tokens" ADD COLUMN "payout_address" character varying NULL;
-- Create "provider_balances" table
CREATE TABLE "provider_balances" (
  "id" uuid NOT NULL,
  "available_balance" double precision NOT NULL,
  "total_balance" double precision NOT NULL,
  "reserved_balance" double precision NOT NULL,
  "is_available" boolean NOT NULL DEFAULT true,
  "updated_at" timestamptz NOT NULL,
  "fiat_currency_provider_balances" uuid NULL,
  "provider_profile_provider_balances" character varying NOT NULL,
  "token_provider_balances" bigint NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "provider_balances_fiat_currencies_provider_balances" FOREIGN KEY ("fiat_currency_provider_balances") REFERENCES "fiat_currencies" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "provider_balances_provider_profiles_provider_balances" FOREIGN KEY ("provider_profile_provider_balances") REFERENCES "provider_profiles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "provider_balances_tokens_provider_balances" FOREIGN KEY ("token_provider_balances") REFERENCES "tokens" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "providerbalances_provider_prof_2921dab244b64cba131b96e75d015a42" to table: "provider_balances"
CREATE UNIQUE INDEX "providerbalances_provider_prof_2921dab244b64cba131b96e75d015a42" ON "provider_balances" ("provider_profile_provider_balances", "token_provider_balances");
-- Create index "providerbalances_provider_prof_d9d18842b7ae2319abfa725851077fe7" to table: "provider_balances"
CREATE UNIQUE INDEX "providerbalances_provider_prof_d9d18842b7ae2319abfa725851077fe7" ON "provider_balances" ("provider_profile_provider_balances", "fiat_currency_provider_balances");
-- Add pk ranges for ('provider_balances') tables
INSERT INTO "ent_types" ("type") VALUES ('provider_balances');
