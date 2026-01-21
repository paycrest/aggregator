-- Create "provider_balances" table
CREATE TABLE "provider_balances" (
  "id" uuid NOT NULL,
  "available_balance" double precision NOT NULL,
  "total_balance" double precision NOT NULL,
  "reserved_balance" double precision NOT NULL,
  "is_available" boolean NOT NULL DEFAULT true,
  "updated_at" timestamptz NOT NULL,
  "fiat_currency_provider_balances" uuid NULL,
  "token_provider_balances" bigint NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "provider_balances_fiat_currencies_provider_balances" FOREIGN KEY ("fiat_currency_provider_balances") REFERENCES "fiat_currencies" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "provider_balances_tokens_provider_balances" FOREIGN KEY ("token_provider_balances") REFERENCES "tokens" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "provider_balances_xor_check" CHECK (
    ("fiat_currency_provider_balances" IS NOT NULL)::int + ("token_provider_balances" IS NOT NULL)::int = 1
  )
);
-- Create "provider_profile_provider_balances" table
CREATE TABLE "provider_profile_provider_balances" (
  "provider_profile_id" character varying NOT NULL,
  "provider_balances_id" uuid NOT NULL,
  PRIMARY KEY ("provider_profile_id", "provider_balances_id"),
  CONSTRAINT "provider_profile_provider_balances_provider_balances_id" FOREIGN KEY ("provider_balances_id") REFERENCES "provider_balances" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "provider_profile_provider_balances_provider_profile_id" FOREIGN KEY ("provider_profile_id") REFERENCES "provider_profiles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Add pk ranges for ('provider_balances') tables
INSERT INTO "ent_types" ("type") VALUES ('provider_balances');

-- Drop old provider_currencies and its unique index (drop table cascades indexes)
DROP TABLE "provider_currencies";
