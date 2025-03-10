-- Modify "provider_order_tokens" table
ALTER TABLE "provider_order_tokens" DROP COLUMN "symbol", DROP COLUMN "addresses", ADD COLUMN "fiat_currency_provider_order_tokens" uuid NOT NULL, ADD COLUMN "token_provider_order_tokens" bigint NOT NULL, ADD CONSTRAINT "provider_order_tokens_fiat_currencies_provider_order_tokens" FOREIGN KEY ("fiat_currency_provider_order_tokens") REFERENCES "fiat_currencies" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, ADD CONSTRAINT "provider_order_tokens_tokens_provider_order_tokens" FOREIGN KEY ("token_provider_order_tokens") REFERENCES "tokens" ("id") ON UPDATE NO ACTION ON DELETE CASCADE;
-- Create index "providerordertoken_network_pro_78d86f7d16ed79216b911727a796323a" to table: "provider_order_tokens"
CREATE UNIQUE INDEX "providerordertoken_network_pro_78d86f7d16ed79216b911727a796323a" ON "provider_order_tokens" ("network", "provider_profile_order_tokens", "token_provider_order_tokens", "fiat_currency_provider_order_tokens");
-- Drop index "senderordertoken_sender_profil_c0e12093989225f7a56a29b8ff69c3bf" from table: "sender_order_tokens"
DROP INDEX "senderordertoken_sender_profil_c0e12093989225f7a56a29b8ff69c3bf";
-- Rename a column from "token_sender_settings" to "token_sender_order_tokens"
ALTER TABLE "sender_order_tokens" RENAME COLUMN "token_sender_settings" TO "token_sender_order_tokens";
-- Modify "sender_order_tokens" table
ALTER TABLE "sender_order_tokens" DROP CONSTRAINT "sender_order_tokens_tokens_sender_settings", ADD CONSTRAINT "sender_order_tokens_tokens_sender_order_tokens" FOREIGN KEY ("token_sender_order_tokens") REFERENCES "tokens" ("id") ON UPDATE NO ACTION ON DELETE CASCADE;
-- Create index "senderordertoken_sender_profil_42c97c0d9385a26fbc0a873a5885486b" to table: "sender_order_tokens"
CREATE UNIQUE INDEX "senderordertoken_sender_profil_42c97c0d9385a26fbc0a873a5885486b" ON "sender_order_tokens" ("sender_profile_order_tokens", "token_sender_order_tokens");
-- Drop "fiat_currency_provider_settings" table
DROP TABLE "fiat_currency_provider_settings";
-- Drop "token_provider_settings" table
DROP TABLE "token_provider_settings";
