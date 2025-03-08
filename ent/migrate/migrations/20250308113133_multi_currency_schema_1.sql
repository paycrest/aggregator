-- Rename an index from "lockpaymentorder_gateway_id_rate_tx_hash_block_number_instituti" to "lockpaymentorder_gateway_id_ra_65d1cd4f9b7a0ff4525b6f2bc506afdc"
ALTER INDEX "lockpaymentorder_gateway_id_rate_tx_hash_block_number_instituti" RENAME TO "lockpaymentorder_gateway_id_ra_65d1cd4f9b7a0ff4525b6f2bc506afdc";
-- Rename an index from "senderordertoken_sender_profile_order_tokens_token_sender_setti" to "senderordertoken_sender_profil_c0e12093989225f7a56a29b8ff69c3bf"
ALTER INDEX "senderordertoken_sender_profile_order_tokens_token_sender_setti" RENAME TO "senderordertoken_sender_profil_c0e12093989225f7a56a29b8ff69c3bf";
-- Modify "provider_order_tokens" table
ALTER TABLE "provider_order_tokens" ALTER COLUMN "provider_profile_order_tokens" SET NOT NULL, ADD COLUMN "address" character varying NULL, ADD COLUMN "network" character varying NULL;
-- Create "fiat_currency_provider_settings" table
CREATE TABLE "fiat_currency_provider_settings" ("fiat_currency_id" uuid NOT NULL, "provider_order_token_id" bigint NOT NULL, PRIMARY KEY ("fiat_currency_id", "provider_order_token_id"), CONSTRAINT "fiat_currency_provider_settings_fiat_currency_id" FOREIGN KEY ("fiat_currency_id") REFERENCES "fiat_currencies" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "fiat_currency_provider_settings_provider_order_token_id" FOREIGN KEY ("provider_order_token_id") REFERENCES "provider_order_tokens" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Modify "provider_profiles" table
ALTER TABLE "provider_profiles" DROP COLUMN "fiat_currency_providers";
-- Create "fiat_currency_providers" table
CREATE TABLE "fiat_currency_providers" ("fiat_currency_id" uuid NOT NULL, "provider_profile_id" character varying NOT NULL, PRIMARY KEY ("fiat_currency_id", "provider_profile_id"), CONSTRAINT "fiat_currency_providers_fiat_currency_id" FOREIGN KEY ("fiat_currency_id") REFERENCES "fiat_currencies" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "fiat_currency_providers_provider_profile_id" FOREIGN KEY ("provider_profile_id") REFERENCES "provider_profiles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "token_provider_settings" table
CREATE TABLE "token_provider_settings" ("token_id" bigint NOT NULL, "provider_order_token_id" bigint NOT NULL, PRIMARY KEY ("token_id", "provider_order_token_id"), CONSTRAINT "token_provider_settings_provider_order_token_id" FOREIGN KEY ("provider_order_token_id") REFERENCES "provider_order_tokens" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "token_provider_settings_token_id" FOREIGN KEY ("token_id") REFERENCES "tokens" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
