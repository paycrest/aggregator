-- Drop index "providerordertoken_network_pro_78d86f7d16ed79216b911727a796323a" from table: "provider_order_tokens"
DROP INDEX "providerordertoken_network_pro_78d86f7d16ed79216b911727a796323a";
-- Create index "providerordertoken_provider_pr_6a0d0c64fd46fb967691502cb58fa192" to table: "provider_order_tokens"
CREATE UNIQUE INDEX "providerordertoken_provider_pr_6a0d0c64fd46fb967691502cb58fa192" ON "provider_order_tokens" ("provider_profile_order_tokens", "token_provider_order_tokens", "fiat_currency_provider_order_tokens");
