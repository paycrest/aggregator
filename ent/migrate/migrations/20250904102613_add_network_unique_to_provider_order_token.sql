-- Drop index "providerordertoken_provider_pr_6a0d0c64fd46fb967691502cb58fa192" from table: "provider_order_tokens"
DROP INDEX "providerordertoken_provider_pr_6a0d0c64fd46fb967691502cb58fa192";

-- Backfill NULL networks from tokens.network -> networks.identifier
UPDATE provider_order_tokens pot
SET    network = n.identifier
FROM   tokens t
JOIN   networks n ON n.id = t.network_tokens
WHERE  pot.network IS NULL
AND    pot.token_provider_order_tokens = t.id;

-- Modify "provider_order_tokens" table
ALTER TABLE "provider_order_tokens" ALTER COLUMN "network" SET NOT NULL;
-- Create index "providerordertoken_network_pro_78d86f7d16ed79216b911727a796323a" to table: "provider_order_tokens"
CREATE UNIQUE INDEX "providerordertoken_network_pro_78d86f7d16ed79216b911727a796323a" ON "provider_order_tokens" ("network", "provider_profile_order_tokens", "token_provider_order_tokens", "fiat_currency_provider_order_tokens");
