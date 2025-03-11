-- Step 1: Add the columns as nullable first
ALTER TABLE "provider_order_tokens" 
  DROP COLUMN "symbol", 
  DROP COLUMN "addresses", 
  ADD COLUMN "fiat_currency_provider_order_tokens" uuid NULL, 
  ADD COLUMN "token_provider_order_tokens" bigint NULL;

-- Step 2: Set token_provider_order_tokens based on network
UPDATE provider_order_tokens pot
SET token_provider_order_tokens = t.id
FROM tokens t
JOIN networks n ON t.network_tokens = n.id
WHERE pot.network = n.identifier;

-- Step 3: Set fiat_currency_provider_order_tokens based on your criteria
WITH provider_currency_assignment AS (
  SELECT 
    pp.id AS provider_profile_id,
    CASE 
      WHEN EXISTS (
        SELECT 1 
        FROM provider_order_tokens pot 
        WHERE pot.provider_profile_order_tokens = pp.id 
          AND pot.fixed_conversion_rate < 150 
          AND pot.fixed_conversion_rate > 1
      ) THEN (SELECT id FROM fiat_currencies WHERE code = 'KES')
      ELSE (SELECT id FROM fiat_currencies WHERE code = 'NGN')
    END AS fiat_currency_id
  FROM provider_profiles pp
)
UPDATE provider_order_tokens pot
SET fiat_currency_provider_order_tokens = pca.fiat_currency_id
FROM provider_currency_assignment pca
WHERE pot.provider_profile_order_tokens = pca.provider_profile_id;

-- Step 4: Now add the NOT NULL constraints
ALTER TABLE "provider_order_tokens" 
  ALTER COLUMN "fiat_currency_provider_order_tokens" SET NOT NULL,
  ALTER COLUMN "token_provider_order_tokens" SET NOT NULL;

-- Step 5: Add foreign key constraints
ALTER TABLE "provider_order_tokens"
  ADD CONSTRAINT "provider_order_tokens_fiat_currencies_provider_order_tokens" 
    FOREIGN KEY ("fiat_currency_provider_order_tokens") 
    REFERENCES "fiat_currencies" ("id") 
    ON UPDATE NO ACTION ON DELETE CASCADE, 
  ADD CONSTRAINT "provider_order_tokens_tokens_provider_order_tokens" 
    FOREIGN KEY ("token_provider_order_tokens") 
    REFERENCES "tokens" ("id") 
    ON UPDATE NO ACTION ON DELETE CASCADE;

-- Step 6: Handle potential duplicates before creating unique index
DELETE FROM provider_order_tokens
WHERE id IN (
    SELECT id FROM (
        SELECT id,
        ROW_NUMBER() OVER (
            PARTITION BY network, provider_profile_order_tokens, token_provider_order_tokens, fiat_currency_provider_order_tokens
            ORDER BY id
        ) AS row_num
        FROM provider_order_tokens
    ) t
    WHERE row_num > 1
);

-- Step 7: Create the unique index
CREATE UNIQUE INDEX "providerordertoken_network_pro_78d86f7d16ed79216b911727a796323a" 
  ON "provider_order_tokens" ("provider_profile_order_tokens", "token_provider_order_tokens", "fiat_currency_provider_order_tokens");

-- The rest of your script
DROP INDEX "senderordertoken_sender_profil_c0e12093989225f7a56a29b8ff69c3bf";

ALTER TABLE "sender_order_tokens" RENAME COLUMN "token_sender_settings" TO "token_sender_order_tokens";

ALTER TABLE "sender_order_tokens" 
  DROP CONSTRAINT "sender_order_tokens_tokens_sender_settings", 
  ADD CONSTRAINT "sender_order_tokens_tokens_sender_order_tokens" 
    FOREIGN KEY ("token_sender_order_tokens") 
    REFERENCES "tokens" ("id") 
    ON UPDATE NO ACTION ON DELETE CASCADE;

CREATE UNIQUE INDEX "senderordertoken_sender_profil_42c97c0d9385a26fbc0a873a5885486b" 
  ON "sender_order_tokens" ("sender_profile_order_tokens", "token_sender_order_tokens");

DROP TABLE "fiat_currency_provider_settings";
DROP TABLE "token_provider_settings";