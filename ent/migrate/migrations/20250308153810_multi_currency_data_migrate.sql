-- First, create new rows with expanded address/network pairs
WITH expanded_addresses AS (
  SELECT 
    pot.id AS original_id,
    pot.created_at,
    pot.updated_at,
    pot.symbol,
    pot.fixed_conversion_rate,
    pot.floating_conversion_rate,
    pot.conversion_rate_type,
    pot.max_order_amount,
    pot.min_order_amount,
    pot.provider_profile_order_tokens,
    json_array_elements(pot.addresses::json) AS address_obj
  FROM provider_order_tokens pot
  WHERE pot.addresses IS NOT NULL AND pot.addresses != '[]'
)
INSERT INTO provider_order_tokens (
  created_at,
  updated_at,
  symbol,
  fixed_conversion_rate,
  floating_conversion_rate,
  conversion_rate_type,
  max_order_amount,
  min_order_amount,
  provider_profile_order_tokens,
  addresses,  -- Include addresses column
  address,
  network
)
SELECT 
  ea.created_at,
  ea.updated_at,
  ea.symbol,
  ea.fixed_conversion_rate,
  ea.floating_conversion_rate,
  ea.conversion_rate_type,
  ea.max_order_amount,
  ea.min_order_amount,
  ea.provider_profile_order_tokens,
  '[]'::jsonb,  -- Empty JSON array for addresses
  (ea.address_obj->>'address')::varchar AS address,
  (ea.address_obj->>'network')::varchar AS network
FROM expanded_addresses ea;

-- Then, delete the original rows that had JSON arrays
DELETE FROM provider_order_tokens 
WHERE addresses IS NOT NULL AND addresses != '[]';

-- Insert relationships into token_provider_settings table
INSERT INTO token_provider_settings (token_id, provider_order_token_id)
SELECT t.id AS token_id, pot.id AS provider_order_token_id
FROM provider_order_tokens pot
JOIN tokens t ON pot.symbol = t.symbol
JOIN networks n ON t.network_tokens = n.id
WHERE pot.network = n.identifier
-- Avoid duplicate entries
ON CONFLICT (token_id, provider_order_token_id) DO NOTHING;

-- First, create a Common Table Expression to determine the appropriate fiat_currency_id for each provider
WITH provider_currency_mapping AS (
  SELECT 
    pp.id AS provider_profile_id,
    CASE 
      WHEN EXISTS (
        SELECT 1 
        FROM provider_order_tokens pot 
        WHERE pot.provider_profile_order_tokens = pp.id 
          AND pot.fixed_conversion_rate < 150
      ) THEN (SELECT id FROM fiat_currencies WHERE code = 'KES')
      ELSE (SELECT id FROM fiat_currencies WHERE code = 'NGN')
    END AS fiat_currency_id
  FROM provider_profiles pp
)

-- Now insert into fiat_currency_provider_settings
INSERT INTO fiat_currency_provider_settings (fiat_currency_id, provider_order_token_id)
SELECT 
  pcm.fiat_currency_id,
  pot.id AS provider_order_token_id
FROM provider_order_tokens pot
JOIN provider_currency_mapping pcm ON pot.provider_profile_order_tokens = pcm.provider_profile_id
-- Avoid duplicate entries
ON CONFLICT (fiat_currency_id, provider_order_token_id) DO NOTHING;