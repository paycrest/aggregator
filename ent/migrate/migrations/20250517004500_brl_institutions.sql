-- First, add the BRL currency
INSERT INTO fiat_currencies (
    id, code, short_name, decimals, symbol, name, market_rate, is_enabled, created_at, updated_at
) VALUES (
    gen_random_uuid(), 'BRL', 'Real', 2, 'R$', 'Brazilian Real', 5.66, false, now(), now()
);

-- Then add the institutions for BRL
DO $$
DECLARE
    fiat_currency_id UUID;
    last_bucket_id BIGINT;
BEGIN
    -- Get the ID of the BRL fiat currency
    SELECT "id" INTO fiat_currency_id
    FROM "fiat_currencies"
    WHERE "code" = 'BRL';

    -- Add institutions to the BRL fiat currency
    WITH institutions (code, name, type, updated_at, created_at) AS (
        VALUES
            ('PIXKBRPC', 'Pix', 'mobile_money', now(), now()),
            ('PIXQBRPC', 'PixQR', 'mobile_money', now(), now())
    )
    INSERT INTO "institutions" ("code", "name", "fiat_currency_institutions", "type", "updated_at", "created_at")
    SELECT "code", "name", fiat_currency_id, "type", "updated_at", "created_at"
    FROM institutions
    ON CONFLICT ("code") DO NOTHING;

    -- Get the last bucket ID
    SELECT COALESCE(MAX(id), 0) INTO last_bucket_id FROM provision_buckets;

    -- Add provision buckets to the BRL fiat currency
    INSERT INTO provision_buckets (id, min_amount, max_amount, created_at, fiat_currency_provision_buckets)
    VALUES 
        (last_bucket_id + 1, 0, 10000, now(), fiat_currency_id),
        (last_bucket_id + 2, 10001, 50000, now(), fiat_currency_id)
    ON CONFLICT (id) DO NOTHING;
END$$; 