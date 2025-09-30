-- First, create the MWK fiat currency if it doesn't exist
INSERT INTO fiat_currencies (
    id, code, short_name, decimals, symbol, name, market_rate, is_enabled, created_at, updated_at
) VALUES (
    gen_random_uuid(), 'MWK', 'Kwacha', 2, 'MK', 'Malawian Kwacha', 1700.00, false, now(), now()
) ON CONFLICT (code) DO NOTHING;

-- Add institutions and provision buckets for MWK
DO $$
DECLARE
    fiat_currency_id UUID;
    last_bucket_id BIGINT;
BEGIN
    -- Get the ID of the MWK fiat currency
    SELECT "id" INTO fiat_currency_id
    FROM "fiat_currencies"
    WHERE "code" = 'MWK';

    -- Only proceed if the fiat currency exists
    IF fiat_currency_id IS NOT NULL THEN
        -- Add institutions to the MWK fiat currency
    WITH institutions (code, name, type, updated_at, created_at) AS (
        VALUES
            ('ECOCMWMW', 'Ecobank Malawi Limited', 'bank', now(), now()),
            ('SBICMWMX', 'Standard Bank Limited', 'bank', now(), now()),
            ('NBMAMWMW', 'National Bank of Malawi', 'bank', now(), now()),
            ('FDHFMWMW', 'FDH Bank Limited', 'bank', now(), now()),
            ('CDHIMWMW', 'CDH Investment Bank', 'bank', now(), now()),
            ('FRCGMWMW', 'First Capital Limited', 'bank', now(), now()),
            ('NBSTMWMW','NBS Bank Limited', 'bank', now(), now()),
            ('MBBCMWMW','Centenary Bank', 'bank', now(), now()),
            ('TNMPMWPC', 'TNM Mpamba', 'mobile_money', now(), now())
    )
    INSERT INTO "institutions" ("code", "name", "fiat_currency_institutions", "type", "updated_at", "created_at")
    SELECT "code", "name", fiat_currency_id, "type", "updated_at", "created_at"
    FROM institutions
    ON CONFLICT ("code") DO NOTHING;

    -- Get the last bucket ID
    SELECT COALESCE(MAX(id), 0) INTO last_bucket_id FROM provision_buckets;

    -- Add provision buckets to the MWK fiat currency
    INSERT INTO provision_buckets (id, min_amount, max_amount, created_at, fiat_currency_provision_buckets)
    VALUES 
        (last_bucket_id + 1, 0, 50000, now(), fiat_currency_id),
        (last_bucket_id + 2, 50001, 10000000, now(), fiat_currency_id),
        (last_bucket_id + 3, 10000001, 100000000, now(), fiat_currency_id)
    ON CONFLICT (id) DO NOTHING;
    END IF;
END$$;