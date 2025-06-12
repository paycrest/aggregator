-- First, check if the MWK fiat currency exists
SELECT EXISTS (
    SELECT 1 FROM "fiat_currencies"
    WHERE "code" = 'MWK'
);

-- If the MWK fiat currency exists, then add the institutions
DO $$
DECLARE
    fiat_currency_id UUID;
    last_bucket_id BIGINT;
BEGIN
    -- Get the ID of the MWK fiat currency
    SELECT "id" INTO fiat_currency_id
    FROM "fiat_currencies"
    WHERE "code" = 'MWK';

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
            ('MBBCMWMW','Centenary Bank', 'mobile_money', now(), now()),
            ('TNMPMWPC', 'TNM Mpamba', 'mobile_money', now(), now())
    )
    INSERT INTO "institutions" ("code", "name", "fiat_currency_institutions", "type", "updated_at", "created_at")
    SELECT "code", "name", fiat_currency_id, "type", "updated_at", "created_at"
    FROM institutions
    ON CONFLICT ("code") DO NOTHING;

    -- Get the last bucket ID
    SELECT COALESCE(MAX(id), 0) INTO last_bucket_id FROM provision_buckets;

    -- Add provision buckets to the UGX fiat currency
    INSERT INTO provision_buckets (id, min_amount, max_amount, created_at, fiat_currency_provision_buckets)
    VALUES 
        (last_bucket_id + 1, 0, 1000, now(), fiat_currency_id),
        (last_bucket_id + 2, 1001, 5000, now(), fiat_currency_id),
        (last_bucket_id + 3, 5001, 50000, now(), fiat_currency_id)
    ON CONFLICT (id) DO NOTHING;
END$$;