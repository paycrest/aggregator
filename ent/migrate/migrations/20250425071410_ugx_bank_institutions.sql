-- First, check if the UGX fiat currency exists
SELECT EXISTS (
    SELECT 1 FROM "fiat_currencies"
    WHERE "code" = 'UGX'
);

-- If the UGX fiat currency exists, then add the institutions
DO $$
DECLARE
    fiat_currency_id UUID;
    last_bucket_id BIGINT;
BEGIN
    -- Get the ID of the UGX fiat currency
    SELECT "id" INTO fiat_currency_id
    FROM "fiat_currencies"
    WHERE "code" = 'UGX';

    -- Add institutions to the UGX fiat currency
    WITH institutions (code, name, type, updated_at, created_at) AS (
        VALUES
            ('ABCFUGKA', 'ABC Capital Bank Ltd', 'bank', now(), now()),
            ('ULTXUGK1', 'Alt Xchange Limited', 'bank', now(), now()),
            ('AFRIUGKA', 'Bank of Africa Uganda Ltd', 'bank', now(), now()),
            ('BARBUGKA', 'Bank of Baroda (Uganda) Limited', 'bank', now(), now()),
            ('BKIDUGKA', 'Bank of India (Uganda) Limited', 'bank', now(), now()),
            ('UGBAUGKA', 'Bank of Uganda', 'bank', now(), now()),
            ('BARCUGKX', 'Barclays Bank of Uganda Limited', 'bank', now(), now()),
            ('BATSUGK1', 'British American Tobacco Uganda Ltd', 'bank', now(), now()),
            ('CAIEUGKA', 'Cairo International Bank Limited', 'bank', now(), now()),
            ('CERBUGKA', 'Centenary Rural Development Bank Limited', 'bank', now(), now()),
            ('CITIUGKA', 'Citibank Uganda Limited', 'bank', now(), now()),
            ('COPBUGK1', 'Co-Operative Bank Ltd.', 'bank', now(), now()),
            ('CBAFUGKA', 'Commercial Bank of Africa Uganda Limited', 'bank', now(), now()),
            ('COBEUGPC', 'Commerzbank - EUR', 'bank', now(), now()),
            ('COBGUGPC', 'Commerzbank - GBP', 'bank', now(), now()),
            ('COBUUGPC', 'Commerzbank - USD', 'bank', now(), now()),
            ('CRANUGKA', 'Crane Bank Ltd', 'bank', now(), now()),
            ('CRKSUGK1', 'Crested Stocks And Securities Limited', 'bank', now(), now()),
            ('DFCUUGKA', 'DFCU Bank Ltd.', 'bank', now(), now()),
            ('DTKEUGKA', 'Diamond Trust Bank Uganda Limited', 'bank', now(), now()),
            ('AFDEUGKA', 'East African Development Bank', 'bank', now(), now()),
            ('ECOCUGKA', 'Ecobank', 'bank', now(), now()),
            ('ENCOUGK1', 'Engiplan Consultants', 'bank', now(), now()),
            ('EQBLUGKA', 'Equity Bank Uganda Limited', 'bank', now(), now()),
            ('EQSBUGK1', 'Equity Stock Brokers (U) Ltd', 'bank', now(), now()),
            ('EXTNUGKA', 'Exim Bank (Uganda) Limited', 'bank', now(), now()),
            ('FTBLUGKA', 'Finance Trust Bank Limited', 'bank', now(), now()),
            ('FINCAUGPC', 'FINCA Uganda Limited', 'bank', now(), now()),
            ('GLTRUGPC', 'Global Trust Bank', 'bank', now(), now()),
            ('GTBIUGKA', 'Guaranty Trust Bank Uganda Limited', 'bank', now(), now()),
            ('HFINUGKA', 'Housing Finance Bank Limited', 'bank', now(), now()),
            ('ICFBUGK1', 'International Credit Bank Ltd.', 'bank', now(), now()),
            ('KCBLUGKA', 'KCB Bank Uganda Limited', 'bank', now(), now()),
            ('MBRSUGK1', 'Mbea Brokerage Services (U) Limited', 'bank', now(), now()),
            ('MCBDUGKB', 'Mercantile Credit Bank Ltd', 'bank', now(), now()),
            ('NACOUGKA', 'National Bank of Commerce', 'bank', now(), now()),
            ('NINCUGPC', 'NC Bank Uganda Limited', 'bank', now(), now()),
            ('NEDTUGPC', 'Nedbank', 'bank', now(), now()),
            ('OPUGUGKA', 'Opportunity Bank Uganda Limited', 'bank', now(), now()),
            ('ORINUGKA', 'Orient Bank Limited', 'bank', now(), now()),
            ('UGPBUGKA', 'Post Bank Uganda Limited', 'bank', now(), now()),
            ('PRDEMFPC', 'Pride Microfinance Limited', 'bank', now(), now()),
            ('SABMUGT1', 'Sabmiller Uganda', 'bank', now(), now()),
            ('SBICUGKX', 'Stanbic Bank Uganda Limited', 'bank', now(), now()),
            ('SCBLUGKA', 'Standard Chartered Bank Uganda Limited', 'bank', now(), now()),
            ('UIDBUGK1', 'The Uganda Institute of Bankers', 'bank', now(), now()),
            ('TOPFUGKA', 'Top Finance Bank Limited', 'bank', now(), now()),
            ('TRABUGPC', 'Trans Africa Bank Ltd', 'bank', now(), now()),
            ('TROAUGKA', 'Tropical Bank Limited', 'bank', now(), now()),
            ('TRBAUGK1', 'Trust Bank (Uganda) Limited', 'bank', now(), now()),
            ('USCDUGKA', 'Uganda Securities Exchange', 'bank', now(), now()),
            ('UNAFUGKA', 'United Bank for Africa Uganda Limited', 'bank', now(), now())
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