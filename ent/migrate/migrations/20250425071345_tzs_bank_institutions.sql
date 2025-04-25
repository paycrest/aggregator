-- First, check if the TZS fiat currency exists
SELECT EXISTS (
    SELECT 1 FROM "fiat_currencies"
    WHERE "code" = 'TZS'
);

-- If the TZS fiat currency exists, then add the institutions
DO $$
DECLARE
    fiat_currency_id UUID;
    last_bucket_id BIGINT;
BEGIN
    -- Get the ID of the TZS fiat currency
    SELECT "id" INTO fiat_currency_id
    FROM "fiat_currencies"
    WHERE "code" = 'TZS';

    -- Add institutions to the TZS fiat currency
    WITH institutions (code, name, type, updated_at, created_at) AS (
        VALUES
            ('ACTZTZTZ', 'Access Bank Tanzania Ltd', 'bank', now(), now()),
            ('AKCOTZTZ', 'Akiba Commercial Bank PLC', 'bank', now(), now()),
            ('AMNNTZTZ', 'Amana Bank Limited', 'bank', now(), now()),
            ('AZANTZTZ', 'Azania bank Limited', 'bank', now(), now()),
            ('BNKMTZPC', 'bank M Tanzania Public Limited Company', 'bank', now(), now()),
            ('EUAFTZTZ', 'Bank of Africa Tanzania Limited', 'bank', now(), now()),
            ('BARBTZTZ', 'Bank of Baroda (Tanzania) Ltd', 'bank', now(), now()),
            ('BKIDTZTZ', 'Bank Of India (Tanzania) Limited', 'bank', now(), now()),
            ('TANZTZTX', 'Bank of Tanzania', 'bank', now(), now()),
            ('BARCTZTZ', 'Barclays Bank (Tanzania) Ltd.', 'bank', now(), now()),
            ('CNRBTZTZ', 'Canara Bank (Tanzania) Limited', 'bank', now(), now()),
            ('CHLMTZTZ', 'China Commercial Bank Limited', 'bank', now(), now()),
            ('CITITZTZ', 'Citibank Tanzania Ltd.', 'bank', now(), now()),
            ('CBAFTZTZ', 'Commercial Bank of Africa (Tanzania) Limited', 'bank', now(), now()),
            ('CBFWTZTZ', 'Covenant Bank For Women (Tanzania) Limited', 'bank', now(), now()),
            ('CORUTZTZ', 'CRDB Bank PLC', 'bank', now(), now()),
            ('DASUTZTZ', 'DCB Commercial Bank Plc', 'bank', now(), now()),
            ('DTKETZTZ', 'Diamond Trust Bank Tanzania Limited', 'bank', now(), now()),
            ('ECOCTZTZ', 'Ecobank Tanzania', 'bank', now(), now()),
            ('EQBLTZTZ', 'Equity Bank Tanzania Limited', 'bank', now(), now()),
            ('EXTNTZTZ', 'Exim Bank (Tanzania) Limited', 'bank', now(), now()),
            ('FNMITZTZ', 'FINCA Microfinance Bank Ltd', 'bank', now(), now()),
            ('FHTLTZPC', 'First Housing Finance Tanzania Limited', 'bank', now(), now()),
            ('FIRNTZTX', 'First National Bank Tanzania Limited', 'bank', now(), now()),
            ('GTBITZTZ', 'Guaranty Trust Bank (Tanzania) Limited', 'bank', now(), now()),
            ('HABLTZTZ', 'Habib African Bank Ltd.', 'bank', now(), now()),
            ('HALOTZPC', 'Halopesa', 'mobile_money', now(), now()),
            ('IMBLTZTZ', 'I and M Bank Tanzania Limited', 'bank', now(), now()),
            ('BKMYTZTZ', 'International Commercial Bank (Tanzania) Ltd', 'bank', now(), now()),
            ('KCBLTZTZ', 'KCB Bank Tanzania Ltd', 'bank', now(), now()),
            ('KLMJTZTZ', 'Kilimanjaro Cooperative Bank Limited', 'bank', now(), now()),
            ('ADVBTZTZ', 'Letshego Bank (T) Limited', 'bank', now(), now()),
            ('MBTLTZTZ', 'Maendeleo Bank Ltd', 'bank', now(), now()),
            ('MKCBTZTZ', 'Mkombozi Commercial Bank Ltd', 'bank', now(), now()),
            ('MUOBTZTZ', 'Mucoba Bank Plc', 'bank', now(), now()),
            ('MWCOTZTZ', 'Mwalimu Commercial Bank Plc', 'bank', now(), now()),
            ('MWCBTZTZ', 'Mwanga Community Bank Ltd', 'bank', now(), now()),
            ('NLCBTZTX', 'National Bank of Commerce Ltd.', 'bank', now(), now()),
            ('NMIBTZTZ', 'National Microfinance Bank Ltd.', 'bank', now(), now()),
            ('SFICTZTZ', 'NIC Bank Tanzania Limited', 'bank', now(), now()),
            ('SBICTZTX', 'Stanbic Bank Tanzania Ltd', 'bank', now(), now()),
            ('SCBLTZTX', 'Standard Chartered Bank Tanzania Ltd.', 'bank', now(), now()),
            ('TZADTZTZ', 'Tanzania Agricultural Development Bank', 'bank', now(), now()),
            ('PBZATZTZ', 'The People''s Bank of Zanzibar Ltd.', 'bank', now(), now()),
            ('TAINTZTZ', 'TIB Corporate Bank Limited', 'bank', now(), now()),
            ('TIBDTZPC', 'TIB Development Bank Ltd', 'bank', now(), now()),
            ('TAPBTZTZ', 'TPB Bank Company Ltd', 'bank', now(), now()),
            ('TRBATZT1', 'Trust Bank (Tanzania) Limited', 'bank', now(), now()),
            ('UNILTZTZ', 'UBL Bank (Tanzania) Limited', 'bank', now(), now()),
            ('UCCTTZTZ', 'Uchumi Commercial Bank', 'bank', now(), now()),
            ('UNAFTZTZ', 'United Bank For Africa (Tanzania) Limited', 'bank', now(), now()),
            ('VODATZPC', 'Vodacom', 'mobile_money', now(), now()),
            ('YETMTZTZ', 'Yetu Microfinance Bank PLC', 'bank', now(), now())
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