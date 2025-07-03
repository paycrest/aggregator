-- First, check if the INR fiat currency exists
SELECT EXISTS (
    SELECT 1 FROM "fiat_currencies"
    WHERE "code" = 'INR'
);

-- If the INR fiat currency exists, then add the institutions and provision buckets
DO $$
DECLARE
    fiat_currency_id UUID;
    last_bucket_id BIGINT;
BEGIN
    -- Get the ID of the INR fiat currency
    SELECT "id" INTO fiat_currency_id
    FROM "fiat_currencies"
    WHERE "code" = 'INR';

    -- Add institutions to the INR fiat currency
    WITH institutions (code, name, type, updated_at, created_at) AS (
        VALUES
            -- Banks (using SWIFT-like codes as primary identifiers)
            ('SBININBB', 'State Bank of India', 'bank', now(), now()),
            ('HDFCINBB', 'HDFC Bank', 'bank', now(), now()),
            ('ICICINBB', 'ICICI Bank', 'bank', now(), now()),
            ('AXISINBB', 'Axis Bank', 'bank', now(), now()),
            ('PUNBINBB', 'Punjab National Bank', 'bank', now(), now()),
            ('BARBINBB', 'Bank of Baroda', 'bank', now(), now()),
            ('CANBINBB', 'Canara Bank', 'bank', now(), now()),
            ('UBININBB', 'Union Bank of India', 'bank', now(), now()),
            ('IDIBINBB', 'Indian Bank', 'bank', now(), now()),
            ('IOBAINBB', 'Indian Overseas Bank', 'bank', now(), now()),
            ('PSIBINBB', 'Punjab & Sind Bank', 'bank', now(), now()),
            ('UCBAINBB', 'UCO Bank', 'bank', now(), now()),
            ('BKIDINBB', 'Bank of India', 'bank', now(), now()),
            ('CBININBB', 'Central Bank of India', 'bank', now(), now()),
            ('IDFBINBB', 'IDFC First Bank', 'bank', now(), now()),
            ('KKBKINBB', 'Kotak Mahindra Bank', 'bank', now(), now()),
            ('YESBINBB', 'Yes Bank', 'bank', now(), now()),
            ('FINOINBB', 'Fino Payments Bank', 'bank', now(), now()),
            ('AUBLINBB', 'AU Small Finance Bank', 'bank', now(), now()),
            ('JANAINBB', 'Jana Small Finance Bank', 'bank', now(), now()),
            ('UJVNINBB', 'Ujjivan Small Finance Bank', 'bank', now(), now()),
            ('ESFBINBB', 'Equitas Small Finance Bank', 'bank', now(), now()),
            ('PAYMINBB', 'Paytm Payments Bank', 'bank', now(), now()),
            ('AMEXINBB', 'American Express', 'bank', now(), now()),
            ('CITIINBB', 'Citibank India', 'bank', now(), now()),
            ('HSBCINBB', 'HSBC India', 'bank', now(), now()),
            ('SCBLINBB', 'Standard Chartered Bank', 'bank', now(), now()),
            ('DBSSINBB', 'DBS Bank India', 'bank', now(), now()),
            ('RATNINBB', 'RBL Bank', 'bank', now(), now()),
            ('KARNINBB', 'Karnataka Bank', 'bank', now(), now()),
            ('KVBLINBB', 'Karur Vysya Bank', 'bank', now(), now()),
            ('TMBLINBB', 'Tamilnad Mercantile Bank', 'bank', now(), now()),
            ('FEDFINBB', 'Federal Bank', 'bank', now(), now()),
            ('SOUTINBB', 'South Indian Bank', 'bank', now(), now()),
            ('DCBLINBB', 'DCB Bank', 'bank', now(), now()),
            ('JAMMINBB', 'Jammu & Kashmir Bank', 'bank', now(), now()),
            ('VIJYINBB', 'Vijaya Bank', 'bank', now(), now()),
            ('ALLAINBB', 'Allahabad Bank', 'bank', now(), now()),
            ('SYNBINBB', 'Syndicate Bank', 'bank', now(), now()),
            ('ORBCINBB', 'Oriental Bank of Commerce', 'bank', now(), now()),
            ('ANDBINBB', 'Andhra Bank', 'bank', now(), now()),
            ('VIJBINBB', 'Vijaya Bank', 'bank', now(), now()),
            ('UNIONINBB', 'Union Bank of India', 'bank', now(), now()),
            ('INDIINBB', 'Indian Bank', 'bank', now(), now()),
            ('MAHBINBB', 'Bank of Maharashtra', 'bank', now(), now()),
            ('BNDNINCC', 'Bandhan Bank', 'bank', now(), now()),
            ('CNRBINBB', 'Canara Bank', 'bank', now(), now()),
            ('CIUBIN5M', 'City Union Bank', 'bank', now(), now()),
            ('COSDINBB', 'Cosmos Co-operative Bank', 'bank', now(), now()),
            ('DLXBINBB', 'Dhanlaxmi Bank', 'bank', now(), now()),
            ('DEUTINBB', 'Deutsche Bank', 'bank', now(), now()),
            ('EQTBIN55', 'Equitas Small Finance Bank', 'bank', now(), now()),
            ('FDRLINBB', 'Federal Bank', 'bank', now(), now()),
            ('IBKLINBB', 'IDBI Bank', 'bank', now(), now()),
            ('INDBINBB', 'IndusInd Bank', 'bank', now(), now()),
            ('KARBINBB', 'Karnataka Bank', 'bank', now(), now()),
            ('SOININ55', 'South Indian Bank', 'bank', now(), now()),
            ('CSYBIN55', 'Catholic Syrian Bank', 'bank', now(), now()),
            ('NSDLINB1', 'NSDL Payments Bank', 'bank', now(), now()),
            ('UPIINPC', 'UPI (Unified Payments Interface)', 'mobile_money', now(), now()),
            ('PAYTINPC', 'Paytm Wallet', 'mobile_money', now(), now()),
            ('PHONINPC', 'PhonePe Wallet', 'mobile_money', now(), now()),
            ('GOOGINPC', 'Google Pay', 'mobile_money', now(), now()),
            ('AMAZINPC', 'Amazon Pay', 'mobile_money', now(), now()),
            ('BHIMINPC', 'BHIM UPI', 'mobile_money', now(), now()),
            ('FREIINPC', 'Freecharge Wallet', 'mobile_money', now(), now()),
            ('MOKIINPC', 'MobiKwik Wallet', 'mobile_money', now(), now()),
            ('CREDINPC', 'CRED App', 'mobile_money', now(), now()),
            ('GPAYINPC', 'Google Pay', 'mobile_money', now(), now()),
            ('APAYINPC', 'Apple Pay', 'mobile_money', now(), now()),
            ('SAMSINPC', 'Samsung Pay', 'mobile_money', now(), now()),
            ('WALTINPC', 'Generic Wallet', 'mobile_money', now(), now()),
            ('RELIINPC', 'Reliance JioMoney', 'mobile_money', now(), now()),
            ('AIRTINPC', 'Airtel Money', 'mobile_money', now(), now()),
            ('VODAINPC', 'Vodafone M-Pesa', 'mobile_money', now(), now()),
            ('IDEAINPC', 'Idea Money', 'mobile_money', now(), now()),
            ('BSNLINPC', 'BSNL Money', 'mobile_money', now(), now()),
            ('MTNLINPC', 'MTNL Money', 'mobile_money', now(), now())
    )
    INSERT INTO "institutions" ("code", "name", "fiat_currency_institutions", "type", "updated_at", "created_at")
    SELECT "code", "name", fiat_currency_id, "type", "updated_at", "created_at"
    FROM institutions
    ON CONFLICT ("code") DO NOTHING;

    -- Get the last bucket ID
    SELECT COALESCE(MAX(id), 0) INTO last_bucket_id FROM provision_buckets;

    -- Add provision buckets for INR fiat currency
    INSERT INTO provision_buckets (id, min_amount, max_amount, created_at, fiat_currency_provision_buckets)
    VALUES
        (last_bucket_id + 1, 0, 10000, now(), fiat_currency_id),
        (last_bucket_id + 2, 10001, 100000, now(), fiat_currency_id),
        (last_bucket_id + 3, 100001, 1000000, now(), fiat_currency_id)
    ON CONFLICT (id) DO NOTHING;
END$$;