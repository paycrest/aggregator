-- -------------------------------------------------------------
-- TablePlus 6.2.1(578)
--
-- https://tableplus.com/
--
-- Database: neondb
-- Generation Time: 2025-01-21 10:59:35.8580
-- -------------------------------------------------------------


-- Drop Schema
DROP SCHEMA IF EXISTS public CASCADE;

DROP SCHEMA IF EXISTS atlas_schema_revisions CASCADE;

-- Create Schema
CREATE SCHEMA public;
CREATE SCHEMA atlas_schema_revisions;

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."api_keys" (
    "id" uuid NOT NULL,
    "secret" varchar NOT NULL,
    "provider_profile_api_key" varchar,
    "sender_profile_api_key" uuid,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."atlas_schema_revisions" (
    "version" varchar NOT NULL,
    "description" varchar NOT NULL,
    "type" int8 NOT NULL DEFAULT 2,
    "applied" int8 NOT NULL DEFAULT 0,
    "total" int8 NOT NULL DEFAULT 0,
    "executed_at" timestamptz NOT NULL,
    "execution_time" int8 NOT NULL,
    "error" text,
    "error_stmt" text,
    "hash" varchar NOT NULL,
    "partial_hashes" jsonb,
    "operator_version" varchar NOT NULL,
    PRIMARY KEY ("version")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."ent_types" (
    "id" int8 NOT NULL,
    "type" varchar NOT NULL,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."fiat_currencies" (
    "id" uuid NOT NULL,
    "created_at" timestamptz NOT NULL,
    "updated_at" timestamptz NOT NULL,
    "code" varchar NOT NULL,
    "short_name" varchar NOT NULL,
    "decimals" int8 NOT NULL DEFAULT 2,
    "symbol" varchar NOT NULL,
    "name" varchar NOT NULL,
    "market_rate" float8 NOT NULL,
    "is_enabled" bool NOT NULL DEFAULT false,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."fiat_currency_providers" (
    "fiat_currency_id" uuid NOT NULL,
    "provider_profile_id" varchar NOT NULL,
    PRIMARY KEY ("fiat_currency_id","provider_profile_id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."identity_verification_requests" (
    "id" uuid NOT NULL,
    "wallet_address" varchar NOT NULL,
    "wallet_signature" varchar NOT NULL,
    "platform" varchar NOT NULL,
    "platform_ref" varchar NOT NULL,
    "verification_url" varchar NOT NULL,
    "status" varchar NOT NULL DEFAULT 'pending'::character varying,
    "fee_reclaimed" bool NOT NULL DEFAULT false,
    "updated_at" timestamptz NOT NULL,
    "last_url_created_at" timestamptz NOT NULL,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."institutions" (
    "id" int8 NOT NULL,
    "created_at" timestamptz NOT NULL,
    "updated_at" timestamptz NOT NULL,
    "code" varchar NOT NULL,
    "name" varchar NOT NULL,
    "type" varchar NOT NULL DEFAULT 'bank'::character varying,
    "fiat_currency_institutions" uuid,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."linked_addresses" (
    "id" int8 NOT NULL,
    "created_at" timestamptz NOT NULL,
    "updated_at" timestamptz NOT NULL,
    "address" varchar NOT NULL,
    "salt" bytea NOT NULL,
    "institution" varchar NOT NULL,
    "account_identifier" varchar NOT NULL,
    "account_name" varchar NOT NULL,
    "owner_address" varchar NOT NULL,
    "last_indexed_block" int8,
    "tx_hash" varchar,
    "sender_profile_linked_address" uuid,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."lock_order_fulfillments" (
    "id" uuid NOT NULL,
    "created_at" timestamptz NOT NULL,
    "updated_at" timestamptz NOT NULL,
    "tx_id" varchar NOT NULL,
    "validation_status" varchar NOT NULL DEFAULT 'pending'::character varying,
    "validation_error" varchar,
    "lock_payment_order_fulfillments" uuid NOT NULL,
    "psp" varchar,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."lock_payment_orders" (
    "id" uuid NOT NULL,
    "created_at" timestamptz NOT NULL,
    "updated_at" timestamptz NOT NULL,
    "amount" float8 NOT NULL,
    "rate" float8 NOT NULL,
    "order_percent" float8 NOT NULL,
    "tx_hash" varchar,
    "status" varchar NOT NULL DEFAULT 'pending'::character varying,
    "block_number" int8 NOT NULL,
    "institution" varchar NOT NULL,
    "account_identifier" varchar NOT NULL,
    "account_name" varchar NOT NULL,
    "memo" varchar,
    "cancellation_count" int8 NOT NULL DEFAULT 0,
    "cancellation_reasons" jsonb NOT NULL,
    "provider_profile_assigned_orders" varchar,
    "provision_bucket_lock_payment_orders" int8,
    "token_lock_payment_orders" int8 NOT NULL,
    "gateway_id" varchar NOT NULL,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."networks" (
    "id" int8 NOT NULL,
    "created_at" timestamptz NOT NULL,
    "updated_at" timestamptz NOT NULL,
    "chain_id" int8 NOT NULL,
    "identifier" varchar NOT NULL,
    "rpc_endpoint" varchar NOT NULL,
    "is_testnet" bool NOT NULL,
    "fee" float8 NOT NULL,
    "chain_id_hex" varchar,
    "gateway_contract_address" varchar NOT NULL DEFAULT ''::character varying,
    "bundler_url" varchar,
    "paymaster_url" varchar,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."payment_order_recipients" (
    "id" int8 NOT NULL,
    "institution" varchar NOT NULL,
    "account_identifier" varchar NOT NULL,
    "account_name" varchar NOT NULL,
    "memo" varchar,
    "provider_id" varchar,
    "payment_order_recipient" uuid NOT NULL,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."payment_orders" (
    "id" uuid NOT NULL,
    "created_at" timestamptz NOT NULL,
    "updated_at" timestamptz NOT NULL,
    "amount" float8 NOT NULL,
    "amount_paid" float8 NOT NULL,
    "amount_returned" float8 NOT NULL,
    "sender_fee" float8 NOT NULL,
    "rate" float8 NOT NULL,
    "tx_hash" varchar,
    "receive_address_text" varchar NOT NULL,
    "status" varchar NOT NULL DEFAULT 'initiated'::character varying,
    "api_key_payment_orders" uuid,
    "sender_profile_payment_orders" uuid,
    "token_payment_orders" int8 NOT NULL,
    "from_address" varchar,
    "network_fee" float8 NOT NULL,
    "fee_percent" float8 NOT NULL,
    "fee_address" varchar,
    "percent_settled" float8 NOT NULL,
    "protocol_fee" float8 NOT NULL,
    "gateway_id" varchar,
    "block_number" int8 NOT NULL DEFAULT 0,
    "return_address" varchar,
    "linked_address_payment_orders" int8,
    "reference" varchar,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."provider_order_tokens" (
    "id" int8 NOT NULL,
    "created_at" timestamptz NOT NULL,
    "updated_at" timestamptz NOT NULL,
    "fixed_conversion_rate" float8 NOT NULL,
    "floating_conversion_rate" float8 NOT NULL,
    "conversion_rate_type" varchar NOT NULL,
    "max_order_amount" float8 NOT NULL,
    "min_order_amount" float8 NOT NULL,
    "provider_profile_order_tokens" varchar NOT NULL,
    "address" varchar,
    "network" varchar,
    "fiat_currency_provider_order_tokens" uuid NOT NULL,
    "token_provider_order_tokens" int8 NOT NULL,
    PRIMARY KEY ("id")
);


-- Table Definition
CREATE TABLE "public"."provider_profiles" (
    "id" varchar NOT NULL,
    "trading_name" varchar,
    "host_identifier" varchar,
    "provision_mode" varchar NOT NULL DEFAULT 'auto'::character varying,
    "is_active" bool NOT NULL DEFAULT false,
    "is_available" bool NOT NULL DEFAULT false,
    "updated_at" timestamptz NOT NULL,
    "visibility_mode" varchar NOT NULL DEFAULT 'public'::character varying,
    "address" text,
    "mobile_number" varchar,
    "date_of_birth" timestamptz,
    "business_name" varchar,
    "identity_document_type" varchar,
    "identity_document" varchar,
    "business_document" varchar,
    "user_provider_profile" uuid NOT NULL,
    "is_kyb_verified" bool NOT NULL DEFAULT false,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."provider_ratings" (
    "id" int8 NOT NULL,
    "created_at" timestamptz NOT NULL,
    "updated_at" timestamptz NOT NULL,
    "trust_score" float8 NOT NULL,
    "provider_profile_provider_rating" varchar NOT NULL,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."provision_bucket_provider_profiles" (
    "provision_bucket_id" int8 NOT NULL,
    "provider_profile_id" varchar NOT NULL,
    PRIMARY KEY ("provision_bucket_id","provider_profile_id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."provision_buckets" (
    "id" int8 NOT NULL,
    "min_amount" float8 NOT NULL,
    "max_amount" float8 NOT NULL,
    "created_at" timestamptz NOT NULL,
    "fiat_currency_provision_buckets" uuid NOT NULL,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."receive_addresses" (
    "id" int8 NOT NULL,
    "created_at" timestamptz NOT NULL,
    "updated_at" timestamptz NOT NULL,
    "address" varchar NOT NULL,
    "salt" bytea NOT NULL,
    "status" varchar NOT NULL DEFAULT 'unused'::character varying,
    "last_indexed_block" int8,
    "last_used" timestamptz,
    "valid_until" timestamptz,
    "payment_order_receive_address" uuid,
    "tx_hash" varchar,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."sender_order_tokens" (
    "id" int8 NOT NULL,
    "created_at" timestamptz NOT NULL,
    "updated_at" timestamptz NOT NULL,
    "fee_percent" float8 NOT NULL,
    "fee_address" varchar NOT NULL,
    "refund_address" varchar NOT NULL,
    "sender_profile_order_tokens" uuid NOT NULL,
    "token_sender_settings" int8 NOT NULL,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."sender_profiles" (
    "id" uuid NOT NULL,
    "webhook_url" varchar,
    "domain_whitelist" jsonb NOT NULL,
    "is_active" bool NOT NULL DEFAULT false,
    "updated_at" timestamptz NOT NULL,
    "user_sender_profile" uuid NOT NULL,
    "is_partner" bool NOT NULL DEFAULT false,
    "provider_id" varchar,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."tokens" (
    "id" int8 NOT NULL,
    "created_at" timestamptz NOT NULL,
    "updated_at" timestamptz NOT NULL,
    "symbol" varchar NOT NULL,
    "contract_address" varchar NOT NULL,
    "decimals" int2 NOT NULL,
    "is_enabled" bool NOT NULL DEFAULT false,
    "network_tokens" int8 NOT NULL,
    "base_currency" varchar NOT NULL DEFAULT 'USD'::character varying,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."transaction_logs" (
    "created_at" timestamptz NOT NULL,
    "gateway_id" varchar,
    "status" varchar NOT NULL DEFAULT 'order_initiated'::character varying,
    "network" varchar,
    "tx_hash" varchar,
    "metadata" jsonb NOT NULL,
    "id" uuid NOT NULL,
    "lock_payment_order_transactions" uuid,
    "payment_order_transactions" uuid,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."users" (
    "id" uuid NOT NULL,
    "created_at" timestamptz NOT NULL,
    "updated_at" timestamptz NOT NULL,
    "first_name" varchar NOT NULL,
    "last_name" varchar NOT NULL,
    "email" varchar NOT NULL,
    "password" varchar NOT NULL,
    "scope" varchar NOT NULL,
    "is_email_verified" bool NOT NULL DEFAULT false,
    "has_early_access" bool NOT NULL DEFAULT false,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."verification_tokens" (
    "id" uuid NOT NULL,
    "created_at" timestamptz NOT NULL,
    "updated_at" timestamptz NOT NULL,
    "token" varchar NOT NULL,
    "scope" varchar NOT NULL,
    "expiry_at" timestamptz NOT NULL,
    "user_verification_token" uuid NOT NULL,
    PRIMARY KEY ("id")
);

-- Table Definition
CREATE TABLE IF NOT EXISTS "public"."webhook_retry_attempts" (
    "id" int8 NOT NULL,
    "created_at" timestamptz NOT NULL,
    "updated_at" timestamptz NOT NULL,
    "attempt_number" int8 NOT NULL,
    "next_retry_time" timestamptz NOT NULL,
    "payload" jsonb NOT NULL,
    "signature" varchar,
    "webhook_url" varchar NOT NULL,
    "status" varchar NOT NULL DEFAULT 'failed'::character varying,
    PRIMARY KEY ("id")
);

INSERT INTO "public"."atlas_schema_revisions" ("version", "description", "type", "applied", "total", "executed_at", "execution_time", "error", "error_stmt", "hash", "partial_hashes", "operator_version") VALUES
('.atlas_cloud_identifier', '77ef936e-d384-408b-b363-3b95743c8bb3', 2, 0, 0, '2024-02-18 01:12:21.871752+00', 0, NULL, NULL, '', NULL, 'Atlas CLI v0.18.1-6561539-canary'),
('20240220003618', 'add_is_kyb_verified', 1, 0, 0, '2024-03-07 22:22:40.184837+00', 0, '', '', '', NULL, 'Atlas CLI v0.18.1-6561539-canary'),
('20240326145227', 'has_early_access', 2, 1, 1, '2024-03-26 14:53:02.381127+00', 301180667, '', '', '7DYQAuJJeHMw0FjA9G5Sv5CTmwyOZxaPdfJHZmq2EAs=', '["h1:HOlQ96+/HCxiyYQ03C4lQbSoOZvwCTj6ZQigXhJEw34="]', 'Atlas CLI v0.20.1-99eab66-canary'),
('20240404065157', 'add_gateway_id', 2, 2, 2, '2024-04-04 06:52:15.135364+00', 277346875, '', '', '9STQPRr3OXQ+1zYd/3+IOJlgSaFRdqV+Rh/6Ti9McmA=', '["h1:m5U1eZBDhclk4ywOUHJG6drB30czbifTl8geyZsZLv8=", "h1:V73dVDQU1CxajHyjBroIPap4hf/gljWrsoKVZcd1pgo="]', 'Atlas CLI v0.20.1-99eab66-canary'),
('20240404231425', 'add_fee_to_network', 2, 1, 1, '2024-04-05 04:09:52.822275+00', 278361542, '', '', 'Wq2M7TH7QilJ5k/1rMOstnDagw5E+vr0WrAPhMTn0Fc=', '["h1:aDSnFyhhl0S7DvZKtUA1D+osuzV2lYCZcj303PLL6dU="]', 'Atlas CLI v0.20.1-99eab66-canary'),
('20240414002738', 'payment_order_block_number', 2, 2, 2, '2024-04-14 00:36:57.946777+00', 305331417, '', '', 'r5bHvVEdxltzfgQ3RggfgRUzSs8d7jLeLSCwfImb3DY=', '["h1:H44GTAifVD/+r9FMRhHaSIf4kiLuhhtUl9TbHC0ElQQ=", "h1:CkTM5Q51tSM/bvCEEn9ZmMQ0Yn18za3jBDKsbUFAkEo="]', 'Atlas CLI v0.20.1-99eab66-canary'),
('20240416055001', 'chain_id_hex', 2, 1, 1, '2024-04-16 05:51:06.701322+00', 300647959, '', '', '6NUaokKTGwj3YZ4zaEMbYZueiZsEn2/MnkiwLZuK56o=', '["h1:1xNiJgmRhHvsAgfeL3fEnsUNbZX18++fXWunwJunJw8="]', 'Atlas CLI v0.20.1-99eab66-canary'),
('20240421230634', 'add_return_address', 2, 1, 1, '2024-04-21 23:28:23.612706+00', 288331541, '', '', '/4a1d784HzkPTYruYacw324unCPb+WqFVpBtQSMAIbU=', '["h1:ZSNPUAlVOBuZhjjcBLQ2nRTUlBK8sQ93cHSGKQzac+c="]', 'Atlas CLI v0.20.1-99eab66-canary'),
('20240610130003', 'add_transaction_log', 2, 2, 2, '2024-06-12 04:13:52.855008+00', 290314334, '', '', 'sfSDmm6BlZ3VJLvdQiCBVtv1DLNxvO+XWYn2ifU5Eaw=', '["h1:xKnvlZdl796rihdM2gUzBKZ1vL7peKtU2/Eu9qiQbmI=", "h1:jKdL72djFz62nKd1tn77NtpJInvheLXJi4uvm5LpbXs="]', 'Atlas CLI v0.20.1-99eab66-canary'),
('20240613025318', 'network_gateway_address', 2, 2, 2, '2024-06-13 03:33:41.694496+00', 319610500, '', '', 'X0ZttslKQKalRn7+KgSYx0kckAr7e4L4dbUUoEJT3iU=', '["h1:sHqRDZqdWcgQEdfdOYT1NOfrSNX03yKjc/dReSXo5mQ=", "h1:QUzasPultb8+MEk222EPMEUBtcD8aIVNKHBIVdOrnIw="]', 'Atlas CLI v0.20.1-99eab66-canary'),
('20240613142908', 'add_institution', 2, 3, 3, '2024-06-13 14:49:45.210131+00', 286927375, '', '', 'VHmIvmMsP7dfWEl+VqOtPSdPsbDXufSezJgDsJQ1rVc=', '["h1:jvYSna+7oOCCJeE9h+EiTqYMx7CipZn+1ev7BrhNiRg=", "h1:NikZHEMuegdUs+bIUzvShSsVCdhKPqPfSu0hDwzqH9E=", "h1:Uykz1Sqs/B7fmcghrWIjH5h0m6z4xYoJRpmLoLT0jZQ="]', 'Atlas CLI v0.20.1-99eab66-canary'),
('20240613143010', 'ngn_institutions', 2, 2, 2, '2024-06-13 14:49:48.69751+00', 279372708, '', '', 'YI8YUHyX6qP94ggCHQglYnMHYtLkSTVRUI25eLbP1Nw=', '["h1:PzrmG789uKAELCcW7w6bNpnAOgaIPdP46uHwVKj1qyE=", "h1:n6IIq+isMTclpGMrwDA/n9TVVIeaI0YnY/+Z7KOsqP4="]', 'Atlas CLI v0.20.1-99eab66-canary'),
('20240626125532', 'sender_order_tokens', 2, 4, 4, '2024-06-26 12:57:07.075239+00', 295040667, '', '', 'BWvJmKMLgp8jrhYZVU47QLs12osTuaRkgkOWB351v2s=', '["h1:qavccheWTRrT3EeviAwInNTOe+5wRcNlcxChl1Ou/q0=", "h1:iKbtiInYqx0nHy+irYJTV25qNn5tWr0XwvALAhSFafI=", "h1:1RG9W8XX40sUuugmFZc1E+Fi/4Yfrjm5gkrEC067kZQ=", "h1:D2uho29o9lKKrXxpIEAuFOOaFFbRZM9ivpgrGYiLcxY="]', 'Atlas CLI v0.20.1-99eab66-canary'),
('20240807013441', 'add_psp_to_fulfillment', 2, 1, 1, '2024-08-10 02:38:10.41944+00', 292226667, '', '', 'C1rDzjWQcN5Bi2HJB/+E087+zwTLZ0IfBol7rfcoKx4=', '["h1:rNHKClqvogggGZ63Wdo23HFZhOBASgxvW3Z7d30OyCg="]', 'Atlas CLI v0.25.1-810278b-canary'),
('20240820211511', 'unique_gateway_id', 2, 2, 2, '2024-08-20 21:34:04.32869+00', 286489834, '', '', 'Q2q1pDpPNSUTt4zWpuMFAU+CqWMrTwagnRM8hmPlrwQ=', '["h1:qyiVtqYdKJyHO6HIjQWf/c84noKFNB/VRypy+OEXzY8=", "h1:gQ2+XVqa2Lbq84qahh6bN5lnPtWemcqhooSyWXblfF4="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240820215151', 'multi_fulfillments', 2, 3, 3, '2024-08-21 12:02:48.60742+00', 299475333, '', '', 'tzIAvIUZ9IgzO+6Df6uicRybclEKDjbXs6bcUWb0/WI=', '["h1:SzNoFPUm27tEobpS0zYpx4jK3d3TsglY94IAeqvZg8Y=", "h1:yFR8CfaxB0iQIYUSLB1I9IbdvEG9YGyfm720g/J1BL0=", "h1:Q1ViI6tpbFokfbVi3jgI7zzCWEUP2H3+Dp7KVNcnJeA="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240822020854', 'fee_percent', 2, 2, 2, '2024-08-22 18:33:19.119246+00', 301367375, '', '', 'Vl6hO6F/+czwgJ1C+7Xb00UgCJhHd7DqVLZ4dcZNUcY=', '["h1:3wSFFuDQWjGMS1FOS9/FRxcUgnRIAuw0hraXeI3dVrQ=", "h1:jkszuCKfXMgrdDSODvxw8u04GyqpGvIjSbzEnoCHsFY="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240831223804', 'add_fiat_currencies_1', 2, 6, 6, '2024-09-01 00:35:19.568068+00', 283170959, '', '', 'CPRpvs4yry+3CP8Qjy3bCzkPMo5m+LyuVqAxLJ43onw=', '["h1:CSyOZ1s07wGh6w5or4zLah2Mk+u0/8bXzvQmzQ2t9RA=", "h1:6wKbya5c4gQJuf2CJLRbNcuXPgMuAoEmuwnDAGaQ4fw=", "h1:VGfW/tidcf+rREjXXqTGj7aCyvk2zd3D71lmIpgEPsA=", "h1:nBj7biVJOzuwo5EfTjuwVt/L0t/u/wKgdQWOj0ezrP8=", "h1:wtTWagMUsxc6+4JnQ+QXqA2rBc5950sYq483FwXNfcY=", "h1:rsnrHy1Lyi8hDZUAS8ZZfAjlQk6SAugQIhGwpKtqdMI="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240831223854', 'kes_institutions', 2, 2, 2, '2024-09-01 00:35:24.303823+00', 294086750, '', '', 'M5o0bnkVwRVEVkyi9sGANGqrC+0BiJp39v1BVHXfB5Y=', '["h1:HDHINjps7Kuv80rVSFPtEvqqx/JNj9YYFv7z5yNJnko=", "h1:RQLCrvV8WK0TAw88IceqB8FjByOgfHcT5HmREQgOfi8="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240831231010', 'ugx_institutions', 2, 2, 2, '2024-09-01 00:35:27.394166+00', 300459792, '', '', 'SnvPjrS4We2McfB0lHlb9nZdhhaPI5XCypUGi2oTjVQ=', '["h1:jpwNQc8Iy/ISM2ZW64FaLkTo/+taYnPyw7BsbZNvYeo=", "h1:FY0bQ7ZvICZH3zSQJoameZG3Sy5L/V37RomIRLO+eOA="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240831231410', 'tzs_institutions', 2, 2, 2, '2024-09-01 00:35:30.54768+00', 299726166, '', '', 'sSgJzP3e8Qsp6tvIfXR0m1babfJxlsF+WEvCP3yvwfM=', '["h1:SWYCGBMW52v1yn+puMP3udw2sid+oJ/OZGrloHXuY18=", "h1:zByGk28+xJ7k7ITjRD1haLTq/JimAcx8RPo9wGhwgH4="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240831231510', 'xofben_institutions', 2, 2, 2, '2024-09-01 00:35:33.658741+00', 293179334, '', '', 'iJ/IxrwV3j6UA9RoN6MfGp33EuNpp6dYi0s8vP+cA3c=', '["h1:tHcmU3/gwQ6jeDWGsikn4yE0G2u2NJ8sedK3MmDqAQk=", "h1:kMv+d+xciH7esuFvu6uMT/J2u6Epnf0RohJHFSipzH4="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240831231600', 'xofciv_institutions', 2, 2, 2, '2024-09-01 00:35:36.782463+00', 287086458, '', '', 'vWNVTOIuLNNSp+iJIjz56m1iBgtkHd98C9xb0xhnfqw=', '["h1:W0C/whVTRaV588pus/LVOSpFiTm2cxTWZRJO1o2rsQA=", "h1:RfI4DQXAv3jAbkrChfNmJiRWkROuspdrCaqn9yPHxZc="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240831235010', 'ghs_institutions', 2, 2, 2, '2024-09-01 00:38:29.536611+00', 274469500, '', '', 'ZJOc32/coqZ/PA0oeG82e9pqI4euEiqQDt0+KijjMzE=', '["h1:ruCC37ZLt9kFAE+zbhrZ7w7T2VH7Uo6xY1SHlIcfeYs=", "h1:yVuCVNx+7WfYRsY/lD8wOL0m2WQK59vpdHHHIvQI4Y4="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240905170202', 'sender_provider_id', 2, 2, 2, '2024-09-05 17:06:17.296744+00', 307672709, '', '', 'TIesYeIISWyfL1DZhEwBhfiA1EW2Qqf/DF4n7M4gPa0=', '["h1:YCXetRnyFtRsIbZ7MybjK5EYj3yuTznIEia55DnTDn0=", "h1:CAwmTWpPYudmRnlAbNCZApEmZpMdedWp/0UAdHS/b1Y="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240919231535', 'gateway_id_not_unique', 2, 1, 1, '2024-09-20 00:12:07.046865+00', 331627833, '', '', 'AXYjKRqkEiGuMDnSSau5gbDzRqPupsgTfiXr9bEeeF4=', '["h1:b2HKY+VWJwlKi98t3yC8cA9iOGQ5AMpSZxi1rFFn5pc="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240921140012', 'lockpaymentorder_indexes', 2, 1, 1, '2024-09-21 17:51:50.287067+00', 288178875, '', '', 'f7OcEP0F0fPaOj+pb/FjsEKmLlo4T4YemG1ix6ixU7g=', '["h1:UrO9pmOt/W7lvIZZY8uGgLdbJBxZ+81QFp7lNG+cVUw="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240921162100', 'paymentorder_triggers', 2, 3, 3, '2024-09-21 17:51:52.945169+00', 289008833, '', '', 'gA39sUR/l5BxGAgoq6NT2MyE2eiCqkGOoDsbFkMG7+k=', '["h1:N+D7/ywT57XH8TpWdc5XhdyA7oz0HXLjmrmlnKixyOE=", "h1:R0V/IjqdO6ECHfiGCifPodhEG/tKGE7C4xJMlVMmurY=", "h1:yqso52Tr9SXM9sfugl5nk5Qx/MLLVL0wWH/zDl9mFwQ="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240921194100', 'fix_paymentorder_triggers', 2, 6, 6, '2024-09-24 04:19:28.201612+00', 311619041, '', '', 'tmrnbzbGIQbfA79JMZRFcc8LH0LYnb/2SfCjPDkNd7M=', '["h1:jwdPJaETJUZXcqPK7wDCqEQV2CetgVSKANUOOIlQh4Q=", "h1:JpDyX3m19ndoL8FQ8uvcULUP0/0NZ5bjn0QkrQt+/AQ=", "h1:sdcreIbM4t96rH8HXGxDypRLxgI/0X19/fE1B+TV/MI=", "h1:K+Xi3LMOM1NLjVlWRxsPI6IKwTMI/lqvP69yo+bPcew=", "h1:PC8Qua7m8iFHjbd712QYeo9xX6MeotpF4rZKxdAl8IA=", "h1:AH4NEa6KY/jPXtSTTuKVxYh/q6tdzRUZwW5xLDXdiXg="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240921200000', 'fix_round_func', 2, 6, 6, '2024-09-24 04:19:33.169879+00', 303769083, '', '', 'mR1A+YVNZB2Yv1/zBMS+vLlQqNe6Fq7P53xAgW7hHg8=', '["h1:jwdPJaETJUZXcqPK7wDCqEQV2CetgVSKANUOOIlQh4Q=", "h1:JpDyX3m19ndoL8FQ8uvcULUP0/0NZ5bjn0QkrQt+/AQ=", "h1:sdcreIbM4t96rH8HXGxDypRLxgI/0X19/fE1B+TV/MI=", "h1:pdGH0J0thYEk1IE0v9TfLwyqz48vEg+pVSSEzR9/QqY=", "h1:LlYBWOxrgOOCTsC4aChyISn5+zN8n/b7T2Vm5o0cvno=", "h1:JaGIC7j1ENUX09ys2BCAsXrNkg+z5mx5Tgo/eoXRaVE="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240921203200', 'fix_round_func_2', 2, 6, 6, '2024-09-24 04:19:38.137477+00', 298740917, '', '', 'k9ktbooFfvawpcH0YWFMjD1HUOH4HH1fdjRxHCdnN1g=', '["h1:jwdPJaETJUZXcqPK7wDCqEQV2CetgVSKANUOOIlQh4Q=", "h1:JpDyX3m19ndoL8FQ8uvcULUP0/0NZ5bjn0QkrQt+/AQ=", "h1:sdcreIbM4t96rH8HXGxDypRLxgI/0X19/fE1B+TV/MI=", "h1:ruliQRXWzxi+64xciW4xfZwi/xokJv+p3uZ0U+7PoGk=", "h1:oIKiaPbKZVLQINj4uZTulbIQKICv9Rgjdy+1y1Gn1Ow=", "h1:ZQWvEyFsPi0mVfktzzZRbosXbUBcBwwxD+idqjKc26A="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240921215500', 'fix_round_func_3', 2, 6, 6, '2024-09-24 04:19:43.27777+00', 303857750, '', '', 'xi7V+CK3pPh0nHHTzQLDUGjOratBuAtN3Hs3xB3f2mg=', '["h1:jwdPJaETJUZXcqPK7wDCqEQV2CetgVSKANUOOIlQh4Q=", "h1:JpDyX3m19ndoL8FQ8uvcULUP0/0NZ5bjn0QkrQt+/AQ=", "h1:sdcreIbM4t96rH8HXGxDypRLxgI/0X19/fE1B+TV/MI=", "h1:ruliQRXWzxi+64xciW4xfZwi/xokJv+p3uZ0U+7PoGk=", "h1:MMYSDf/iqTfKQYbtKKAwllx5nxbr9l5rSA6TYPJ4BwU=", "h1:ExKIdLWT6YvJ3OGYzfMZ7cvD4ssTpW7ybtvNsdC3erU="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240921224500', 'fix_round_func_4', 2, 6, 6, '2024-09-24 04:19:48.284856+00', 298840375, '', '', 'hz+6zAhCKOx0cfiTkfEqjSqGt/bX+KGnfdQe1T7zZtA=', '["h1:jwdPJaETJUZXcqPK7wDCqEQV2CetgVSKANUOOIlQh4Q=", "h1:JpDyX3m19ndoL8FQ8uvcULUP0/0NZ5bjn0QkrQt+/AQ=", "h1:sdcreIbM4t96rH8HXGxDypRLxgI/0X19/fE1B+TV/MI=", "h1:ruliQRXWzxi+64xciW4xfZwi/xokJv+p3uZ0U+7PoGk=", "h1:RotpNKW8Y5X1Qqv6cPSE4eYAPTHGYga4agmUQ9XbYEY=", "h1:jLcfmkM3hU/8MHTzzdtAP80I5Ej4tR8lZP2BUooYUV0="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240921225500', 'fix_round_func_5', 2, 6, 6, '2024-09-24 04:19:53.255444+00', 298837083, '', '', 'HiM4roZT0QzRQ16+EmLoKTsUeIF9wrwZxp+dYCcPKS4=', '["h1:jwdPJaETJUZXcqPK7wDCqEQV2CetgVSKANUOOIlQh4Q=", "h1:JpDyX3m19ndoL8FQ8uvcULUP0/0NZ5bjn0QkrQt+/AQ=", "h1:sdcreIbM4t96rH8HXGxDypRLxgI/0X19/fE1B+TV/MI=", "h1:ruliQRXWzxi+64xciW4xfZwi/xokJv+p3uZ0U+7PoGk=", "h1:tsUZP363tQTU7mTkp1IJWAmIrKwxKhUEEm9K9mqWBMQ=", "h1:k1EUJ74jGznRdm3i3rqzCr+mYBtcGeeDToJEN4VycMI="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240924051600', 'fix_round_func_6', 2, 6, 6, '2024-09-24 04:19:58.505575+00', 292255792, '', '', 'oh7hLKl2ts+4nSHakFwMUsYjDnIJc5cFn2xK+ngcjF8=', '["h1:jwdPJaETJUZXcqPK7wDCqEQV2CetgVSKANUOOIlQh4Q=", "h1:JpDyX3m19ndoL8FQ8uvcULUP0/0NZ5bjn0QkrQt+/AQ=", "h1:sdcreIbM4t96rH8HXGxDypRLxgI/0X19/fE1B+TV/MI=", "h1:ruliQRXWzxi+64xciW4xfZwi/xokJv+p3uZ0U+7PoGk=", "h1:z0M/bu+ys3mmLlvLLc2SWQnRx8migw3q+h4T4b21pZY=", "h1:kGEOZfVt8g53Hiw6phv7XQJcyh1O05WYI1iw8YYl/O8="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20240926223529', 'id_verification', 2, 4, 4, '2024-10-01 04:28:53.072766+00', 304730292, '', '', 'aYhhfCFcEgL5Vn0+H68EyIhA94LeKX+2H+XIi8lg7ls=', '["h1:n5AWgmubgkV26Qk4Ed5oSyQ7YnHxd70jy6Yn9zVGbJA=", "h1:bE/C6TvotaZepzaRvTmJqsemnG4FeNbBVYAVx2CWCNg=", "h1:TDt/xzFm+D2n9i8ZivRy7uaokkzWQ1Iyzh2AKSuEL5o=", "h1:5VKoGdduW4Haiz5+H0Wzt5a/dZofKtrD04Dz2vsx7gY="]', 'Atlas CLI v0.26.1-363dc46-canary'),
('20241011010524', 'linked_addresses', 2, 6, 6, '2024-10-11 22:54:25.123545+00', 315099583, '', '', 'JvCXlyrRTwXqYPwz5YoGoh+/KEaGiswxmRp//wyxyhU=', '["h1:dn26phMD/ZP4udc2BqFgrBwkvXcfSL7A6prOOzAL0Ww=", "h1:0G/LPHcytSmVRGdedOSMQYlwpECu2JZPTSrHFdDiHXI=", "h1:x7JUeBTLYw8HD5nVU8ZHkzu5yiZVKPumCMAev/I1oas=", "h1:9u7SKlgwr5bl8s0mETRVFmV+wDGHw1m+jGJiwftz/ek=", "h1:oCwIO9D/qxXbe91FAG1AIeHhbIxGEwCy38sLWer4c0g=", "h1:p4/MVC8p5Uf11/5u1TVNxaIz18A512dVed+xhmyxN5Q="]', 'Atlas CLI v0.28.2-b924c5b-canary'),
('20241226183354', 'add_reference', 2, 1, 1, '2024-12-26 18:36:44.696672+00', 327627000, '', '', 'oS3oVJcfD6q7EvDQrTWudCEf3HjBm/yI8XTlPvGqLC8=', '["h1:VeyQNskvtRecBTjMrZA55ZrYJ5DjvZWr4xk3bMyJQTI="]', 'Atlas CLI v0.28.2-b924c5b-canary');

INSERT INTO "public"."ent_types" ("id", "type") VALUES
(1, 'api_keys'),
(2, 'fiat_currencies'),
(3, 'lock_order_fulfillments'),
(4, 'lock_payment_orders'),
(5, 'networks'),
(6, 'payment_orders'),
(7, 'payment_order_recipients'),
(8, 'provider_order_tokens'),
(9, 'provider_profiles'),
(10, 'provider_ratings'),
(11, 'provision_buckets'),
(12, 'receive_addresses'),
(13, 'sender_profiles'),
(14, 'tokens'),
(15, 'users'),
(16, 'verification_tokens'),
(17, 'webhook_retry_attempts'),
(18, 'transaction_logs'),
(19, 'institutions'),
(20, 'sender_order_tokens'),
(21, 'identity_verification_requests'),
(22, 'linked_addresses'),
(23, 'provision_bucket_provider_profiles');

INSERT INTO "public"."fiat_currencies" ("id", "created_at", "updated_at", "code", "short_name", "decimals", "symbol", "name", "market_rate", "is_enabled") VALUES
('5a349408-ebcf-4c7e-98c7-46b6596e0b27', '2024-02-03 23:54:31.693539+00', '2025-01-21 18:00:00.665002+00', 'NGN', 'Naira', 2, '₦', 'Nigerian Naira', 1658.1, 't'),
('9adbbdce-0d98-4c2d-81d8-789e291ad589', '2024-09-01 00:35:18.248882+00', '2024-09-01 00:35:18.248882+00', 'XOF-BEN', 'Céfa Benin', 2, 'CFA', 'West African CFA franc', 599.5, 'f'),
('9e8b5fde-4ec0-4867-940a-64e79af8157d', '2024-09-01 00:35:18.248882+00', '2024-09-01 00:35:18.248882+00', 'TZS', 'TZS', 2, 'TSh', 'Tanzanian Shilling', 3716.44, 'f'),
('a87437e3-cfe5-4033-9978-26ae1238821d', '2024-09-01 00:35:18.248882+00', '2024-09-01 00:35:18.248882+00', 'UGX', 'UGX', 2, 'USh', 'Ugandan Shilling', 3716.44, 'f'),
('bdd94af2-1d65-4ed2-9072-cfa656677686', '2024-09-01 00:35:18.248882+00', '2024-09-01 00:35:18.248882+00', 'XOF-CIV', 'Côte d''Ivoire', 2, 'CFA', 'West African CFA franc', 599.5, 'f'),
('e89be396-0e0e-40fc-ac03-08691b566f75', '2024-09-01 00:35:18.248882+00', '2024-09-01 00:35:18.248882+00', 'GHS', 'Cedi', 2, 'GH¢', 'Ghana Cedi', 15.65, 'f'),
('e9325102-6be5-47a7-89d0-8bbeecacb3bc', '2024-09-01 00:35:18.248882+00', '2025-01-21 18:00:00.359014+00', 'KES', 'KES', 2, 'KSh', 'Kenyan Shilling', 130.005, 't');

INSERT INTO "public"."fiat_currency_providers" ("fiat_currency_id", "provider_profile_id") VALUES
('5a349408-ebcf-4c7e-98c7-46b6596e0b27', 'AtGaDPqT');

INSERT INTO "public"."institutions" ("id", "created_at", "updated_at", "code", "name", "type", "fiat_currency_institutions") VALUES
(77309411328, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'ABNGNGLA', 'Access Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411329, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'DBLNNGLA', 'Diamond Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411330, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'FIDTNGLA', 'Fidelity Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411331, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'FCMBNGLA', 'FCMB', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411332, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'FBNINGLA', 'First Bank Of Nigeria', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411333, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'GTBINGLA', 'Guaranty Trust Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411334, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'PRDTNGLA', 'Polaris Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411335, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'UBNINGLA', 'Union Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411336, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'UNAFNGLA', 'United Bank for Africa', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411337, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'CITINGLA', 'Citibank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411338, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'ECOCNGLA', 'Ecobank Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411339, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'HBCLNGLA', 'Heritage', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411340, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'PLNINGLA', 'Keystone Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411341, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'SBICNGLA', 'Stanbic IBTC Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411342, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'SCBLNGLA', 'Standard Chartered Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411343, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'NAMENGLA', 'Sterling Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411344, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'ICITNGLA', 'Unity Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411345, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'SUTGNGLA', 'Suntrust Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411346, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'PROVNGLA', 'Providus Bank ', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411347, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'KDHLNGLA', 'FBNQuest Merchant Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411348, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'GMBLNGLA', 'Greenwich Merchant Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411349, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'FSDHNGLA', 'FSDH Merchant Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411350, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'FIRNNGLA', 'Rand Merchant Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411351, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'JAIZNGLA', 'Jaiz Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411352, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'ZEIBNGLA', 'Zenith Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411353, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'WEMANGLA', 'Wema Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411354, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'KUDANGPC', 'Kuda Microfinance Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411355, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'OPAYNGPC', 'OPay', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411356, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'MONINGPC', 'Moniepoint Microfinance Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411357, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'PALMNGPC', 'PalmPay', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411358, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'SAHVNGPC', 'Safehaven Microfinance Bank', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411359, '2024-06-13 14:49:47.76094+00', '2024-06-13 14:49:47.76094+00', 'PAYTNGPC', 'Paystack-Titan MFB', 'bank', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(77309411360, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'KCBLKENX', 'Kenya Commercial Bank', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411361, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'SCBLKENX', 'Standard Chartered Kenya', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411362, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'CITIKENA', 'Citi Bank', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411363, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'DTKEKENA', 'Diamond Trust Bank', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411364, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'BARCKENX', 'ABSA Bank Kenya', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411365, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'MIEKKENA', 'Middle East Bank', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411366, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'EQBLKENA', 'Equity Bank', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411367, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'BARBKENA', 'Bank of Baroda', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411368, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'AFRIKENX', 'Bank of Africa', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411369, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'SBICKENX', 'Stanbic Bank Kenya', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411370, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'ABCLKENA', 'African Bank Corporation Limited', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411371, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'ECOCKENA', 'Ecobank Transnational Inc.', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411372, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'CRMFKENA', 'Caritas Microfinance Bank', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411373, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'PAUTKENA', 'Paramount Bank', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411374, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'CIFIKENA', 'Kingdom Bank Limited', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411375, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'GTBIKENA', 'Guaranty Trust Holding Company PLC', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411376, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'FABLKENA', 'Family Bank', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411377, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'CBAFKENX', 'National Commercial Bank of Africa', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411378, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'CONKKENA', 'Consolidated Bank Kenya', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411379, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'HFCOKENA', 'Housing finance Company', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411380, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'MYBKKENA', 'Commercial International Bank Kenya Limited', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411381, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'GAFRKENA', 'Gulf African Bank', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411382, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'FCBAKEPC', 'First Community Bank', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411383, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'DUIBKENA', 'Dubai Islamic Bank', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411384, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'KWMIKENX', 'Kenya Women Microfinance Bank', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411385, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'FAUMKENA', 'Faulu Bank', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411386, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'PRIEKENX', 'Prime Bank Limited', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411387, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'CRBTKENA', 'Credit Bank Limited', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411388, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'UNAIKEPC', 'Unaitas Sacco', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411389, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'GUARKENA', 'Guardian Bank Limited', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411390, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'IMBLKENA', 'Investments & Morgage Limited', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411391, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'SIDNKENA', 'Sidian Bank', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411392, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'UNAFKENA', 'United Bank for Africa', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411393, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'KCOOKENA', 'Cooperative Bank of Kenya', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411394, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'CHFIKENX', 'Choice Microfinance Bank Kenya Limited', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411395, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'STIMKEPC', 'Stima SACCO', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411396, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'NBKEKENX', 'National Bank of kenya', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411397, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'VICMKENA', 'Victoria Commercial Bank', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411398, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'MORBKENA', 'Oriental Commercial Bank Limited', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411399, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'SBMKKENA', 'SBM Bank Kenya', 'bank', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411400, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'SAFAKEPC', 'SAFARICOM', 'mobile_money', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411401, '2024-09-01 00:35:23.010297+00', '2024-09-01 00:35:23.010297+00', 'AIRTKEPC', 'AIRTEL', 'mobile_money', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(77309411402, '2024-09-01 00:35:26.071436+00', '2024-09-01 00:35:26.071436+00', 'MOMOUGPC', 'MTN Mobile Money', 'mobile_money', 'a87437e3-cfe5-4033-9978-26ae1238821d'),
(77309411403, '2024-09-01 00:35:26.071436+00', '2024-09-01 00:35:26.071436+00', 'AIRTUGPC', 'Airtel Money', 'mobile_money', 'a87437e3-cfe5-4033-9978-26ae1238821d'),
(77309411404, '2024-09-01 00:35:29.216692+00', '2024-09-01 00:35:29.216692+00', 'TIGOTZPC', 'Tigo Pesa', 'mobile_money', '9e8b5fde-4ec0-4867-940a-64e79af8157d'),
(77309411405, '2024-09-01 00:35:29.216692+00', '2024-09-01 00:35:29.216692+00', 'AIRTTZPC', 'Airtel Money', 'mobile_money', '9e8b5fde-4ec0-4867-940a-64e79af8157d'),
(77309411406, '2024-09-01 00:35:32.36934+00', '2024-09-01 00:35:32.36934+00', 'MOMOBJPC', 'MTN Mobile Money', 'mobile_money', '9adbbdce-0d98-4c2d-81d8-789e291ad589'),
(77309411407, '2024-09-01 00:35:35.485581+00', '2024-09-01 00:35:35.485581+00', 'MOMOCIPC', 'MTN Mobile Money', 'mobile_money', 'bdd94af2-1d65-4ed2-9072-cfa656677686'),
(77309411408, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'HFCAGHAC', 'REPUBLIC BANK', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411409, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'BAGHGHAC', 'BANK OF GHANA', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411410, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'STBGGHAC', 'UBA GHANA', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411411, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'FBLIGHAC', 'FIDELITY BANK GHANA', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411412, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'CBGHGHAC', 'Consolidated Bank Ghana', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411413, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'MBGHGHAC', 'Universal Merchant Bank', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411414, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'AREXGHAC', 'APEX BANK', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411415, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'OMBLGHAC', 'OMNI BANK', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411416, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'NIBGGHAC', 'National Investment Bank Limited', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411417, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'ADNTGHAC', 'Agricultural Development Bank', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411418, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'ZEBLGHAC', 'ZENITH BANK GHANA', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411419, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'ZEEPGHPC', 'ZEEPAY GHANA', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411420, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'SBICGHAC', 'STANBIC BANK GHANA', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411421, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'SCBLGHAC', 'STANDARD CHARTERED GHANA', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411422, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'SISLGHPC', 'SERVICES INTEGRITY SAVINGS & LOANS', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411423, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'BARCGHAC', 'ABSA BANK GHANA', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411424, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'FAMCGHAC', 'First Atlantic Bank GHANA', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411425, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'ABNGGHAC', 'ACCESS BANK GHANA', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411426, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'FIRNGHAC', 'First National Bank', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411427, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'GMONGHPC', 'G-MONEY', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411428, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'GHCBGHAC', 'GCB Bank Limited', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411429, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'GHLLGHPC', 'Ghl Bank Limited', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411430, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'AMMAGHAC', 'Bank of Africa Ghana Limited', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411431, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'PUBKGHAC', 'Prudential Bank Limited', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411432, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'INCEGHAC', 'FBNBank Ghana Limited', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411433, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'ECOCGHAC', 'ECOBANK GHANA', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411434, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'ACCCGHAC', 'CAL BANK', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411435, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'SSEBGHAC', 'Societe Generale Ghana Limited', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411436, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'GTBIGHAC', 'GT BANK GHANA', 'bank', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411437, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'MOMOGHPC', 'MTN Mobile Money', 'mobile_money', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411438, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'VODAGHPC', 'Vodafone Cash', 'mobile_money', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(77309411439, '2024-09-01 00:38:28.242862+00', '2024-09-01 00:38:28.242862+00', 'AIRTGHPC', 'AirtelTigo Money', 'mobile_money', 'e89be396-0e0e-40fc-ac03-08691b566f75');

INSERT INTO "public"."networks" ("id", "created_at", "updated_at", "chain_id", "identifier", "rpc_endpoint", "is_testnet", "fee", "chain_id_hex", "gateway_contract_address", "bundler_url", "paymaster_url") VALUES
(17179869184, '2024-02-03 23:54:30.744922+00', '2024-02-03 23:54:30.744923+00', 11155111, 'ethereum-sepolia', 'wss://sepolia.infura.io/ws/v3/4458cf4d1689497b9a38b1d6bbf05e78', 't', 0, NULL, '0xCAD53Ff499155Cc2fAA2082A85716322906886c2', 'https://bundler.biconomy.io/api/v2/11155111/nJPK7B3ru.dd7f7861-190d-41bd-af80-6877f74b8f44', 'https://paymaster.biconomy.io/api/v1/11155111/VD_kir2JP.9bd5c901-92c0-43ca-a30f-bb8bbbdd3286'),
(17179869185, '2024-04-29 10:39:32.596797+00', '2024-04-29 10:39:32.596797+00', 421614, 'arbitrum-sepolia', 'wss://arbitrum-sepolia.infura.io/ws/v3/4458cf4d1689497b9a38b1d6bbf05e78', 't', 5, '0x66eee', '0x87B321fc77A0fDD0ca1fEe7Ab791131157B9841A', 'https://bundler.biconomy.io/api/v2/421614/nJPK7B3ru.dd7f7861-190d-41bd-af80-6877f74b8f44', 'https://paymaster.biconomy.io/api/v1/421614/oUg0lNcC-.5c16e9a1-2991-41c2-86ad-8bbd246ace57'),
(17179869186, '2024-06-07 01:45:47.477654+00', '2024-06-07 01:45:47.477654+00', 12002, 'tron-shasta', 'https://api.shasta.trongrid.io', 't', 5, NULL, 'TYA8urq7nkN2yU7rJqAgwDShCusDZrrsxZ', 'https://bundler.shasta.tron.io', 'https://paymaster.shasta.tron.io'),
(17179869187, '2024-06-18 03:04:10.375048+00', '2024-06-18 03:04:10.375048+00', 84532, 'base-sepolia', 'wss://base-sepolia.infura.io/ws/v3/4458cf4d1689497b9a38b1d6bbf05e78', 't', 0, NULL, '0x847dfdAa218F9137229CF8424378871A1DA8f625', 'https://bundler.biconomy.io/api/v2/84532/nJPK7B3ru.dd7f7861-190d-41bd-af80-6877f74b8f44', 'https://paymaster.biconomy.io/api/v1/84532/AtzxDAqR_.805ec674-af7e-4af8-828d-1e4190b51d5a');

INSERT INTO "public"."tokens" ("id", "created_at", "updated_at", "symbol", "contract_address", "decimals", "is_enabled", "network_tokens", "base_currency") VALUES
(55834574849, '2024-03-07 16:38:00.058+00', '2024-03-07 16:38:00.058+00', '6TEST', '0x3870419Ba2BBf0127060bCB37f69A1b1C090992B', 6, 't', 17179869184, 'USD'),
(55834574850, '2024-04-29 10:39:57.365548+00', '2024-04-29 10:39:57.365548+00', '6TEST', '0x3870419Ba2BBf0127060bCB37f69A1b1C090992B', 6, 't', 17179869185, 'USD'),
(55834574851, '2024-06-07 02:10:04.766128+00', '2024-06-07 02:10:04.766128+00', 'USDT', 'TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs', 6, 't', 17179869186, 'USD'),
(55834574852, '2024-06-18 03:05:11.732975+00', '2024-06-18 03:05:11.732975+00', 'DAI', '0x7683022d84F726a96c4A6611cD31DBf5409c0Ac9', 18, 't', 17179869187, 'USD'),
(55834574853, '2024-06-18 03:06:16.468889+00', '2024-06-18 03:06:16.468889+00', 'DAI', '0x77Ab54631BfBAE40383c62044dC30B229c7df9f5', 18, 't', 17179869184, 'USD');

INSERT INTO "public"."users" ("id", "created_at", "updated_at", "first_name", "last_name", "email", "password", "scope", "is_email_verified", "has_early_access") VALUES
('6f7209d3-8f70-499f-aec8-65644d55ad5e', '2025-01-21 12:36:20.39029+00', '2025-01-21 12:36:20.39029+00', 'John', 'Doe', 'john.doe@paycrest.io', '$2a$14$Y8ySFbWKeIyxYdH5Qp2ga.I2QObyuxQ/5xhKHi3BXkmgW8NeRmTKS', 'sender provider', 't', 't');

-- Inserted after creation of sender, provider and user to avoid foreign key constraint

INSERT INTO "public"."api_keys" ("id", "secret", "provider_profile_api_key", "sender_profile_api_key") VALUES
('0c73884d-4438-41a8-9624-d6aec679f868', '3n9Xj63xmqe4b7IgL3h0/EuBsHaByIQzxMmXlmm8d/hN3iBQyQhrl37MEeWVlH3LVPHG4fPBEjG2STWFJnBZ91pKYFXXBPL+', 'AtGaDPqT', NULL),
('11f93de0-d304-4498-8b7b-6cecbc5b2dd8', '/5OxcB9HZ2jJIfsC+AmHhEVs6Khe3x0KS9ZkhSvHZknOiVtBvEa4J+f8P8nzs9qfComAvogtkcqrzGc+suu6JA3lqbSlazyO', NULL, 'e93a1cba-832f-4a7c-aab5-929a53c84324');

INSERT INTO "public"."provider_order_tokens" ("id", "created_at", "updated_at", "fixed_conversion_rate", "floating_conversion_rate", "conversion_rate_type", "max_order_amount", "min_order_amount", "provider_profile_order_tokens", "address", "network", "fiat_currency_provider_order_tokens", "token_provider_order_tokens") VALUES
(30064771084, '2025-01-21 12:45:59.108096+00', '2025-01-21 16:39:25.205819+00', 1598, 0, 'fixed', 900, 100, 'AtGaDPqT', '0xf4c5c4deDde7A86b25E7430796441e209e23eBFB', 'ethereum-sepolia', '5a349408-ebcf-4c7e-98c7-46b6596e0b27', 55834574849),
(30064771085, '2025-01-21 12:46:12.789689+00', '2025-01-21 12:46:12.78969+00', 1598, 0, 'fixed', 900, 100, 'AtGaDPqT', '0xf4c5c4deDde7A86b25E7430796441e209e23eBFB', 'base-sepolia', '5a349408-ebcf-4c7e-98c7-46b6596e0b27', 55834574852),
(30064771086, '2025-01-21 12:46:20.289845+00', '2025-01-21 12:46:20.289845+00', 1598, 0, 'fixed', 900, 100, 'AtGaDPqT', '0xf4c5c4deDde7A86b25E7430796441e209e23eBFB', 'arbitrum-sepolia', '5a349408-ebcf-4c7e-98c7-46b6596e0b27', 55834574853);

INSERT INTO "public"."provider_profiles" ("id", "trading_name", "host_identifier", "provision_mode", "is_active", "is_available", "updated_at", "visibility_mode", "address", "mobile_number", "date_of_birth", "business_name", "identity_document_type", "identity_document", "business_document", "user_provider_profile", "is_kyb_verified") VALUES
('AtGaDPqT', 'John Doe Exchange', 'http://localhost:8105', 'auto', 't', 't', '2025-01-21 16:39:25.232449+00', 'private', '1, John Doe Street, Surulere, Lagos, Nigeria', '+2348123456789', '1993-01-01 00:00:00+00', 'John Doe Exchange Ltd', 'passport', 'https://res.cloudinary.com/de6e0wihu/image/upload/v1737463231/wbeica7nxawqthdnpazv.png', 'https://res.cloudinary.com/de6e0wihu/image/upload/v1737463231/hngwr0f5mw1z9vdvrjqm.png', '6f7209d3-8f70-499f-aec8-65644d55ad5e', 't');

INSERT INTO "public"."provision_buckets" ("id", "min_amount", "max_amount", "created_at", "fiat_currency_provision_buckets") VALUES
(42949672960, 5001, 50000, '2024-02-03 23:54:34.688488+00', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(42949672961, 1001, 5000, '2024-02-03 23:54:41.598789+00', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(42949672962, 0.5, 1000, '2024-02-03 23:54:48.514016+00', '5a349408-ebcf-4c7e-98c7-46b6596e0b27'),
(42949672963, 0, 1000, '2024-09-01 00:35:23.010297+00', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(42949672964, 1001, 5000, '2024-09-01 00:35:23.010297+00', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(42949672965, 5001, 50000, '2024-09-01 00:35:23.010297+00', 'e9325102-6be5-47a7-89d0-8bbeecacb3bc'),
(42949672966, 0, 1000, '2024-09-01 00:35:26.071436+00', 'a87437e3-cfe5-4033-9978-26ae1238821d'),
(42949672967, 1001, 5000, '2024-09-01 00:35:26.071436+00', 'a87437e3-cfe5-4033-9978-26ae1238821d'),
(42949672968, 5001, 50000, '2024-09-01 00:35:26.071436+00', 'a87437e3-cfe5-4033-9978-26ae1238821d'),
(42949672969, 0, 1000, '2024-09-01 00:35:29.216692+00', '9e8b5fde-4ec0-4867-940a-64e79af8157d'),
(42949672970, 1001, 5000, '2024-09-01 00:35:29.216692+00', '9e8b5fde-4ec0-4867-940a-64e79af8157d'),
(42949672971, 5001, 50000, '2024-09-01 00:35:29.216692+00', '9e8b5fde-4ec0-4867-940a-64e79af8157d'),
(42949672972, 0, 1000, '2024-09-01 00:35:32.36934+00', '9adbbdce-0d98-4c2d-81d8-789e291ad589'),
(42949672973, 1001, 5000, '2024-09-01 00:35:32.36934+00', '9adbbdce-0d98-4c2d-81d8-789e291ad589'),
(42949672974, 5001, 50000, '2024-09-01 00:35:32.36934+00', '9adbbdce-0d98-4c2d-81d8-789e291ad589'),
(42949672975, 0, 1000, '2024-09-01 00:35:35.485581+00', 'bdd94af2-1d65-4ed2-9072-cfa656677686'),
(42949672976, 1001, 5000, '2024-09-01 00:35:35.485581+00', 'bdd94af2-1d65-4ed2-9072-cfa656677686'),
(42949672977, 5001, 50000, '2024-09-01 00:35:35.485581+00', 'bdd94af2-1d65-4ed2-9072-cfa656677686'),
(42949672978, 0, 1000, '2024-09-01 00:38:28.242862+00', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(42949672979, 1001, 5000, '2024-09-01 00:38:28.242862+00', 'e89be396-0e0e-40fc-ac03-08691b566f75'),
(42949672980, 5001, 50000, '2024-09-01 00:38:28.242862+00', 'e89be396-0e0e-40fc-ac03-08691b566f75');

INSERT INTO "public"."provision_bucket_provider_profiles" ("provision_bucket_id", "provider_profile_id") VALUES
(42949672960, 'AtGaDPqT'),
(42949672961, 'AtGaDPqT'),
(42949672962, 'AtGaDPqT'),
(42949672963, 'AtGaDPqT'),
(42949672964, 'AtGaDPqT'),
(42949672965, 'AtGaDPqT'),
(42949672966, 'AtGaDPqT'),
(42949672967, 'AtGaDPqT'),
(42949672968, 'AtGaDPqT'),
(42949672969, 'AtGaDPqT'),
(42949672970, 'AtGaDPqT'),
(42949672971, 'AtGaDPqT'),
(42949672972, 'AtGaDPqT'),
(42949672973, 'AtGaDPqT'),
(42949672974, 'AtGaDPqT'),
(42949672975, 'AtGaDPqT'),
(42949672976, 'AtGaDPqT'),
(42949672977, 'AtGaDPqT'),
(42949672978, 'AtGaDPqT'),
(42949672979, 'AtGaDPqT'),
(42949672980, 'AtGaDPqT');

INSERT INTO "public"."sender_order_tokens" ("id", "created_at", "updated_at", "fee_percent", "fee_address", "refund_address", "sender_profile_order_tokens", "token_sender_settings") VALUES
(81604378631, '2025-01-21 16:41:02.671992+00', '2025-01-21 16:41:02.671993+00', 0, '0x409689E3008d43a9eb439e7B275749D4a71D8E2D', '0x409689E3008d43a9eb439e7B275749D4a71D8E2D', 'e93a1cba-832f-4a7c-aab5-929a53c84324', 55834574849),
(81604378632, '2025-01-21 16:41:02.689905+00', '2025-01-21 16:41:02.689905+00', 0, '0x409689E3008d43a9eb439e7B275749D4a71D8E2D', '0x409689E3008d43a9eb439e7B275749D4a71D8E2D', 'e93a1cba-832f-4a7c-aab5-929a53c84324', 55834574850),
(81604378633, '2025-01-21 16:41:20.630752+00', '2025-01-21 16:41:20.630752+00', 0, '0x409689E3008d43a9eb439e7B275749D4a71D8E2D', '0x409689E3008d43a9eb439e7B275749D4a71D8E2D', 'e93a1cba-832f-4a7c-aab5-929a53c84324', 55834574853),
(81604378634, '2025-01-21 16:41:20.636581+00', '2025-01-21 16:41:20.636581+00', 0, '0x409689E3008d43a9eb439e7B275749D4a71D8E2D', '0x409689E3008d43a9eb439e7B275749D4a71D8E2D', 'e93a1cba-832f-4a7c-aab5-929a53c84324', 55834574852);

INSERT INTO "public"."sender_profiles" ("id", "webhook_url", "domain_whitelist", "is_active", "updated_at", "user_sender_profile", "is_partner", "provider_id") VALUES
('e93a1cba-832f-4a7c-aab5-929a53c84324', NULL, '[]', 't', '2025-01-21 16:41:20.641606+00', '6f7209d3-8f70-499f-aec8-65644d55ad5e', 'f', NULL);

ALTER TABLE "public"."api_keys" ADD FOREIGN KEY ("provider_profile_api_key") REFERENCES "public"."provider_profiles"("id") ON DELETE CASCADE;
ALTER TABLE "public"."api_keys" ADD FOREIGN KEY ("sender_profile_api_key") REFERENCES "public"."sender_profiles"("id") ON DELETE CASCADE;


-- Indices
CREATE UNIQUE INDEX api_keys_secret_key ON public.api_keys USING btree (secret);
CREATE UNIQUE INDEX api_keys_provider_profile_api_key_key ON public.api_keys USING btree (provider_profile_api_key);
CREATE UNIQUE INDEX api_keys_sender_profile_api_key_key ON public.api_keys USING btree (sender_profile_api_key);


-- Indices
CREATE UNIQUE INDEX ent_types_type_key ON public.ent_types USING btree (type);


-- Indices
CREATE UNIQUE INDEX fiat_currencies_code_key ON public.fiat_currencies USING btree (code);
CREATE UNIQUE INDEX fiat_currencies_short_name_key ON public.fiat_currencies USING btree (short_name);
ALTER TABLE "public"."fiat_currency_providers" ADD FOREIGN KEY ("provider_profile_id") REFERENCES "public"."provider_profiles"("id") ON DELETE CASCADE;
ALTER TABLE "public"."fiat_currency_providers" ADD FOREIGN KEY ("fiat_currency_id") REFERENCES "public"."fiat_currencies"("id") ON DELETE CASCADE;


-- Indices
CREATE UNIQUE INDEX identity_verification_requests_wallet_address_key ON public.identity_verification_requests USING btree (wallet_address);
CREATE UNIQUE INDEX identity_verification_requests_wallet_signature_key ON public.identity_verification_requests USING btree (wallet_signature);
ALTER TABLE "public"."institutions" ADD FOREIGN KEY ("fiat_currency_institutions") REFERENCES "public"."fiat_currencies"("id") ON DELETE SET NULL;


-- Indices
CREATE UNIQUE INDEX institutions_code_key ON public.institutions USING btree (code);
ALTER TABLE "public"."linked_addresses" ADD FOREIGN KEY ("sender_profile_linked_address") REFERENCES "public"."sender_profiles"("id") ON DELETE CASCADE;


-- Indices
CREATE UNIQUE INDEX linked_addresses_address_key ON public.linked_addresses USING btree (address);
CREATE UNIQUE INDEX linked_addresses_owner_address_key ON public.linked_addresses USING btree (owner_address);
CREATE UNIQUE INDEX linked_addresses_salt_key ON public.linked_addresses USING btree (salt);
ALTER TABLE "public"."lock_order_fulfillments" ADD FOREIGN KEY ("lock_payment_order_fulfillments") REFERENCES "public"."lock_payment_orders"("id") ON DELETE CASCADE;


-- Indices
CREATE UNIQUE INDEX lock_order_fulfillments_tx_id_key ON public.lock_order_fulfillments USING btree (tx_id);
ALTER TABLE "public"."lock_payment_orders" ADD FOREIGN KEY ("provision_bucket_lock_payment_orders") REFERENCES "public"."provision_buckets"("id") ON DELETE SET NULL;
ALTER TABLE "public"."lock_payment_orders" ADD FOREIGN KEY ("token_lock_payment_orders") REFERENCES "public"."tokens"("id") ON DELETE CASCADE;
ALTER TABLE "public"."lock_payment_orders" ADD FOREIGN KEY ("provider_profile_assigned_orders") REFERENCES "public"."provider_profiles"("id") ON DELETE CASCADE;


-- Indices
CREATE UNIQUE INDEX lockpaymentorder_gateway_id_ra_65d1cd4f9b7a0ff4525b6f2bc506afdc ON public.lock_payment_orders USING btree (gateway_id, rate, tx_hash, block_number, institution, account_identifier, account_name, memo, token_lock_payment_orders);


-- Indices
CREATE UNIQUE INDEX networks_identifier_key ON public.networks USING btree (identifier);
ALTER TABLE "public"."payment_order_recipients" ADD FOREIGN KEY ("payment_order_recipient") REFERENCES "public"."payment_orders"("id") ON DELETE CASCADE;


-- Indices
CREATE UNIQUE INDEX payment_order_recipients_payment_order_recipient_key ON public.payment_order_recipients USING btree (payment_order_recipient);
ALTER TABLE "public"."payment_orders" ADD FOREIGN KEY ("token_payment_orders") REFERENCES "public"."tokens"("id") ON DELETE CASCADE;
ALTER TABLE "public"."payment_orders" ADD FOREIGN KEY ("sender_profile_payment_orders") REFERENCES "public"."sender_profiles"("id") ON DELETE SET NULL;
ALTER TABLE "public"."payment_orders" ADD FOREIGN KEY ("api_key_payment_orders") REFERENCES "public"."api_keys"("id") ON DELETE SET NULL;
ALTER TABLE "public"."payment_orders" ADD FOREIGN KEY ("linked_address_payment_orders") REFERENCES "public"."linked_addresses"("id") ON DELETE SET NULL;
ALTER TABLE "public"."provider_order_tokens" ADD FOREIGN KEY ("provider_profile_order_tokens") REFERENCES "public"."provider_profiles"("id") ON DELETE CASCADE;
ALTER TABLE "public"."provider_order_tokens" ADD FOREIGN KEY ("token_provider_order_tokens") REFERENCES "public"."tokens"("id") ON DELETE CASCADE;
ALTER TABLE "public"."provider_order_tokens" ADD FOREIGN KEY ("fiat_currency_provider_order_tokens") REFERENCES "public"."fiat_currencies"("id") ON DELETE CASCADE;
ALTER TABLE "public"."provider_profiles" ADD FOREIGN KEY ("user_provider_profile") REFERENCES "public"."users"("id") ON DELETE CASCADE;


-- Indices
CREATE UNIQUE INDEX providerordertoken_provider_pr_6a0d0c64fd46fb967691502cb58fa192 ON public.provider_order_tokens USING btree (provider_profile_order_tokens, token_provider_order_tokens, fiat_currency_provider_order_tokens);
ALTER TABLE "public"."provider_profiles" ADD FOREIGN KEY ("user_provider_profile") REFERENCES "public"."users"("id") ON DELETE CASCADE;


-- Indices
CREATE UNIQUE INDEX provider_profiles_user_provider_profile_key ON public.provider_profiles USING btree (user_provider_profile);
ALTER TABLE "public"."provider_ratings" ADD FOREIGN KEY ("provider_profile_provider_rating") REFERENCES "public"."provider_profiles"("id");


-- Indices
CREATE UNIQUE INDEX provider_ratings_provider_profile_provider_rating_key ON public.provider_ratings USING btree (provider_profile_provider_rating);
ALTER TABLE "public"."provision_bucket_provider_profiles" ADD FOREIGN KEY ("provision_bucket_id") REFERENCES "public"."provision_buckets"("id") ON DELETE CASCADE;
ALTER TABLE "public"."provision_bucket_provider_profiles" ADD FOREIGN KEY ("provider_profile_id") REFERENCES "public"."provider_profiles"("id") ON DELETE CASCADE;
ALTER TABLE "public"."provision_buckets" ADD FOREIGN KEY ("fiat_currency_provision_buckets") REFERENCES "public"."fiat_currencies"("id") ON DELETE CASCADE;
ALTER TABLE "public"."receive_addresses" ADD FOREIGN KEY ("payment_order_receive_address") REFERENCES "public"."payment_orders"("id") ON DELETE SET NULL;


-- Indices
CREATE UNIQUE INDEX receive_addresses_address_key ON public.receive_addresses USING btree (address);
CREATE UNIQUE INDEX receive_addresses_salt_key ON public.receive_addresses USING btree (salt);
CREATE UNIQUE INDEX receive_addresses_payment_order_receive_address_key ON public.receive_addresses USING btree (payment_order_receive_address);
ALTER TABLE "public"."sender_order_tokens" ADD FOREIGN KEY ("token_sender_settings") REFERENCES "public"."tokens"("id");
ALTER TABLE "public"."sender_order_tokens" ADD FOREIGN KEY ("sender_profile_order_tokens") REFERENCES "public"."sender_profiles"("id") ON DELETE CASCADE;


-- Indices
CREATE UNIQUE INDEX senderordertoken_sender_profil_c0e12093989225f7a56a29b8ff69c3bf ON public.sender_order_tokens USING btree (sender_profile_order_tokens, token_sender_settings);
ALTER TABLE "public"."sender_profiles" ADD FOREIGN KEY ("user_sender_profile") REFERENCES "public"."users"("id") ON DELETE CASCADE;


-- Indices
CREATE UNIQUE INDEX sender_profiles_user_sender_profile_key ON public.sender_profiles USING btree (user_sender_profile);
ALTER TABLE "public"."tokens" ADD FOREIGN KEY ("network_tokens") REFERENCES "public"."networks"("id") ON DELETE CASCADE;
ALTER TABLE "public"."transaction_logs" ADD FOREIGN KEY ("lock_payment_order_transactions") REFERENCES "public"."lock_payment_orders"("id") ON DELETE SET NULL;
ALTER TABLE "public"."transaction_logs" ADD FOREIGN KEY ("payment_order_transactions") REFERENCES "public"."payment_orders"("id") ON DELETE SET NULL;


-- Indices
CREATE UNIQUE INDEX users_email_key ON public.users USING btree (email);
CREATE UNIQUE INDEX user_email_scope ON public.users USING btree (email, scope);
ALTER TABLE "public"."verification_tokens" ADD FOREIGN KEY ("user_verification_token") REFERENCES "public"."users"("id") ON DELETE CASCADE;
