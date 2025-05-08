-- Modify "provider_profiles" table
ALTER TABLE "provider_profiles" ADD COLUMN "monthly_volume" character varying NULL;

-- Modify "sender_profiles" table
ALTER TABLE "sender_profiles"
    ADD COLUMN "monthly_volume" character varying NULL,
    ADD COLUMN "business_website" character varying NULL,
    ADD COLUMN "nature_of_business" character varying(255) NULL;