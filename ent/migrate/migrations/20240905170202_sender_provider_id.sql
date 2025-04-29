-- Modify "provider_profiles" table
ALTER TABLE "provider_profiles" DROP COLUMN "is_partner";
ALTER TABLE "provider_profiles" 
    DROP COLUMN "is_partner",
    ADD COLUMN "monthly_volume" decimal DEFAULT NULL;

-- Modify "sender_profiles" table
ALTER TABLE "sender_profiles" ADD COLUMN "provider_id" character varying NULL;