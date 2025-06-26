-- Modify "networks" table
ALTER TABLE "networks" ALTER COLUMN "block_time" DROP DEFAULT;
-- Modify "provider_profiles" table
ALTER TABLE "provider_profiles" DROP COLUMN "address", DROP COLUMN "mobile_number", DROP COLUMN "date_of_birth", DROP COLUMN "business_name", DROP COLUMN "identity_document_type", DROP COLUMN "identity_document", DROP COLUMN "business_document", ADD COLUMN "kyb_verification_status" character varying NOT NULL DEFAULT 'not_started';
-- Modify "sender_profiles" table
ALTER TABLE "sender_profiles" ADD COLUMN "is_kyb_verified" boolean NOT NULL DEFAULT false, ADD COLUMN "kyb_verification_status" character varying NOT NULL DEFAULT 'not_started';
-- Modify "users" table
ALTER TABLE "users" ADD COLUMN "is_kyb_verified" boolean NOT NULL DEFAULT false;
-- Create "kyb_profiles" table
CREATE TABLE "kyb_profiles" ("id" uuid NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "mobile_number" character varying NOT NULL, "company_name" character varying NOT NULL, "registered_business_address" character varying NOT NULL, "certificate_of_incorporation_url" character varying NOT NULL, "articles_of_incorporation_url" character varying NOT NULL, "business_license_url" character varying NULL, "proof_of_business_address_url" character varying NOT NULL, "proof_of_residential_address_url" character varying NOT NULL, "aml_policy_url" character varying NULL, "kyc_policy_url" character varying NULL, "user_kyb_profile" uuid NULL, PRIMARY KEY ("id"), CONSTRAINT "kyb_profiles_users_kyb_profile" FOREIGN KEY ("user_kyb_profile") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "kyb_profiles_user_kyb_profile_key" to table: "kyb_profiles"
CREATE UNIQUE INDEX "kyb_profiles_user_kyb_profile_key" ON "kyb_profiles" ("user_kyb_profile");
-- Create "beneficial_owners" table
CREATE TABLE "beneficial_owners" ("id" uuid NOT NULL, "full_name" character varying NOT NULL, "residential_address" character varying NOT NULL, "proof_of_residential_address_url" character varying NOT NULL, "government_issued_id_url" character varying NOT NULL, "date_of_birth" character varying NOT NULL, "ownership_percentage" double precision NOT NULL, "government_issued_id_type" character varying NULL, "kyb_profile_beneficial_owners" uuid NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "beneficial_owners_kyb_profiles_beneficial_owners" FOREIGN KEY ("kyb_profile_beneficial_owners") REFERENCES "kyb_profiles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
