-- Create "sender_fiat_accounts" table
CREATE TABLE "sender_fiat_accounts" (
  "id" uuid NOT NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "institution" character varying NOT NULL,
  "account_identifier" character varying NOT NULL,
  "account_name" character varying NOT NULL,
  "sender_profile_refund_accounts" uuid NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "sender_fiat_accounts_sender_profiles_refund_accounts" FOREIGN KEY ("sender_profile_refund_accounts") REFERENCES "sender_profiles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "senderfiataccount_institution_account_identifier_sender_profile_refund_accounts" to table: "sender_fiat_accounts"
CREATE UNIQUE INDEX "senderfiataccount_institution_account_identifier_sender_profile_refund_accounts" ON "sender_fiat_accounts" ("institution", "account_identifier", "sender_profile_refund_accounts");
-- Create index "senderfiataccount_sender_profile_refund_accounts" to table: "sender_fiat_accounts" (lookup by sender)
CREATE INDEX "senderfiataccount_sender_profile_refund_accounts" ON "sender_fiat_accounts" ("sender_profile_refund_accounts");
