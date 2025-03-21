-- Modify "sender_profiles" table
ALTER TABLE "sender_profiles" DROP COLUMN "fee_per_token_unit", DROP COLUMN "fee_address", DROP COLUMN "refund_address";
-- Create "sender_order_tokens" table
CREATE TABLE "sender_order_tokens" ("id" bigint NOT NULL GENERATED BY DEFAULT AS IDENTITY (START WITH 81604378624), "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "fee_per_token_unit" double precision NOT NULL, "fee_address" character varying NOT NULL, "refund_address" character varying NOT NULL, "sender_profile_order_tokens" uuid NOT NULL, "token_sender_settings" bigint NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "sender_order_tokens_sender_profiles_order_tokens" FOREIGN KEY ("sender_profile_order_tokens") REFERENCES "sender_profiles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "sender_order_tokens_tokens_sender_settings" FOREIGN KEY ("token_sender_settings") REFERENCES "tokens" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "senderordertoken_sender_profil_c0e12093989225f7a56a29b8ff69c3bf" to table: "sender_order_tokens"
CREATE UNIQUE INDEX "senderordertoken_sender_profil_c0e12093989225f7a56a29b8ff69c3bf" ON "sender_order_tokens" ("sender_profile_order_tokens", "token_sender_settings");
-- Add pk ranges for ('sender_order_tokens') tables
INSERT INTO "ent_types" ("type") VALUES ('sender_order_tokens');
