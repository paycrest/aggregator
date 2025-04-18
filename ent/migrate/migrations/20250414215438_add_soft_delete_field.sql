-- Modify "lock_payment_orders" table
ALTER TABLE "public"."lock_payment_orders" ADD COLUMN "deleted_at" timestamptz NULL;
-- Modify "payment_orders" table
ALTER TABLE "public"."payment_orders" DROP CONSTRAINT "payment_orders_sender_profiles_payment_orders", ADD COLUMN "deleted_at" timestamptz NULL, ADD CONSTRAINT "payment_orders_sender_profiles_payment_orders" FOREIGN KEY ("sender_profile_payment_orders") REFERENCES "public"."sender_profiles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE;
