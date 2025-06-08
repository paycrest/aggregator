-- Drop index "linked_addresses_salt_key" from table: "linked_addresses"
DROP INDEX "linked_addresses_salt_key";
-- Modify "linked_addresses" table
ALTER TABLE "linked_addresses" ALTER COLUMN "salt" DROP NOT NULL;
-- Modify "lock_payment_orders" table
ALTER TABLE "lock_payment_orders" ADD COLUMN "sender" character varying NULL;
-- Modify "networks" table
ALTER TABLE "networks" DROP COLUMN "chain_id_hex", ADD COLUMN "block_time" double precision NOT NULL;
-- Drop index "receive_addresses_salt_key" from table: "receive_addresses"
DROP INDEX "receive_addresses_salt_key";
-- Modify "receive_addresses" table
ALTER TABLE "receive_addresses" ALTER COLUMN "salt" DROP NOT NULL;
