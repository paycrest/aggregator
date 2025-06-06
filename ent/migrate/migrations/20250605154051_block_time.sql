-- Modify "networks" table
ALTER TABLE "networks" DROP COLUMN "chain_id_hex", ADD COLUMN "block_time" double precision NOT NULL DEFAULT 2.0;
