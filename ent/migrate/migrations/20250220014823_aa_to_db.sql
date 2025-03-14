-- Modify "networks" table
ALTER TABLE "networks" ADD COLUMN "bundler_url" character varying NULL, ADD COLUMN "paymaster_url" character varying NULL;
