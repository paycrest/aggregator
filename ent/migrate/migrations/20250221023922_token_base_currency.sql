-- Modify "tokens" table
ALTER TABLE "tokens" ADD COLUMN "base_currency" character varying NOT NULL DEFAULT 'USD';
