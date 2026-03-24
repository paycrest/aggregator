-- Modify "payment_orders" table
ALTER TABLE "payment_orders" DROP CONSTRAINT "payment_orders_provision_buckets_payment_orders", ADD COLUMN "assignment_market_buy_rate" double precision NULL, ADD COLUMN "assignment_market_sell_rate" double precision NULL;
-- Modify "provision_buckets" table
ALTER TABLE "provision_buckets" DROP CONSTRAINT "provision_buckets_fiat_currencies_provision_buckets", ALTER COLUMN "fiat_currency_provision_buckets" DROP NOT NULL;
-- Modify "provider_order_tokens" table
ALTER TABLE "provider_order_tokens" ADD COLUMN "score" double precision NOT NULL, ADD COLUMN "last_order_assigned_at" timestamptz NULL;
-- Create "provider_assignment_runs" table
CREATE TABLE "provider_assignment_runs" (
  "id" uuid NOT NULL,
  "assigned_provider_id" character varying NULL,
  "attempted_at" timestamptz NOT NULL,
  "trigger" character varying NOT NULL,
  "result" character varying NOT NULL,
  "used_fallback" boolean NOT NULL DEFAULT false,
  "market_buy_rate_snapshot" double precision NULL,
  "market_sell_rate_snapshot" double precision NULL,
  "error_message" text NULL,
  "payment_order_provider_assignment_runs" uuid NOT NULL,
  "provider_order_token_assignment_runs" bigint NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "provider_assignment_runs_payme_84d7fae6191fe88595e67cd16cb3084e" FOREIGN KEY ("payment_order_provider_assignment_runs") REFERENCES "payment_orders" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "provider_assignment_runs_provider_order_tokens_assignment_runs" FOREIGN KEY ("provider_order_token_assignment_runs") REFERENCES "provider_order_tokens" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create "provider_order_token_score_histories" table
CREATE TABLE "provider_order_token_score_histories" (
  "id" uuid NOT NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "event_type" character varying NOT NULL,
  "delta" double precision NOT NULL,
  "payment_order_provider_order_token_score_histories" uuid NOT NULL,
  "provider_order_token_score_histories" bigint NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "provider_order_token_score_his_050ed76dac5be457330d8b5fc14ea929" FOREIGN KEY ("provider_order_token_score_histories") REFERENCES "provider_order_tokens" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "provider_order_token_score_his_86d4d0f0f46280f11b0b15de2006a55a" FOREIGN KEY ("payment_order_provider_order_token_score_histories") REFERENCES "payment_orders" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "providerordertokenscorehistory_c8746269c38251583432217f8d24daef" to table: "provider_order_token_score_histories"
CREATE UNIQUE INDEX "providerordertokenscorehistory_c8746269c38251583432217f8d24daef" ON "provider_order_token_score_histories" ("event_type", "payment_order_provider_order_token_score_histories");
-- Add pk ranges for ('provider_assignment_runs'),('provider_order_token_score_histories') tables
INSERT INTO "ent_types" ("type") VALUES ('provider_assignment_runs'), ('provider_order_token_score_histories');
