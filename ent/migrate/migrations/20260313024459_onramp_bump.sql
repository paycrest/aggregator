-- Modify "fiat_currencies" table
ALTER TABLE "fiat_currencies" DROP COLUMN "market_rate", ADD COLUMN "market_buy_rate" double precision NULL, ADD COLUMN "market_sell_rate" double precision NULL;
-- Drop index "paymentorder_gateway_id_rate_t_57e75f781063c0a1f3a65de50acf4d66" from table: "payment_orders"
DROP INDEX "paymentorder_gateway_id_rate_t_57e75f781063c0a1f3a65de50acf4d66";
-- Rename a column from "return_address" to "refund_or_recipient_address"
ALTER TABLE "payment_orders" RENAME COLUMN "return_address" TO "refund_or_recipient_address";
-- Modify "payment_orders" table
ALTER TABLE "payment_orders" ADD COLUMN "direction" character varying NOT NULL DEFAULT 'offramp';
-- Create index "paymentorder_gateway_id_rate_t_15007928d1c2801bc0fb6a70487f22ae" to table: "payment_orders"
CREATE UNIQUE INDEX "paymentorder_gateway_id_rate_t_15007928d1c2801bc0fb6a70487f22ae" ON "payment_orders" ("gateway_id", "rate", "tx_hash", "block_number", "institution", "account_identifier", "account_name", "memo", "direction", "refund_or_recipient_address", "token_payment_orders");
-- Modify "provider_order_tokens" table
ALTER TABLE "provider_order_tokens" DROP COLUMN "fixed_conversion_rate", DROP COLUMN "floating_conversion_rate", DROP COLUMN "conversion_rate_type", ADD COLUMN "fixed_buy_rate" double precision NULL, ADD COLUMN "fixed_sell_rate" double precision NULL, ADD COLUMN "floating_buy_delta" double precision NULL, ADD COLUMN "floating_sell_delta" double precision NULL;
-- Modify "sender_profiles" table
ALTER TABLE "sender_profiles" ADD COLUMN "webhook_version" character varying NULL DEFAULT '1';
