-- Modify "networks" table
ALTER TABLE "networks" ALTER COLUMN "block_time" DROP DEFAULT;
-- Modify "payment_orders" table
ALTER TABLE "payment_orders" ADD COLUMN "message_hash" character varying NULL;
-- Create "payment_webhooks" table
CREATE TABLE "payment_webhooks" ("id" uuid NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "webhook_id" character varying NOT NULL, "webhook_secret" character varying NOT NULL, "callback_url" character varying NOT NULL, "network_payment_webhook" bigint NULL, "payment_order_payment_webhook" uuid NULL, PRIMARY KEY ("id"), CONSTRAINT "payment_webhooks_networks_payment_webhook" FOREIGN KEY ("network_payment_webhook") REFERENCES "networks" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "payment_webhooks_payment_orders_payment_webhook" FOREIGN KEY ("payment_order_payment_webhook") REFERENCES "payment_orders" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- Create index "payment_webhooks_network_payment_webhook_key" to table: "payment_webhooks"
CREATE UNIQUE INDEX "payment_webhooks_network_payment_webhook_key" ON "payment_webhooks" ("network_payment_webhook");
-- Create index "payment_webhooks_payment_order_payment_webhook_key" to table: "payment_webhooks"
CREATE UNIQUE INDEX "payment_webhooks_payment_order_payment_webhook_key" ON "payment_webhooks" ("payment_order_payment_webhook");
