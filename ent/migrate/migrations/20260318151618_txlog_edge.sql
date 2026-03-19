-- Backfill: set payment_order_transactions from payment_orders where gateway_id and network match
UPDATE "transaction_logs" tl
SET "payment_order_transactions" = (
  SELECT p.id FROM "payment_orders" p
  INNER JOIN "tokens" t ON p.token_payment_orders = t.id
  INNER JOIN "networks" n ON t.network_tokens = n.id
  WHERE p.gateway_id = tl.gateway_id AND n.identifier = tl.network
  LIMIT 1
)
WHERE tl.payment_order_transactions IS NULL
  AND tl.gateway_id IS NOT NULL
  AND tl.network IS NOT NULL;
-- Delete logs that could not be backfilled (no matching order)
DELETE FROM "transaction_logs" WHERE "payment_order_transactions" IS NULL;
-- Make payment_order required
ALTER TABLE "transaction_logs" DROP CONSTRAINT "transaction_logs_payment_orders_transactions", ALTER COLUMN "payment_order_transactions" SET NOT NULL, ADD CONSTRAINT "transaction_logs_payment_orders_transactions" FOREIGN KEY ("payment_order_transactions") REFERENCES "payment_orders" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
