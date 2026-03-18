-- Modify "transaction_logs" table
ALTER TABLE "transaction_logs" DROP CONSTRAINT "transaction_logs_payment_orders_transactions", ALTER COLUMN "payment_order_transactions" SET NOT NULL, ADD CONSTRAINT "transaction_logs_payment_orders_transactions" FOREIGN KEY ("payment_order_transactions") REFERENCES "payment_orders" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
