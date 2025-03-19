ALTER TABLE payment_orders ADD COLUMN deleted_at TIMESTAMP NULL;
ALTER TABLE lock_payment_orders ADD COLUMN deleted_at TIMESTAMP NULL;
