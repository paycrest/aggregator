-- Add amount_in_usd column to lock_payment_orders table (nullable initially)
ALTER TABLE "lock_payment_orders" ADD COLUMN "amount_in_usd" numeric;

-- Add amount_in_usd column to payment_orders table (nullable initially)
ALTER TABLE "payment_orders" ADD COLUMN "amount_in_usd" numeric;

-- Update existing records in lock_payment_orders with calculated values
UPDATE "lock_payment_orders" 
SET "amount_in_usd" = CASE 
    WHEN "rate" = 1 THEN "amount" / 1515
    ELSE "amount"
END;

-- Update existing records in payment_orders with calculated values
UPDATE "payment_orders" 
SET "amount_in_usd" = CASE 
    WHEN "rate" = 1 THEN "amount" / 1515
    ELSE "amount"
END;

-- Make the column non-nullable for both tables
ALTER TABLE "lock_payment_orders" ALTER COLUMN "amount_in_usd" SET NOT NULL;
ALTER TABLE "payment_orders" ALTER COLUMN "amount_in_usd" SET NOT NULL;

-- Add indexes for better query performance (optional)
CREATE INDEX "idx_lock_payment_orders_amount_in_usd" ON "lock_payment_orders" ("amount_in_usd");
CREATE INDEX "idx_payment_orders_amount_in_usd" ON "payment_orders" ("amount_in_usd");