-- Update financial fields to use DECIMAL(20,8) precision for better financial accuracy
 -- Update payment_orders table

ALTER TABLE "payment_orders"
ALTER COLUMN "amount" TYPE DECIMAL(20,8);


ALTER TABLE "payment_orders"
ALTER COLUMN "amount_paid" TYPE DECIMAL(20,8);


ALTER TABLE "payment_orders"
ALTER COLUMN "amount_returned" TYPE DECIMAL(20,8);


ALTER TABLE "payment_orders"
ALTER COLUMN "percent_settled" TYPE DECIMAL(20,8);


ALTER TABLE "payment_orders"
ALTER COLUMN "sender_fee" TYPE DECIMAL(20,8);


ALTER TABLE "payment_orders"
ALTER COLUMN "network_fee" TYPE DECIMAL(20,8);


ALTER TABLE "payment_orders"
ALTER COLUMN "rate" TYPE DECIMAL(20,8);


ALTER TABLE "payment_orders"
ALTER COLUMN "fee_percent" TYPE DECIMAL(20,8);

-- Update lock_payment_orders table

ALTER TABLE "lock_payment_orders"
ALTER COLUMN "amount" TYPE DECIMAL(20,8);


ALTER TABLE "lock_payment_orders"
ALTER COLUMN "protocol_fee" TYPE DECIMAL(20,8);


ALTER TABLE "lock_payment_orders"
ALTER COLUMN "rate" TYPE DECIMAL(20,8);


ALTER TABLE "lock_payment_orders"
ALTER COLUMN "order_percent" TYPE DECIMAL(20,8);

-- Update provider_currencies table

ALTER TABLE "provider_currencies"
ALTER COLUMN "available_balance" TYPE DECIMAL(20,8);


ALTER TABLE "provider_currencies"
ALTER COLUMN "total_balance" TYPE DECIMAL(20,8);


ALTER TABLE "provider_currencies"
ALTER COLUMN "reserved_balance" TYPE DECIMAL(20,8);

-- Update provider_order_tokens table

ALTER TABLE "provider_order_tokens"
ALTER COLUMN "fixed_conversion_rate" TYPE DECIMAL(20,8);


ALTER TABLE "provider_order_tokens"
ALTER COLUMN "floating_conversion_rate" TYPE DECIMAL(20,8);


ALTER TABLE "provider_order_tokens"
ALTER COLUMN "max_order_amount" TYPE DECIMAL(20,8);


ALTER TABLE "provider_order_tokens"
ALTER COLUMN "min_order_amount" TYPE DECIMAL(20,8);


ALTER TABLE "provider_order_tokens"
ALTER COLUMN "rate_slippage" TYPE DECIMAL(20,8);

-- Update provision_buckets table

ALTER TABLE "provision_buckets"
ALTER COLUMN "min_amount" TYPE DECIMAL(20,8);


ALTER TABLE "provision_buckets"
ALTER COLUMN "max_amount" TYPE DECIMAL(20,8);

-- Update sender_order_tokens table

ALTER TABLE "sender_order_tokens"
ALTER COLUMN "fee_percent" TYPE DECIMAL(20,8);

-- Update fiat_currencies table

ALTER TABLE "fiat_currencies"
ALTER COLUMN "market_rate" TYPE DECIMAL(20,8);

-- Update networks table

ALTER TABLE "networks"
ALTER COLUMN "fee" TYPE DECIMAL(20,8);

-- Update beneficial_owners table

ALTER TABLE "beneficial_owners"
ALTER COLUMN "ownership_percentage" TYPE DECIMAL(20,8);

-- Update provider_ratings table

ALTER TABLE "provider_ratings"
ALTER COLUMN "trust_score" TYPE DECIMAL(20,8);

