-- Drop the old trigger and functions if they exist
DROP TRIGGER IF EXISTS enforce_payment_order_amount ON payment_orders;
DROP FUNCTION IF EXISTS check_payment_order_amount;
DROP FUNCTION IF EXISTS calculate_total_amount;

-- Recreate the calculate_total_amount function without protocol_fee
CREATE OR REPLACE FUNCTION calculate_total_amount(
    amount DOUBLE PRECISION,
    sender_fee DOUBLE PRECISION,
    network_fee DOUBLE PRECISION,
    token_decimals SMALLINT
) RETURNS DOUBLE PRECISION AS $$
BEGIN
    RETURN ROUND((amount + sender_fee + network_fee)::NUMERIC, token_decimals::INTEGER);
END;
$$ LANGUAGE plpgsql;

-- Recreate the trigger function without protocol_fee
CREATE OR REPLACE FUNCTION check_payment_order_amount() RETURNS TRIGGER AS $$
DECLARE
    total_amount DOUBLE PRECISION;
    token_decimals SMALLINT;
BEGIN
    -- Get the token decimals
    SELECT decimals INTO token_decimals FROM tokens WHERE id = NEW.token_payment_orders;

    -- Calculate the total amount with fees (no protocol_fee)
    total_amount := calculate_total_amount(OLD.amount, OLD.sender_fee, OLD.network_fee, token_decimals);

    -- Check if the amount_paid is within the valid range
    IF OLD.amount_paid >= total_amount AND OLD.status = NEW.status AND OLD.gateway_id IS NULL THEN
        RAISE EXCEPTION 'Duplicate payment order';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Re-apply the trigger to the payment_orders table
CREATE TRIGGER enforce_payment_order_amount
BEFORE INSERT OR UPDATE ON payment_orders
FOR EACH ROW EXECUTE FUNCTION check_payment_order_amount();