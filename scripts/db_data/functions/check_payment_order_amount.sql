CREATE OR REPLACE FUNCTION public.check_payment_order_amount()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
DECLARE
    total_amount DOUBLE PRECISION;
    token_decimals SMALLINT;
BEGIN
    -- Get the token decimals
    SELECT decimals INTO token_decimals FROM tokens WHERE id = NEW.token_payment_orders;

    -- Calculate the total amount with fees
    total_amount := calculate_total_amount(OLD.amount, OLD.sender_fee, OLD.network_fee, OLD.protocol_fee, token_decimals);

    -- Check if the amount_paid is within the valid range
    IF OLD.amount_paid >= total_amount AND OLD.status = NEW.status AND NOT (OLD.gateway_id IS NULL AND NEW.gateway_id IS NOT NULL) THEN
        RAISE EXCEPTION 'Duplicate payment order';
    END IF;

    RETURN NEW;
END;
$function$
