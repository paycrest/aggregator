CREATE OR REPLACE FUNCTION public.calculate_total_amount(amount double precision, sender_fee double precision, network_fee double precision, protocol_fee double precision, token_decimals smallint)
 RETURNS double precision
 LANGUAGE plpgsql
AS $function$
BEGIN
    RETURN ROUND((amount + sender_fee + network_fee + protocol_fee)::NUMERIC, token_decimals::INTEGER);
END;
$function$
