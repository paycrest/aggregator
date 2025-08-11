ALTER TABLE fiat_currencies 
ADD COLUMN minimum_available_balance DECIMAL(20,8) DEFAULT 0.0,
ADD COLUMN alert_threshold DECIMAL(20,8) DEFAULT 0.0,
ADD COLUMN critical_threshold DECIMAL(20,8) DEFAULT 0.0;

COMMENT ON COLUMN fiat_currencies.minimum_available_balance IS 'Minimum balance required for orders in this currency';
COMMENT ON COLUMN fiat_currencies.alert_threshold IS 'Balance level that triggers low balance alerts';
COMMENT ON COLUMN fiat_currencies.critical_threshold IS 'Balance level that triggers critical balance alerts'; 