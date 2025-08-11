
CREATE TABLE provider_currencies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    available_balance DECIMAL(20,8) NOT NULL DEFAULT 0.0,
    total_balance DECIMAL(20,8) NOT NULL DEFAULT 0.0,
    reserved_balance DECIMAL(20,8) NOT NULL DEFAULT 0.0,
    is_available BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    provider_id VARCHAR NOT NULL,
    currency_id UUID NOT NULL,
    UNIQUE(provider_id, currency_id),
    FOREIGN KEY (provider_id) REFERENCES provider_profiles(id) ON DELETE CASCADE,
    FOREIGN KEY (currency_id) REFERENCES fiat_currencies(id) ON DELETE CASCADE
);

COMMENT ON TABLE provider_currencies IS 'Stores provider balance information for each supported currency';
COMMENT ON COLUMN provider_currencies.available_balance IS 'Available balance for orders';
COMMENT ON COLUMN provider_currencies.total_balance IS 'Total balance including reserved';
COMMENT ON COLUMN provider_currencies.reserved_balance IS 'Balance reserved for pending orders';
COMMENT ON COLUMN provider_currencies.is_available IS 'Whether provider is available for this currency';

CREATE INDEX idx_provider_currencies_provider_id ON provider_currencies(provider_id);
CREATE INDEX idx_provider_currencies_currency_id ON provider_currencies(currency_id);
CREATE INDEX idx_provider_currencies_available_balance ON provider_currencies(available_balance); 