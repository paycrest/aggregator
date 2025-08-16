-- Migration: Convert financial fields to DECIMAL(20,8) precision
-- Date: 2025-08-01
-- Description: Update all monetary amount fields to use DECIMAL(20,8) for financial accuracy
-- Rollback: This migration can be rolled back by reverting to double precision

-- =====================================================
-- FORWARD MIGRATION: Convert to DECIMAL(20,8)
-- =====================================================

-- PaymentOrder table financial fields
ALTER TABLE payment_orders 
    ALTER COLUMN amount TYPE DECIMAL(20,8) USING amount::DECIMAL(20,8),
    ALTER COLUMN amount_paid TYPE DECIMAL(20,8) USING amount_paid::DECIMAL(20,8),
    ALTER COLUMN amount_returned TYPE DECIMAL(20,8) USING amount_returned::DECIMAL(20,8),
    ALTER COLUMN percent_settled TYPE DECIMAL(20,8) USING percent_settled::DECIMAL(20,8),
    ALTER COLUMN sender_fee TYPE DECIMAL(20,8) USING sender_fee::DECIMAL(20,8),
    ALTER COLUMN network_fee TYPE DECIMAL(20,8) USING network_fee::DECIMAL(20,8),
    ALTER COLUMN rate TYPE DECIMAL(20,8) USING rate::DECIMAL(20,8),
    ALTER COLUMN fee_percent TYPE DECIMAL(20,8) USING fee_percent::DECIMAL(20,8);

-- LockPaymentOrder table financial fields
ALTER TABLE lock_payment_orders 
    ALTER COLUMN amount TYPE DECIMAL(20,8) USING amount::DECIMAL(20,8),
    ALTER COLUMN protocol_fee TYPE DECIMAL(20,8) USING protocol_fee::DECIMAL(20,8),
    ALTER COLUMN rate TYPE DECIMAL(20,8) USING rate::DECIMAL(20,8),
    ALTER COLUMN order_percent TYPE DECIMAL(20,8) USING order_percent::DECIMAL(20,8);

-- ProviderCurrencies table financial fields
ALTER TABLE provider_currencies 
    ALTER COLUMN available_balance TYPE DECIMAL(20,8) USING available_balance::DECIMAL(20,8),
    ALTER COLUMN total_balance TYPE DECIMAL(20,8) USING total_balance::DECIMAL(20,8),
    ALTER COLUMN reserved_balance TYPE DECIMAL(20,8) USING reserved_balance::DECIMAL(20,8);

-- ProviderOrderToken table financial fields
ALTER TABLE provider_order_tokens 
    ALTER COLUMN fixed_conversion_rate TYPE DECIMAL(20,8) USING fixed_conversion_rate::DECIMAL(20,8),
    ALTER COLUMN floating_conversion_rate TYPE DECIMAL(20,8) USING floating_conversion_rate::DECIMAL(20,8),
    ALTER COLUMN max_order_amount TYPE DECIMAL(20,8) USING max_order_amount::DECIMAL(20,8),
    ALTER COLUMN min_order_amount TYPE DECIMAL(20,8) USING min_order_amount::DECIMAL(20,8),
    ALTER COLUMN rate_slippage TYPE DECIMAL(20,8) USING rate_slippage::DECIMAL(20,8);

-- ProvisionBucket table financial fields
ALTER TABLE provision_buckets 
    ALTER COLUMN min_amount TYPE DECIMAL(20,8) USING min_amount::DECIMAL(20,8),
    ALTER COLUMN max_amount TYPE DECIMAL(20,8) USING max_amount::DECIMAL(20,8);

-- SenderOrderToken table financial fields
ALTER TABLE sender_order_tokens 
    ALTER COLUMN fee_percent TYPE DECIMAL(20,8) USING fee_percent::DECIMAL(20,8);

-- FiatCurrency table financial fields
ALTER TABLE fiat_currencies 
    ALTER COLUMN market_rate TYPE DECIMAL(20,8) USING market_rate::DECIMAL(20,8);

-- Network table financial fields
ALTER TABLE networks 
    ALTER COLUMN fee TYPE DECIMAL(20,8) USING fee::DECIMAL(20,8);

-- BeneficialOwner table financial fields
ALTER TABLE beneficial_owners 
    ALTER COLUMN ownership_percentage TYPE DECIMAL(20,8) USING ownership_percentage::DECIMAL(20,8);

-- ProviderRating table financial fields
ALTER TABLE provider_ratings 
    ALTER COLUMN trust_score TYPE DECIMAL(20,8) USING trust_score::DECIMAL(20,8);