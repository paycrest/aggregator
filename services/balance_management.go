package services

import (
	"context"
	"fmt"
	"time"

	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/providercurrencies"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

// BalanceManagementService handles provider balance operations
type BalanceManagementService struct {
	client *ent.Client
}

// NewBalanceManagementService creates a new instance of BalanceManagementService
func NewBalanceManagementService() *BalanceManagementService {
	return &BalanceManagementService{
		client: storage.GetClient(),
	}
}

// UpdateProviderBalance updates the balance for a specific provider and currency
func (svc *BalanceManagementService) UpdateProviderBalance(ctx context.Context, providerID string, currencyCode string, availableBalance, totalBalance, reservedBalance decimal.Decimal) error {
	// Find the ProviderCurrencies entry
	providerCurrency, err := svc.client.ProviderCurrencies.
		Query().
		Where(
			providercurrencies.HasProviderWith(providerprofile.IDEQ(providerID)),
			providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to find provider currency for balance update")
		return fmt.Errorf("provider currency not found: %w", err)
	}

	// Update the balance
	_, err = providerCurrency.Update().
		SetAvailableBalance(availableBalance).
		SetTotalBalance(totalBalance).
		SetReservedBalance(reservedBalance).
		SetUpdatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to update provider balance")
		return fmt.Errorf("failed to update balance: %w", err)
	}

	logger.WithFields(logger.Fields{
		"ProviderID":       providerID,
		"Currency":         currencyCode,
		"AvailableBalance": availableBalance.String(),
		"TotalBalance":     totalBalance.String(),
		"ReservedBalance":  reservedBalance.String(),
	}).Infof("Provider balance updated successfully")

	return nil
}

// GetProviderBalance retrieves the balance for a specific provider and currency
func (svc *BalanceManagementService) GetProviderBalance(ctx context.Context, providerID string, currencyCode string) (*ent.ProviderCurrencies, error) {
	providerCurrency, err := svc.client.ProviderCurrencies.
		Query().
		Where(
			providercurrencies.HasProviderWith(providerprofile.IDEQ(providerID)),
			providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		WithProvider().
		WithCurrency().
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to get provider balance")
		return nil, fmt.Errorf("provider currency not found: %w", err)
	}

	return providerCurrency, nil
}

// ReserveBalance reserves a specific amount for a provider and currency
func (svc *BalanceManagementService) ReserveBalance(ctx context.Context, providerID string, currencyCode string, amount decimal.Decimal) error {
	// Use database transaction to prevent race conditions
	tx, err := svc.client.Tx(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to start transaction for balance reservation")
		return fmt.Errorf("failed to start transaction: %w", err)
	}

	// Get provider balance within transaction
	providerCurrency, err := tx.ProviderCurrencies.
		Query().
		Where(
			providercurrencies.HasProviderWith(providerprofile.IDEQ(providerID)),
			providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		WithProvider().
		WithCurrency().
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to get provider balance for reservation")
		_ = tx.Rollback()
		return fmt.Errorf("failed to get provider balance: %w", err)
	}

	// Check if there's sufficient available balance
	if providerCurrency.AvailableBalance.LessThan(amount) {
		logger.WithFields(logger.Fields{
			"ProviderID":       providerID,
			"Currency":         currencyCode,
			"AvailableBalance": providerCurrency.AvailableBalance.String(),
			"RequestedAmount":  amount.String(),
		}).Warnf("Insufficient available balance for reservation")
		_ = tx.Rollback()
		return fmt.Errorf("insufficient available balance: available=%s, requested=%s",
			providerCurrency.AvailableBalance.String(), amount.String())
	}

	// Calculate new balances
	newAvailableBalance := providerCurrency.AvailableBalance.Sub(amount)
	newReservedBalance := providerCurrency.ReservedBalance.Add(amount)

	// Update the balance within transaction
	_, err = providerCurrency.Update().
		SetAvailableBalance(newAvailableBalance).
		SetReservedBalance(newReservedBalance).
		SetUpdatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to reserve balance")
		_ = tx.Rollback()
		return fmt.Errorf("failed to reserve balance: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to commit balance reservation transaction")
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	logger.WithFields(logger.Fields{
		"ProviderID":     providerID,
		"Currency":       currencyCode,
		"ReservedAmount": amount.String(),
		"NewAvailable":   newAvailableBalance.String(),
		"NewReserved":    newReservedBalance.String(),
	}).Infof("Balance reserved successfully")

	return nil
}

// ReleaseReservedBalance releases a previously reserved amount
// If tx is provided, the operation will be performed within that transaction
func (svc *BalanceManagementService) ReleaseReservedBalance(ctx context.Context, providerID string, currencyCode string, amount decimal.Decimal, tx *ent.Tx) error {
	var providerCurrency *ent.ProviderCurrencies
	var err error
	var shouldCommit bool

	// Use transaction client if provided, otherwise create a new transaction
	if tx != nil {
		providerCurrency, err = tx.ProviderCurrencies.
			Query().
			Where(
				providercurrencies.HasProviderWith(providerprofile.IDEQ(providerID)),
				providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
			).
			WithProvider().
			WithCurrency().
			Only(ctx)
	} else {
		// Create a new transaction for atomicity
		tx, err = svc.client.Tx(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"ProviderID": providerID,
				"Currency":   currencyCode,
			}).Errorf("Failed to start transaction for balance release")
			return fmt.Errorf("failed to start transaction: %w", err)
		}
		shouldCommit = true

		providerCurrency, err = tx.ProviderCurrencies.
			Query().
			Where(
				providercurrencies.HasProviderWith(providerprofile.IDEQ(providerID)),
				providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
			).
			WithProvider().
			WithCurrency().
			Only(ctx)
	}

	if err != nil {
		if shouldCommit {
			_ = tx.Rollback()
		}
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to get provider balance for release")
		return fmt.Errorf("failed to get provider balance: %w", err)
	}

	// Check if there's sufficient reserved balance
	if providerCurrency.ReservedBalance.LessThan(amount) {
		if shouldCommit {
			_ = tx.Rollback()
		}
		logger.WithFields(logger.Fields{
			"ProviderID":      providerID,
			"Currency":        currencyCode,
			"ReservedBalance": providerCurrency.ReservedBalance.String(),
			"ReleaseAmount":   amount.String(),
		}).Warnf("Insufficient reserved balance for release")
		return fmt.Errorf("insufficient reserved balance: reserved=%s, requested=%s",
			providerCurrency.ReservedBalance.String(), amount.String())
	}

	// Calculate new balances
	newReservedBalance := providerCurrency.ReservedBalance.Sub(amount)
	newAvailableBalance := providerCurrency.AvailableBalance.Add(amount)

	// Update the balance
	_, err = providerCurrency.Update().
		SetAvailableBalance(newAvailableBalance).
		SetReservedBalance(newReservedBalance).
		SetUpdatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		if shouldCommit {
			_ = tx.Rollback()
		}
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to release reserved balance")
		return fmt.Errorf("failed to release reserved balance: %w", err)
	}

	// Commit the transaction if we created it
	if shouldCommit {
		if err := tx.Commit(); err != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"ProviderID": providerID,
				"Currency":   currencyCode,
			}).Errorf("Failed to commit balance release transaction")
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
	}

	logger.WithFields(logger.Fields{
		"ProviderID":     providerID,
		"Currency":       currencyCode,
		"ReleasedAmount": amount.String(),
		"NewAvailable":   newAvailableBalance.String(),
		"NewReserved":    newReservedBalance.String(),
	}).Infof("Reserved balance released successfully")

	return nil
}

// GetProviderBalances retrieves all balances for a specific provider
func (svc *BalanceManagementService) GetProviderBalances(ctx context.Context, providerID string) ([]*ent.ProviderCurrencies, error) {
	providerCurrencies, err := svc.client.ProviderCurrencies.
		Query().
		Where(providercurrencies.HasProviderWith(providerprofile.IDEQ(providerID))).
		WithProvider().
		WithCurrency().
		All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
		}).Errorf("Failed to get provider balances")
		return nil, fmt.Errorf("failed to get provider balances: %w", err)
	}

	return providerCurrencies, nil
}

// CheckBalanceSufficiency checks if a provider has sufficient available balance for a given amount
func (svc *BalanceManagementService) CheckBalanceSufficiency(ctx context.Context, providerID string, currencyCode string, amount decimal.Decimal) (bool, error) {
	providerCurrency, err := svc.GetProviderBalance(ctx, providerID, currencyCode)
	if err != nil {
		return false, err
	}

	hasSufficientBalance := providerCurrency.AvailableBalance.GreaterThanOrEqual(amount)

	logger.WithFields(logger.Fields{
		"ProviderID":       providerID,
		"Currency":         currencyCode,
		"AvailableBalance": providerCurrency.AvailableBalance.String(),
		"RequiredAmount":   amount.String(),
		"HasSufficient":    hasSufficientBalance,
	}).Debugf("Balance sufficiency check completed")

	return hasSufficientBalance, nil
}
