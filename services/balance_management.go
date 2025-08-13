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
	// Validate and fix balance inconsistencies before proceeding
	err := svc.ValidateAndFixBalances(ctx, providerID, currencyCode)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to validate or fix balances before reservation")
		return fmt.Errorf("balance validation failed: %w", err)
	}

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
	// Validate and fix balance inconsistencies before proceeding (only if not in transaction)
	if tx == nil {
		err := svc.ValidateAndFixBalances(ctx, providerID, currencyCode)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"ProviderID": providerID,
				"Currency":   currencyCode,
			}).Errorf("Failed to validate or fix balances before balance release")
			return fmt.Errorf("balance validation failed: %w", err)
		}
	}

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
		// For legacy providers or edge cases, allow partial release
		if providerCurrency.ReservedBalance.Equal(decimal.Zero) {
			logger.WithFields(logger.Fields{
				"ProviderID": providerID,
				"Currency":   currencyCode,
				"Requested":  amount.String(),
			}).Infof("Provider %s has zero reserved balance, allowing full release", providerID)
			amount = providerCurrency.ReservedBalance // Release whatever is available
		} else {
			logger.WithFields(logger.Fields{
				"ProviderID":      providerID,
				"Currency":        currencyCode,
				"ReservedBalance": providerCurrency.ReservedBalance.String(),
				"ReleaseAmount":   amount.String(),
			}).Warnf("Insufficient reserved balance for release")
			return fmt.Errorf("insufficient reserved balance: reserved=%s, requested=%s",
				providerCurrency.ReservedBalance.String(), amount.String())
		}
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

	// Check if this is a legacy provider (all balance fields are zero)
	isLegacy, err := svc.IsLegacyProvider(ctx, providerID, currencyCode)
	if err != nil {
		return false, err
	}

	// If legacy provider, assume sufficient balance to maintain service continuity
	if isLegacy {
		logger.WithFields(logger.Fields{
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Infof("Provider %s is in legacy mode, assuming sufficient balance", providerID)
		return true, nil
	}

	// For providers with balance management, perform actual balance check
	hasSufficientBalance := providerCurrency.AvailableBalance.GreaterThanOrEqual(amount)

	return hasSufficientBalance, nil
}

// IsLegacyProvider checks if a provider has zero balances (hasn't updated to balance management yet)
func (svc *BalanceManagementService) IsLegacyProvider(ctx context.Context, providerID string, currencyCode string) (bool, error) {
	providerCurrency, err := svc.GetProviderBalance(ctx, providerID, currencyCode)
	if err != nil {
		return false, err
	}

	// Provider is considered legacy if all balance fields are zero
	isLegacy := providerCurrency.AvailableBalance.Equal(decimal.Zero) &&
		providerCurrency.TotalBalance.Equal(decimal.Zero) &&
		providerCurrency.ReservedBalance.Equal(decimal.Zero)

	return isLegacy, nil
}

// ValidateBalanceConsistency validates that provider balances are logically consistent
func (svc *BalanceManagementService) ValidateBalanceConsistency(ctx context.Context, providerID string, currencyCode string) error {
	providerCurrency, err := svc.GetProviderBalance(ctx, providerID, currencyCode)
	if err != nil {
		return err
	}

	// Ensure balances are logically consistent
	if providerCurrency.AvailableBalance.Add(providerCurrency.ReservedBalance).GreaterThan(providerCurrency.TotalBalance) {
		return fmt.Errorf("balance inconsistency: available + reserved > total for provider %s, currency %s", providerID, currencyCode)
	}

	// Ensure no negative balances
	if providerCurrency.AvailableBalance.LessThan(decimal.Zero) {
		return fmt.Errorf("negative available balance for provider %s, currency %s: %s", providerID, currencyCode, providerCurrency.AvailableBalance.String())
	}

	if providerCurrency.ReservedBalance.LessThan(decimal.Zero) {
		return fmt.Errorf("negative reserved balance for provider %s, currency %s: %s", providerID, currencyCode, providerCurrency.ReservedBalance.String())
	}

	if providerCurrency.TotalBalance.LessThan(decimal.Zero) {
		return fmt.Errorf("negative total balance for provider %s, currency %s: %s", providerID, currencyCode, providerCurrency.TotalBalance.String())
	}

	return nil
}

// FixBalanceInconsistencies automatically fixes common balance inconsistencies
func (svc *BalanceManagementService) FixBalanceInconsistencies(ctx context.Context, providerID string, currencyCode string) error {
	providerCurrency, err := svc.GetProviderBalance(ctx, providerID, currencyCode)
	if err != nil {
		return err
	}

	var needsUpdate bool
	availableBalance := providerCurrency.AvailableBalance
	reservedBalance := providerCurrency.ReservedBalance
	totalBalance := providerCurrency.TotalBalance

	// Fix negative balances by setting them to zero
	if availableBalance.LessThan(decimal.Zero) {
		availableBalance = decimal.Zero
		needsUpdate = true
		logger.WithFields(logger.Fields{
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Warnf("Fixed negative available balance for provider %s", providerID)
	}

	if reservedBalance.LessThan(decimal.Zero) {
		reservedBalance = decimal.Zero
		needsUpdate = true
		logger.WithFields(logger.Fields{
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Warnf("Fixed negative reserved balance for provider %s", providerID)
	}

	if totalBalance.LessThan(decimal.Zero) {
		totalBalance = decimal.Zero
		needsUpdate = true
		logger.WithFields(logger.Fields{
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Warnf("Fixed negative total balance for provider %s", providerID)
	}

	// Fix logical inconsistency: available + reserved should not exceed total
	if availableBalance.Add(reservedBalance).GreaterThan(totalBalance) {
		// Adjust total balance to be the sum of available and reserved
		totalBalance = availableBalance.Add(reservedBalance)
		needsUpdate = true
		logger.WithFields(logger.Fields{
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Warnf("Fixed balance inconsistency for provider %s by adjusting total balance", providerID)
	}

	// Update balances if fixes were applied
	if needsUpdate {
		err = svc.UpdateProviderBalance(ctx, providerID, currencyCode, availableBalance, totalBalance, reservedBalance)
		if err != nil {
			return fmt.Errorf("failed to update balances after fixing inconsistencies: %w", err)
		}

		logger.WithFields(logger.Fields{
			"ProviderID":       providerID,
			"Currency":         currencyCode,
			"AvailableBalance": availableBalance.String(),
			"TotalBalance":     totalBalance.String(),
			"ReservedBalance":  reservedBalance.String(),
		}).Infof("Successfully fixed balance inconsistencies for provider %s", providerID)
	}

	return nil
}

// ValidateAndFixBalances validates and automatically fixes balance inconsistencies before operations
func (svc *BalanceManagementService) ValidateAndFixBalances(ctx context.Context, providerID string, currencyCode string) error {
	// First try to validate balances
	err := svc.ValidateBalanceConsistency(ctx, providerID, currencyCode)
	if err != nil {
		// If validation fails, try to fix inconsistencies
		logger.WithFields(logger.Fields{
			"ProviderID": providerID,
			"Currency":   currencyCode,
			"Error":      err.Error(),
		}).Warnf("Balance validation failed for provider %s, attempting to fix inconsistencies", providerID)

		fixErr := svc.FixBalanceInconsistencies(ctx, providerID, currencyCode)
		if fixErr != nil {
			return fmt.Errorf("failed to validate or fix balances: validation error: %w, fix error: %w", err, fixErr)
		}

		// Validate again after fixing
		err = svc.ValidateBalanceConsistency(ctx, providerID, currencyCode)
		if err != nil {
			return fmt.Errorf("balance validation still failed after fixing inconsistencies: %w", err)
		}
	}

	return nil
}
