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

// ReserveBalance reserves an amount from a provider's available balance
// If tx is nil, a new transaction will be created and committed
func (svc *BalanceManagementService) ReserveBalance(ctx context.Context, providerID string, currencyCode string, amount decimal.Decimal, tx *ent.Tx) error {
	// Track whether we created the transaction internally
	internalTx := false

	// Validate and fix balance inconsistencies before proceeding (only if not in transaction)
	if tx == nil {
		validationErr := svc.ValidateAndFixBalances(ctx, providerID, currencyCode)
		if validationErr != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", validationErr),
				"ProviderID": providerID,
				"Currency":   currencyCode,
			}).Errorf("Failed to validate or fix balances before reservation")
			return fmt.Errorf("balance validation failed: %w", validationErr)
		}

		// Use database transaction to prevent race conditions
		var txErr error
		tx, txErr = svc.client.Tx(ctx)
		if txErr != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", txErr),
				"ProviderID": providerID,
				"Currency":   currencyCode,
			}).Errorf("Failed to start transaction for balance reservation")
			return fmt.Errorf("failed to start transaction: %w", txErr)
		}
		internalTx = true // Mark that we created this transaction
		defer func() {
			if txErr != nil {
				_ = tx.Rollback()
			}
		}()
	}

	// Get provider balance within the transaction
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
		return fmt.Errorf("failed to get provider balance: %w", err)
	}

	// Checks if available balance meets minimum threshold
	minThreshold := providerCurrency.Edges.Currency.MinimumAvailableBalance
	if providerCurrency.AvailableBalance.LessThan(minThreshold) {
		logger.WithFields(logger.Fields{
			"ProviderID":       providerID,
			"Currency":         currencyCode,
			"AvailableBalance": providerCurrency.AvailableBalance.String(),
			"MinimumThreshold": minThreshold.String(),
		}).Warnf("Provider balance below minimum threshold for reservation")
		return fmt.Errorf("provider balance below minimum threshold: available=%s, minimum=%s",
			providerCurrency.AvailableBalance.String(), minThreshold.String())
	}

	// Checks if available balance meets minimum threshold
	requiredBalance := amount.Add(minThreshold)
	if providerCurrency.AvailableBalance.LessThan(requiredBalance) {
		logger.WithFields(logger.Fields{
			"ProviderID":       providerID,
			"Currency":         currencyCode,
			"AvailableBalance": providerCurrency.AvailableBalance.String(),
			"RequiredBalance":  requiredBalance.String(),
			"OrderAmount":      amount.String(),
			"MinimumThreshold": minThreshold.String(),
		}).Warnf("Provider balance insufficient for reservation (threshold check failed)")
		return fmt.Errorf("insufficient balance for reservation: available=%s, required=%s (order=%s + threshold=%s)",
			providerCurrency.AvailableBalance.String(), requiredBalance.String(), amount.String(), minThreshold.String())
	}

	// Check if there's sufficient available balance
	if providerCurrency.AvailableBalance.LessThan(amount) {
		logger.WithFields(logger.Fields{
			"ProviderID":       providerID,
			"Currency":         currencyCode,
			"AvailableBalance": providerCurrency.AvailableBalance.String(),
			"RequestedAmount":  amount.String(),
		}).Warnf("Insufficient available balance for reservation")
		return fmt.Errorf("insufficient available balance: available=%s, requested=%s",
			providerCurrency.AvailableBalance.String(), amount.String())
	}

	// Calculate new balances
	newAvailableBalance := providerCurrency.AvailableBalance.Sub(amount)
	newReservedBalance := providerCurrency.ReservedBalance.Add(amount)

	// Update the balance within the transaction
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
		return fmt.Errorf("failed to reserve balance: %w", err)
	}

	// If this method created the transaction, commit it
	// We can't easily check if tx was created by us, so we'll use a different approach
	// For now, we'll assume that if tx was passed in, the caller manages it
	// If tx was created by us (tx != nil but we're in the defer), we'll commit it
	if internalTx { // Only commit if we created the transaction
		if err := tx.Commit(); err != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"ProviderID": providerID,
				"Currency":   currencyCode,
			}).Errorf("Failed to commit balance reservation transaction")
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
	}

	logger.WithFields(logger.Fields{
		"ProviderID":     providerID,
		"Currency":       currencyCode,
		"ReservedAmount": amount.String(),
		"NewAvailable":   newAvailableBalance.String(),
		"NewReserved":    newReservedBalance.String(),
		"TransactionMode": func() string {
			if tx != nil {
				return "external"
			}
			return "internal"
		}(),
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

		// Add defer rollback for the transaction we created
		defer func() {
			if err != nil {
				_ = tx.Rollback()
			}
		}()

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
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to get provider balance for release")
		return fmt.Errorf("failed to get provider balance: %w", err)
	}

	// Check if there's sufficient reserved balance
	if providerCurrency.ReservedBalance.LessThan(amount) {
		// For edge cases, allow partial release
		if providerCurrency.ReservedBalance.Equal(decimal.Zero) {
			logger.WithFields(logger.Fields{
				"ProviderID": providerID,
				"Currency":   currencyCode,
				"Requested":  amount.String(),
			}).Infof("Provider %s has zero reserved balance, allowing full release", providerID)
			// Fix: Don't set amount to zero - release the requested amount
			// amount = providerCurrency.ReservedBalance // This was causing the bug
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

// HandleOrderTimeout handles order timeout scenarios with proper balance cleanup
// This method is designed to be called from background jobs or cleanup processes
func (svc *BalanceManagementService) HandleOrderTimeout(ctx context.Context, orderID string, providerID string, currencyCode string, amount decimal.Decimal) error {
	// Use a separate context with timeout to prevent hanging
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Start a transaction for atomic operation
	tx, err := svc.client.Tx(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    orderID,
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to start transaction for order timeout handling")
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Get provider balance within transaction
	providerCurrency, err := tx.ProviderCurrencies.
		Query().
		Where(
			providercurrencies.HasProviderWith(providerprofile.IDEQ(providerID)),
			providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    orderID,
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to get provider balance for order timeout handling")
		return fmt.Errorf("failed to get provider balance: %w", err)
	}

	// Check if there's actually reserved balance to release
	if providerCurrency.ReservedBalance.LessThanOrEqual(decimal.Zero) {
		logger.WithFields(logger.Fields{
			"OrderID":    orderID,
			"ProviderID": providerID,
			"Currency":   currencyCode,
			"Amount":     amount.String(),
		}).Infof("No reserved balance to release for timed out order")

		// Commit transaction even if no balance to release
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit timeout transaction: %w", err)
		}
		return nil
	}

	// Calculate how much balance to actually release (don't release more than reserved)
	amountToRelease := decimal.Min(amount, providerCurrency.ReservedBalance)

	// Calculate new balances
	newReservedBalance := providerCurrency.ReservedBalance.Sub(amountToRelease)
	newAvailableBalance := providerCurrency.AvailableBalance.Add(amountToRelease)

	// Ensure balances don't go negative
	if newReservedBalance.LessThan(decimal.Zero) {
		newReservedBalance = decimal.Zero
	}

	// Update balances within transaction
	_, err = providerCurrency.Update().
		SetAvailableBalance(newAvailableBalance).
		SetReservedBalance(newReservedBalance).
		SetUpdatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    orderID,
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to update balances for timed out order")
		return fmt.Errorf("failed to update balances: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    orderID,
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to commit order timeout transaction")
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	logger.WithFields(logger.Fields{
		"OrderID":         orderID,
		"ProviderID":      providerID,
		"Currency":        currencyCode,
		"RequestedAmount": amount.String(),
		"ReleasedAmount":  amountToRelease.String(),
		"NewAvailable":    newAvailableBalance.String(),
		"NewReserved":     newReservedBalance.String(),
	}).Infof("Successfully handled order timeout and released reserved balance")

	return nil
}

// CancelOrderAndReleaseBalance cancels an order and releases any reserved balance
// This method ensures atomic operation of order cancellation and balance release
func (svc *BalanceManagementService) CancelOrderAndReleaseBalance(ctx context.Context, orderID string, providerID string, currencyCode string, amount decimal.Decimal) error {
	// Start a transaction to ensure atomicity
	tx, err := svc.client.Tx(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    orderID,
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to start transaction for order cancellation")
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Get current balance within transaction
	providerCurrency, err := tx.ProviderCurrencies.
		Query().
		Where(
			providercurrencies.HasProviderWith(providerprofile.IDEQ(providerID)),
			providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    orderID,
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to get provider balance for order cancellation")
		return fmt.Errorf("failed to get provider balance: %w", err)
	}

	// Calculate new balances after cancellation
	newReservedBalance := providerCurrency.ReservedBalance.Sub(amount)
	newAvailableBalance := providerCurrency.AvailableBalance.Add(amount)

	// Ensure balances don't go negative
	if newReservedBalance.LessThan(decimal.Zero) {
		newReservedBalance = decimal.Zero
		logger.WithFields(logger.Fields{
			"OrderID":    orderID,
			"ProviderID": providerID,
			"Currency":   currencyCode,
			"Amount":     amount.String(),
		}).Warnf("Adjusted reserved balance to zero for cancelled order")
	}

	// Update balances within transaction
	_, err = providerCurrency.Update().
		SetAvailableBalance(newAvailableBalance).
		SetReservedBalance(newReservedBalance).
		SetUpdatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    orderID,
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to update balances for cancelled order")
		return fmt.Errorf("failed to update balances: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    orderID,
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to commit order cancellation transaction")
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	logger.WithFields(logger.Fields{
		"OrderID":      orderID,
		"ProviderID":   providerID,
		"Currency":     currencyCode,
		"Amount":       amount.String(),
		"NewAvailable": newAvailableBalance.String(),
		"NewReserved":  newReservedBalance.String(),
	}).Infof("Successfully cancelled order and released reserved balance")

	return nil
}

// CancelOrderAndReleaseBalanceWithinTransaction cancels an order and releases balance within an existing transaction
// This method is designed to be called from within another transaction to ensure atomicity
func (svc *BalanceManagementService) CancelOrderAndReleaseBalanceWithinTransaction(ctx context.Context, orderID string, providerID string, currencyCode string, amount decimal.Decimal, tx *ent.Tx) error {
	// Get current balance within the provided transaction
	providerCurrency, err := tx.ProviderCurrencies.
		Query().
		Where(
			providercurrencies.HasProviderWith(providerprofile.IDEQ(providerID)),
			providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    orderID,
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to get provider balance for order cancellation within transaction")
		return fmt.Errorf("failed to get provider balance: %w", err)
	}

	// Calculate new balances after cancellation
	newReservedBalance := providerCurrency.ReservedBalance.Sub(amount)
	newAvailableBalance := providerCurrency.AvailableBalance.Add(amount)

	// Ensure balances don't go negative
	if newReservedBalance.LessThan(decimal.Zero) {
		newReservedBalance = decimal.Zero
		logger.WithFields(logger.Fields{
			"OrderID":    orderID,
			"ProviderID": providerID,
			"Currency":   currencyCode,
			"Amount":     amount.String(),
		}).Warnf("Adjusted reserved balance to zero for cancelled order within transaction")
	}

	// Update balances within the transaction
	_, err = providerCurrency.Update().
		SetAvailableBalance(newAvailableBalance).
		SetReservedBalance(newReservedBalance).
		SetUpdatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    orderID,
			"ProviderID": providerID,
			"Currency":   currencyCode,
		}).Errorf("Failed to update balances for cancelled order within transaction")
		return fmt.Errorf("failed to update balances: %w", err)
	}

	logger.WithFields(logger.Fields{
		"OrderID":      orderID,
		"ProviderID":   providerID,
		"Currency":     currencyCode,
		"Amount":       amount.String(),
		"NewAvailable": newAvailableBalance.String(),
		"NewReserved":  newReservedBalance.String(),
	}).Infof("Successfully cancelled order and released reserved balance within transaction")

	return nil
}

// SafeReleaseBalance safely releases reserved balance with comprehensive error handling
// This method is designed to be called from cleanup operations and should not fail the main flow
func (svc *BalanceManagementService) SafeReleaseBalance(ctx context.Context, providerID string, currencyCode string, amount decimal.Decimal) error {
	// Use a separate context with timeout to prevent hanging
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Attempt to release the balance
	err := svc.ReleaseReservedBalance(ctx, providerID, currencyCode, amount, nil)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
			"Currency":   currencyCode,
			"Amount":     amount.String(),
		}).Errorf("Failed to safely release reserved balance for provider %s - this may require manual intervention", providerID)

		// Log additional context for debugging
		logger.WithFields(logger.Fields{
			"ProviderID": providerID,
			"Currency":   currencyCode,
			"Amount":     amount.String(),
		}).Warnf("Balance release failed - provider %s may have inconsistent balance state", providerID)

		return err
	} else {
		logger.WithFields(logger.Fields{
			"ProviderID": providerID,
			"Currency":   currencyCode,
			"Amount":     amount.String(),
		}).Infof("Successfully released reserved balance for provider %s", providerID)

		return nil
	}
}

// BulkCleanupFailedOrders performs bulk cleanup of failed orders and releases associated balances
// This method is designed to be called from cleanup jobs or admin interfaces
func (svc *BalanceManagementService) BulkCleanupFailedOrders(ctx context.Context, failedOrders []FailedOrderInfo) (*BulkCleanupReport, error) {
	report := &BulkCleanupReport{
		TotalOrders:    len(failedOrders),
		SuccessCount:   0,
		FailureCount:   0,
		TotalAmount:    decimal.Zero,
		Errors:         []string{},
		SuccessDetails: []string{},
		FailureDetails: []string{},
	}

	// Process each failed order
	for _, order := range failedOrders {
		// Use a separate context with timeout for each order
		orderCtx, cancel := context.WithTimeout(ctx, 30*time.Second)

		// Attempt to release balance for this order
		err := svc.SafeReleaseBalance(orderCtx, order.ProviderID, order.CurrencyCode, order.Amount)
		cancel()

		if err != nil {
			report.FailureCount++
			errorMsg := fmt.Sprintf("Order %s: %v", order.OrderID, err)
			report.Errors = append(report.Errors, errorMsg)
			report.FailureDetails = append(report.FailureDetails,
				fmt.Sprintf("Order %s (Provider: %s, Currency: %s, Amount: %s) - %v",
					order.OrderID, order.ProviderID, order.CurrencyCode, order.Amount.String(), err))
		} else {
			report.SuccessCount++
			report.TotalAmount = report.TotalAmount.Add(order.Amount)
			report.SuccessDetails = append(report.SuccessDetails,
				fmt.Sprintf("Order %s (Provider: %s, Currency: %s, Amount: %s) - Balance released successfully",
					order.OrderID, order.ProviderID, order.CurrencyCode, order.Amount.String()))
		}
	}

	// Log summary
	logger.WithFields(logger.Fields{
		"TotalOrders":  report.TotalOrders,
		"SuccessCount": report.SuccessCount,
		"FailureCount": report.FailureCount,
		"TotalAmount":  report.TotalAmount.String(),
	}).Infof("Bulk cleanup completed: %d successful, %d failed", report.SuccessCount, report.FailureCount)

	return report, nil
}

// FailedOrderInfo represents information about a failed order for cleanup
type FailedOrderInfo struct {
	OrderID      string          `json:"orderId"`
	ProviderID   string          `json:"providerId"`
	CurrencyCode string          `json:"currencyCode"`
	Amount       decimal.Decimal `json:"amount"`
	FailureTime  time.Time       `json:"failureTime"`
}

// BulkCleanupReport represents the result of bulk cleanup operations
type BulkCleanupReport struct {
	TotalOrders    int             `json:"totalOrders"`
	SuccessCount   int             `json:"successCount"`
	FailureCount   int             `json:"failureCount"`
	TotalAmount    decimal.Decimal `json:"totalAmount"`
	Errors         []string        `json:"errors"`
	SuccessDetails []string        `json:"successDetails"`
	FailureDetails []string        `json:"failureDetails"`
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
	// providerCurrency, err := svc.GetProviderBalance(ctx, providerID, currencyCode)
	// if err != nil {
	// 	return false, err
	// }

	// For providers with balance management, perform actual balance check
	// hasSufficientBalance := providerCurrency.AvailableBalance.GreaterThanOrEqual(amount)

	return svc.HasSufficientBalance(ctx, providerID, currencyCode, amount)
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
	// Use a transaction to ensure atomic validation and fixing
	tx, err := svc.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction for balance validation: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Get provider balance within transaction to prevent race conditions
	providerCurrency, err := tx.ProviderCurrencies.
		Query().
		Where(
			providercurrencies.HasProviderWith(providerprofile.IDEQ(providerID)),
			providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		Only(ctx)
	if err != nil {
		return fmt.Errorf("failed to get provider balance for validation: %w", err)
	}

	// First try to validate balances
	validationErr := svc.validateBalanceConsistencyInternal(providerCurrency)
	if validationErr != nil {
		// If validation fails, try to fix inconsistencies within the same transaction
		logger.WithFields(logger.Fields{
			"ProviderID": providerID,
			"Currency":   currencyCode,
			"Error":      validationErr.Error(),
		}).Warnf("Balance validation failed for provider %s, attempting to fix inconsistencies", providerID)

		fixErr := svc.fixBalanceInconsistenciesInternal(ctx, providerCurrency, tx)
		if fixErr != nil {
			return fmt.Errorf("failed to validate or fix balances: validation error: %w, fix error: %w", validationErr, fixErr)
		}

		// Validate again after fixing within the same transaction
		validationErr = svc.validateBalanceConsistencyInternal(providerCurrency)
		if validationErr != nil {
			return fmt.Errorf("balance validation still failed after fixing inconsistencies: %w", validationErr)
		}
	}

	// Commit the transaction if everything succeeded
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit balance validation transaction: %w", err)
	}

	return nil
}

// validateBalanceConsistencyInternal validates balance consistency without database queries
func (svc *BalanceManagementService) validateBalanceConsistencyInternal(providerCurrency *ent.ProviderCurrencies) error {
	// Ensure balances are logically consistent
	if providerCurrency.AvailableBalance.Add(providerCurrency.ReservedBalance).GreaterThan(providerCurrency.TotalBalance) {
		return fmt.Errorf("balance inconsistency: available + reserved > total for provider %s, currency %s",
			providerCurrency.Edges.Provider.ID, providerCurrency.Edges.Currency.Code)
	}

	// Ensure no negative balances
	if providerCurrency.AvailableBalance.LessThan(decimal.Zero) {
		return fmt.Errorf("negative available balance for provider %s, currency %s: %s",
			providerCurrency.Edges.Provider.ID, providerCurrency.Edges.Currency.Code, providerCurrency.AvailableBalance.String())
	}

	if providerCurrency.ReservedBalance.LessThan(decimal.Zero) {
		return fmt.Errorf("negative reserved balance for provider %s, currency %s: %s",
			providerCurrency.Edges.Provider.ID, providerCurrency.Edges.Currency.Code, providerCurrency.ReservedBalance.String())
	}

	if providerCurrency.TotalBalance.LessThan(decimal.Zero) {
		return fmt.Errorf("negative total balance for provider %s, currency %s: %s",
			providerCurrency.Edges.Provider.ID, providerCurrency.Edges.Currency.Code, providerCurrency.TotalBalance.String())
	}

	return nil
}

// fixBalanceInconsistenciesInternal fixes balance inconsistencies within a transaction
func (svc *BalanceManagementService) fixBalanceInconsistenciesInternal(ctx context.Context, providerCurrency *ent.ProviderCurrencies, tx *ent.Tx) error {
	var needsUpdate bool
	availableBalance := providerCurrency.AvailableBalance
	reservedBalance := providerCurrency.ReservedBalance
	totalBalance := providerCurrency.TotalBalance

	// Fix negative balances by setting them to zero
	if availableBalance.LessThan(decimal.Zero) {
		availableBalance = decimal.Zero
		needsUpdate = true
		logger.WithFields(logger.Fields{
			"ProviderID": providerCurrency.Edges.Provider.ID,
			"Currency":   providerCurrency.Edges.Currency.Code,
		}).Warnf("Fixed negative available balance for provider %s", providerCurrency.Edges.Provider.ID)
	}

	if reservedBalance.LessThan(decimal.Zero) {
		reservedBalance = decimal.Zero
		needsUpdate = true
		logger.WithFields(logger.Fields{
			"ProviderID": providerCurrency.Edges.Provider.ID,
			"Currency":   providerCurrency.Edges.Currency.Code,
		}).Warnf("Fixed negative reserved balance for provider %s", providerCurrency.Edges.Provider.ID)
	}

	if totalBalance.LessThan(decimal.Zero) {
		totalBalance = decimal.Zero
		needsUpdate = true
		logger.WithFields(logger.Fields{
			"ProviderID": providerCurrency.Edges.Provider.ID,
			"Currency":   providerCurrency.Edges.Currency.Code,
		}).Warnf("Fixed negative total balance for provider %s", providerCurrency.Edges.Provider.ID)
	}

	// Fix logical inconsistency: available + reserved should not exceed total
	if availableBalance.Add(reservedBalance).GreaterThan(totalBalance) {
		// Adjust total balance to be the sum of available and reserved
		totalBalance = availableBalance.Add(reservedBalance)
		needsUpdate = true
		logger.WithFields(logger.Fields{
			"ProviderID": providerCurrency.Edges.Provider.ID,
			"Currency":   providerCurrency.Edges.Currency.Code,
		}).Warnf("Fixed balance inconsistency for provider %s by adjusting total balance", providerCurrency.Edges.Provider.ID)
	}

	// Update balances if fixes were applied within the transaction
	if needsUpdate {
		_, err := providerCurrency.Update().
			SetAvailableBalance(availableBalance).
			SetTotalBalance(totalBalance).
			SetReservedBalance(reservedBalance).
			SetUpdatedAt(time.Now()).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to update balances after fixing inconsistencies: %w", err)
		}

		logger.WithFields(logger.Fields{
			"ProviderID":       providerCurrency.Edges.Provider.ID,
			"Currency":         providerCurrency.Edges.Currency.Code,
			"AvailableBalance": availableBalance.String(),
			"TotalBalance":     totalBalance.String(),
			"ReservedBalance":  reservedBalance.String(),
		}).Infof("Successfully fixed balance inconsistencies for provider %s", providerCurrency.Edges.Provider.ID)
	}

	return nil
}

// CheckBalanceHealth performs a comprehensive health check on provider balances
// This method is designed to be called from monitoring systems or admin interfaces
func (svc *BalanceManagementService) CheckBalanceHealth(ctx context.Context, providerID string, currencyCode string) (*BalanceHealthReport, error) {
	// Get current balance
	providerCurrency, err := svc.GetProviderBalance(ctx, providerID, currencyCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider balance for health check: %w", err)
	}

	report := &BalanceHealthReport{
		ProviderID:       providerID,
		CurrencyCode:     currencyCode,
		AvailableBalance: providerCurrency.AvailableBalance,
		ReservedBalance:  providerCurrency.ReservedBalance,
		TotalBalance:     providerCurrency.TotalBalance,
		LastUpdated:      providerCurrency.UpdatedAt,
		Issues:           []string{},
		Recommendations:  []string{},
	}

	// Check for negative balances
	if providerCurrency.AvailableBalance.LessThan(decimal.Zero) {
		report.Issues = append(report.Issues, fmt.Sprintf("Negative available balance: %s", providerCurrency.AvailableBalance.String()))
		report.Recommendations = append(report.Recommendations, "Reset available balance to zero")
		report.Severity = "HIGH"
	}

	if providerCurrency.ReservedBalance.LessThan(decimal.Zero) {
		report.Issues = append(report.Issues, fmt.Sprintf("Negative reserved balance: %s", providerCurrency.ReservedBalance.String()))
		report.Recommendations = append(report.Recommendations, "Reset reserved balance to zero")
		report.Severity = "HIGH"
	}

	if providerCurrency.TotalBalance.LessThan(decimal.Zero) {
		report.Issues = append(report.Issues, fmt.Sprintf("Negative total balance: %s", providerCurrency.TotalBalance.String()))
		report.Recommendations = append(report.Recommendations, "Reset total balance to zero")
		report.Severity = "HIGH"
	}

	// Check logical consistency
	calculatedTotal := providerCurrency.AvailableBalance.Add(providerCurrency.ReservedBalance)
	if calculatedTotal.GreaterThan(providerCurrency.TotalBalance) {
		report.Issues = append(report.Issues, fmt.Sprintf("Logical inconsistency: available + reserved (%s) > total (%s)",
			calculatedTotal.String(), providerCurrency.TotalBalance.String()))
		report.Recommendations = append(report.Recommendations, "Adjust total balance to match available + reserved")
		report.Severity = "MEDIUM"
	}

	// Check for suspicious patterns
	if providerCurrency.AvailableBalance.Equal(decimal.Zero) &&
		providerCurrency.ReservedBalance.Equal(decimal.Zero) &&
		providerCurrency.TotalBalance.Equal(decimal.Zero) {
		report.Issues = append(report.Issues, "All balance fields are zero - may indicate uninitialized provider")
		report.Recommendations = append(report.Recommendations, "Verify provider balance initialization")
		report.Severity = "LOW"
	}

	if providerCurrency.ReservedBalance.GreaterThan(providerCurrency.TotalBalance) {
		report.Issues = append(report.Issues, fmt.Sprintf("Reserved balance (%s) exceeds total balance (%s)",
			providerCurrency.ReservedBalance.String(), providerCurrency.TotalBalance.String()))
		report.Recommendations = append(report.Recommendations, "Investigate order assignment logic")
		report.Severity = "HIGH"
	}

	// Determine overall health status
	if len(report.Issues) == 0 {
		report.Status = "HEALTHY"
		report.Severity = "NONE"
	} else if report.Severity == "HIGH" {
		report.Status = "CRITICAL"
	} else if report.Severity == "MEDIUM" {
		report.Status = "WARNING"
	} else {
		report.Status = "INFO"
	}

	return report, nil
}

// HasSufficientBalance checks if provider has sufficient balance including thresholds
func (svc *BalanceManagementService) HasSufficientBalance(ctx context.Context, providerID string, currencyCode string, orderAmount decimal.Decimal) (bool, error) {
	// Get provider currency with thresholds
	providerCurrency, err := svc.client.ProviderCurrencies.
		Query().
		Where(
			providercurrencies.HasProviderWith(providerprofile.IDEQ(providerID)),
			providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		WithCurrency().
		Only(ctx)

	if err != nil {
		return false, fmt.Errorf("failed to get provider currency: %w", err)
	}

	// Check if available balance meets minimum threshold
	minThreshold := providerCurrency.Edges.Currency.MinimumAvailableBalance
	if providerCurrency.AvailableBalance.LessThan(minThreshold) {
		logger.WithFields(logger.Fields{
			"ProviderID":       providerID,
			"CurrencyCode":     currencyCode,
			"AvailableBalance": providerCurrency.AvailableBalance.String(),
			"MinimumThreshold": minThreshold.String(),
		}).Warn("Provider balance below minimum threshold")
		return false, nil
	}

	// Check if balance can cover the order amount plus minimum threshold
	requiredBalance := orderAmount.Add(minThreshold)
	if providerCurrency.AvailableBalance.LessThan(requiredBalance) {
		logger.WithFields(logger.Fields{
			"ProviderID":       providerID,
			"CurrencyCode":     currencyCode,
			"AvailableBalance": providerCurrency.AvailableBalance.String(),
			"RequiredBalance":  requiredBalance.String(),
			"OrderAmount":      orderAmount.String(),
		}).Warn("Provider balance insufficient for order")
		return false, nil
	}

	return true, nil
}

// CheckProviderBalanceWithThresholds enhanced version that includes threshold validation
func (svc *BalanceManagementService) CheckProviderBalanceWithThresholds(ctx context.Context, providerID string, currencyCode string) (*ProviderBalanceStatus, error) {
	providerCurrency, err := svc.GetProviderBalance(ctx, providerID, currencyCode)
	if err != nil {
		return nil, err
	}

	status := &ProviderBalanceStatus{
		ProviderID:       providerID,
		CurrencyCode:     currencyCode,
		AvailableBalance: providerCurrency.AvailableBalance,
		ReservedBalance:  providerCurrency.ReservedBalance,
		TotalBalance:     providerCurrency.TotalBalance,
		LastUpdated:      providerCurrency.UpdatedAt,
		Thresholds: ThresholdStatus{
			MinimumThreshold:  providerCurrency.Edges.Currency.MinimumAvailableBalance,
			AlertThreshold:    providerCurrency.Edges.Currency.AlertThreshold,
			CriticalThreshold: providerCurrency.Edges.Currency.CriticalThreshold,
		},
	}

	// Determine status based on thresholds
	if providerCurrency.AvailableBalance.LessThan(providerCurrency.Edges.Currency.CriticalThreshold) {
		status.Status = "CRITICAL"
		status.Message = "Balance below critical threshold"
	} else if providerCurrency.AvailableBalance.LessThan(providerCurrency.Edges.Currency.AlertThreshold) {
		status.Status = "ALERT"
		status.Message = "Balance below alert threshold"
	} else if providerCurrency.AvailableBalance.LessThan(providerCurrency.Edges.Currency.MinimumAvailableBalance) {
		status.Status = "WARNING"
		status.Message = "Balance below minimum threshold"
	} else {
		status.Status = "HEALTHY"
		status.Message = "Balance is healthy"
	}

	return status, nil
}

// GetEligibleProviders returns providers that meet balance thresholds for a given currency and amount
func (svc *BalanceManagementService) GetEligibleProviders(ctx context.Context, currencyCode string, orderAmount decimal.Decimal) ([]*ent.ProviderProfile, error) {
	// Get all active providers for this currency
	providers, err := svc.client.ProviderProfile.
		Query().
		Where(providerprofile.IsActiveEQ(true)).
		WithProviderCurrencies(func(pcq *ent.ProviderCurrenciesQuery) {
			pcq.Where(providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currencyCode))).WithCurrency()
		}).
		All(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to get providers: %w", err)
	}

	// Filter providers with sufficient balance
	var eligibleProviders []*ent.ProviderProfile

	for _, provider := range providers {
		if len(provider.Edges.ProviderCurrencies) == 0 {
			continue
		}

		hasBalance, err := svc.HasSufficientBalance(ctx, provider.ID, currencyCode, orderAmount)
		if err != nil {
			logger.Errorf("Balance check failed for provider %s: %v", provider.ID, err)
			continue
		}

		if hasBalance {
			eligibleProviders = append(eligibleProviders, provider)
		}
	}

	logger.WithFields(logger.Fields{
		"CurrencyCode":      currencyCode,
		"OrderAmount":       orderAmount.String(),
		"TotalProviders":    len(providers),
		"EligibleProviders": len(eligibleProviders),
	}).Infof("Provider eligibility check completed")

	return eligibleProviders, nil
}

func (svc *BalanceManagementService) IsProviderHealthyForCurrency(ctx context.Context, providerID string, currencyCode string) (bool, error) {
	// Get provider currency with thresholds
	providerCurrency, err := svc.client.ProviderCurrencies.
		Query().
		Where(
			providercurrencies.HasProviderWith(providerprofile.IDEQ(providerID)),
			providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		WithCurrency().
		Only(ctx)

	if err != nil {
		return false, fmt.Errorf("failed to get provider currency: %w", err)
	}

	// Check if provider is active and available
	if !providerCurrency.IsAvailable {
		logger.WithFields(logger.Fields{
			"ProviderID":   providerID,
			"CurrencyCode": currencyCode,
		}).Warn("Provider currency is not available")
		return false, nil
	}

	// Check if balance is above critical threshold
	criticalThreshold := providerCurrency.Edges.Currency.CriticalThreshold
	if providerCurrency.AvailableBalance.LessThanOrEqual(criticalThreshold) {
		logger.WithFields(logger.Fields{
			"ProviderID":        providerID,
			"CurrencyCode":      currencyCode,
			"AvailableBalance":  providerCurrency.AvailableBalance.String(),
			"CriticalThreshold": criticalThreshold.String(),
		}).Warn("Provider balance at or below critical threshold")
		return false, nil
	}

	// Check if balance is above alert threshold (with safety margin)
	alertThreshold := providerCurrency.Edges.Currency.AlertThreshold
	safetyMargin := alertThreshold.Mul(decimal.NewFromFloat(0.1)) // 10% safety margin
	effectiveThreshold := alertThreshold.Add(safetyMargin)

	if providerCurrency.AvailableBalance.LessThan(effectiveThreshold) {
		logger.WithFields(logger.Fields{
			"ProviderID":         providerID,
			"CurrencyCode":       currencyCode,
			"AvailableBalance":   providerCurrency.AvailableBalance.String(),
			"AlertThreshold":     alertThreshold.String(),
			"EffectiveThreshold": effectiveThreshold.String(),
		}).Warn("Provider balance below effective threshold (alert + safety margin)")
		return false, nil
	}

	return true, nil
}

func (svc *BalanceManagementService) ValidateProviderBalanceHealth(ctx context.Context, providerID string, currencyCode string, orderAmount decimal.Decimal) (*BalanceHealthReport, error) {
	// Get provider currency with thresholds
	providerCurrency, err := svc.client.ProviderCurrencies.
		Query().
		Where(
			providercurrencies.HasProviderWith(providerprofile.IDEQ(providerID)),
			providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		WithCurrency().
		Only(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to get provider currency: %w", err)
	}

	report := &BalanceHealthReport{
		ProviderID:       providerID,
		CurrencyCode:     currencyCode,
		AvailableBalance: providerCurrency.AvailableBalance,
		ReservedBalance:  providerCurrency.ReservedBalance,
		TotalBalance:     providerCurrency.TotalBalance,
		LastUpdated:      providerCurrency.UpdatedAt,
		Issues:           []string{},
		Recommendations:  []string{},
	}

	// Check critical threshold
	criticalThreshold := providerCurrency.Edges.Currency.CriticalThreshold
	if providerCurrency.AvailableBalance.LessThanOrEqual(criticalThreshold) {
		report.Status = "critical"
		report.Severity = "high"
		report.Issues = append(report.Issues, "Balance at or below critical threshold")
		report.Recommendations = append(report.Recommendations, "Top up balance immediately")
		return report, nil
	}

	// Check alert threshold
	alertThreshold := providerCurrency.Edges.Currency.AlertThreshold
	if providerCurrency.AvailableBalance.LessThan(alertThreshold) {
		report.Status = "warning"
		report.Severity = "medium"
		report.Issues = append(report.Issues, "Balance below alert threshold")
		report.Recommendations = append(report.Recommendations, "Consider topping up balance soon")
	}

	// Check if balance can cover order amount plus minimum threshold
	minThreshold := providerCurrency.Edges.Currency.MinimumAvailableBalance
	requiredBalance := orderAmount.Add(minThreshold)
	if providerCurrency.AvailableBalance.LessThan(requiredBalance) {
		report.Status = "insufficient"
		report.Severity = "high"
		report.Issues = append(report.Issues, "Insufficient balance for order")
		report.Recommendations = append(report.Recommendations, "Increase balance or reduce order amount")
		return report, nil
	}

	// Check if balance is healthy
	if len(report.Issues) == 0 {
		report.Status = "healthy"
		report.Severity = "low"
		report.Recommendations = append(report.Recommendations, "Balance is in good condition")
	}

	return report, nil
}

func (svc *BalanceManagementService) GetHealthyProvidersForCurrency(ctx context.Context, currencyCode string) ([]*ent.ProviderProfile, error) {
	// Get all active providers for this currency
	providers, err := svc.client.ProviderProfile.
		Query().
		Where(providerprofile.IsActiveEQ(true)).
		WithProviderCurrencies(func(pcq *ent.ProviderCurrenciesQuery) {
			pcq.Where(providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currencyCode)))
		}).
		All(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to get providers: %w", err)
	}

	// Filter providers by health status
	var healthyProviders []*ent.ProviderProfile

	for _, provider := range providers {
		if len(provider.Edges.ProviderCurrencies) == 0 {
			continue
		}

		isHealthy, err := svc.IsProviderHealthyForCurrency(ctx, provider.ID, currencyCode)
		if err != nil {
			logger.Errorf("Health check failed for provider %s: %v", provider.ID, err)
			continue
		}

		if isHealthy {
			healthyProviders = append(healthyProviders, provider)
		}
	}

	logger.WithFields(logger.Fields{
		"CurrencyCode":     currencyCode,
		"TotalProviders":   len(providers),
		"HealthyProviders": len(healthyProviders),
	}).Infof("Provider health check completed")

	return healthyProviders, nil
}

// BalanceHealthReport represents the result of a balance health check
type BalanceHealthReport struct {
	ProviderID       string          `json:"providerId"`
	CurrencyCode     string          `json:"currencyCode"`
	AvailableBalance decimal.Decimal `json:"availableBalance"`
	ReservedBalance  decimal.Decimal `json:"reservedBalance"`
	TotalBalance     decimal.Decimal `json:"totalBalance"`
	LastUpdated      time.Time       `json:"lastUpdated"`
	Status           string          `json:"status"`
	Severity         string          `json:"severity"`
	Issues           []string        `json:"issues"`
	Recommendations  []string        `json:"recommendations"`
}

// ProviderBalanceStatus represents the balance status of a provider
type ProviderBalanceStatus struct {
	ProviderID       string          `json:"providerId"`
	CurrencyCode     string          `json:"currencyCode"`
	AvailableBalance decimal.Decimal `json:"availableBalance"`
	ReservedBalance  decimal.Decimal `json:"reservedBalance"`
	TotalBalance     decimal.Decimal `json:"totalBalance"`
	LastUpdated      time.Time       `json:"lastUpdated"`
	Status           string          `json:"status"`
	Message          string          `json:"message"`
	Thresholds       ThresholdStatus `json:"thresholds"`
}

// ThresholdStatus represents the threshold configuration for a currency
type ThresholdStatus struct {
	MinimumThreshold  decimal.Decimal `json:"minimumThreshold"`
	AlertThreshold    decimal.Decimal `json:"alertThreshold"`
	CriticalThreshold decimal.Decimal `json:"criticalThreshold"`
}
