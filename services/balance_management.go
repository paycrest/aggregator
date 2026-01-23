package services

import (
	"context"
	"fmt"
	"time"

	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/providerbalances"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
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

// UpdateProviderFiatBalance updates the fiat balance for a specific provider and currency.
func (svc *BalanceManagementService) UpdateProviderFiatBalance(ctx context.Context, providerID string, currencyCode string, available, total, reserved decimal.Decimal) error {
	bal, err := svc.client.ProviderBalances.Query().
		Where(
			providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)),
			providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to find provider fiat balance for update")
		return fmt.Errorf("provider fiat balance not found: %w", err)
	}
	_, err = bal.Update().
		SetAvailableBalance(available).
		SetTotalBalance(total).
		SetReservedBalance(reserved).
		SetUpdatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to update provider fiat balance")
		return fmt.Errorf("failed to update fiat balance: %w", err)
	}
	logger.WithFields(logger.Fields{"ProviderID": providerID, "Currency": currencyCode, "AvailableBalance": available.String(), "TotalBalance": total.String(), "ReservedBalance": reserved.String()}).Infof("Provider fiat balance updated successfully")
	return nil
}

// GetProviderFiatBalance retrieves the fiat balance for a specific provider and currency.
func (svc *BalanceManagementService) GetProviderFiatBalance(ctx context.Context, providerID string, currencyCode string) (*ent.ProviderBalances, error) {
	bal, err := svc.client.ProviderBalances.Query().
		Where(
			providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)),
			providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		WithProvider().
		WithFiatCurrency().
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to get provider fiat balance")
		return nil, fmt.Errorf("provider fiat balance not found: %w", err)
	}
	return bal, nil
}

// GetProviderTokenBalance retrieves the token balance for a specific provider and token.
func (svc *BalanceManagementService) GetProviderTokenBalance(ctx context.Context, providerID string, tokenID int) (*ent.ProviderBalances, error) {
	bal, err := svc.client.ProviderBalances.Query().
		Where(
			providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)),
			providerbalances.HasTokenWith(token.IDEQ(tokenID)),
		).
		WithProvider().
		WithToken().
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "TokenID": tokenID}).Errorf("Failed to get provider token balance")
		return nil, fmt.Errorf("provider token balance not found: %w", err)
	}
	return bal, nil
}

// UpdateProviderTokenBalance updates the token balance for a specific provider and token.
func (svc *BalanceManagementService) UpdateProviderTokenBalance(ctx context.Context, providerID string, tokenID int, available, total, reserved decimal.Decimal) error {
	bal, err := svc.client.ProviderBalances.Query().
		Where(
			providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)),
			providerbalances.HasTokenWith(token.IDEQ(tokenID)),
		).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "TokenID": tokenID}).Errorf("Failed to find provider token balance for update")
		return fmt.Errorf("provider token balance not found: %w", err)
	}
	_, err = bal.Update().
		SetAvailableBalance(available).
		SetTotalBalance(total).
		SetReservedBalance(reserved).
		SetUpdatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "TokenID": tokenID}).Errorf("Failed to update provider token balance")
		return fmt.Errorf("failed to update token balance: %w", err)
	}
	logger.WithFields(logger.Fields{"ProviderID": providerID, "TokenID": tokenID, "AvailableBalance": available.String(), "TotalBalance": total.String(), "ReservedBalance": reserved.String()}).Infof("Provider token balance updated successfully")
	return nil
}

// UpsertProviderFiatBalance creates or updates the fiat balance for a provider and currency.
// On update, it preserves ReservedBalance (internal reservations for pending orders) and caps
// AvailableBalance by TotalBalance - ReservedBalance to prevent inflating availability.
// New entries are created with is_available=false.
func (svc *BalanceManagementService) UpsertProviderFiatBalance(ctx context.Context, providerID string, currencyCode string, balance *types.ProviderBalance) error {
	existing, err := svc.client.ProviderBalances.Query().
		Where(
			providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)),
			providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		Only(ctx)
	if err != nil {
		if !ent.IsNotFound(err) {
			return fmt.Errorf("failed to query provider fiat balance: %w", err)
		}
		// Create new entry
		provider, err := svc.client.ProviderProfile.Get(ctx, providerID)
		if err != nil {
			return fmt.Errorf("failed to get provider: %w", err)
		}
		fiat, err := svc.client.FiatCurrency.Query().Where(fiatcurrency.CodeEQ(currencyCode)).Only(ctx)
		if err != nil {
			return fmt.Errorf("failed to get fiat currency: %w", err)
		}
		// Cap available balance by total - reserved to prevent inflating availability
		maxAvailable := balance.TotalBalance.Sub(balance.ReservedBalance)
		availableBalance := balance.AvailableBalance
		if maxAvailable.LessThan(availableBalance) {
			availableBalance = maxAvailable
		}
		if availableBalance.LessThan(decimal.Zero) {
			availableBalance = decimal.Zero
		}
		_, err = svc.client.ProviderBalances.Create().
			SetFiatCurrency(fiat).
			SetAvailableBalance(availableBalance).
			SetTotalBalance(balance.TotalBalance).
			SetReservedBalance(balance.ReservedBalance).
			SetIsAvailable(false). // New entries default to false
			SetUpdatedAt(time.Now()).
			SetProviderID(provider.ID).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to create provider fiat balance: %w", err)
		}
		return nil
	}
	// Preserve existing ReservedBalance (our internal reservations for pending orders)
	// Cap available balance by min(provider's reported available, total - reserved)
	existingReserved := existing.ReservedBalance
	maxAvailable := balance.TotalBalance.Sub(existingReserved)
	newAvail := balance.AvailableBalance
	if maxAvailable.LessThan(newAvail) {
		newAvail = maxAvailable
	}
	if newAvail.LessThan(decimal.Zero) {
		newAvail = decimal.Zero
	}
	// Preserve existing is_available status when updating (not modified here)
	_, err = existing.Update().
		SetTotalBalance(balance.TotalBalance).
		SetAvailableBalance(newAvail).
		SetUpdatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to update provider fiat balance: %w", err)
	}
	return nil
}

// UpsertProviderTokenBalance creates or updates the token balance for a provider and token.
// On update, it preserves ReservedBalance and sets AvailableBalance = TotalBalance - ReservedBalance.
// New entries are created with is_available=false.
func (svc *BalanceManagementService) UpsertProviderTokenBalance(ctx context.Context, providerID string, tokenID int, balance *types.ProviderBalance) error {
	existing, err := svc.client.ProviderBalances.Query().
		Where(
			providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)),
			providerbalances.HasTokenWith(token.IDEQ(tokenID)),
		).
		Only(ctx)
	if err != nil {
		if !ent.IsNotFound(err) {
			return fmt.Errorf("failed to query provider token balance: %w", err)
		}
		// Create new entry
		provider, err := svc.client.ProviderProfile.Get(ctx, providerID)
		if err != nil {
			return fmt.Errorf("failed to get provider: %w", err)
		}
		tok, err := svc.client.Token.Get(ctx, tokenID)
		if err != nil {
			return fmt.Errorf("failed to get token: %w", err)
		}
		_, err = svc.client.ProviderBalances.Create().
			SetToken(tok).
			SetTotalBalance(balance.TotalBalance).
			SetAvailableBalance(balance.TotalBalance).
			SetReservedBalance(decimal.Zero).
			SetIsAvailable(false). // New entries default to false
			SetUpdatedAt(time.Now()).
			SetProviderID(provider.ID).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to create provider token balance: %w", err)
		}
		return nil
	}
	existingReserved := existing.ReservedBalance
	newAvail := balance.TotalBalance.Sub(existingReserved)
	if newAvail.LessThan(decimal.Zero) {
		newAvail = decimal.Zero
	}
	// Preserve existing is_available status when updating (not modified here)
	_, err = existing.Update().
		SetTotalBalance(balance.TotalBalance).
		SetAvailableBalance(newAvail).
		SetUpdatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to update provider token balance: %w", err)
	}
	return nil
}

// ReserveFiatBalance reserves an amount from a provider's available fiat balance.
// If tx is nil, a new transaction will be created and committed.
func (svc *BalanceManagementService) ReserveFiatBalance(ctx context.Context, providerID string, currencyCode string, amount decimal.Decimal, tx *ent.Tx) error {
	// Reject non-positive amounts before any transaction operations
	if amount.LessThanOrEqual(decimal.Zero) {
		logger.WithFields(logger.Fields{"ProviderID": providerID, "Currency": currencyCode, "Amount": amount.String()}).Errorf("ReserveFiatBalance: invalid amount - must be greater than zero")
		return fmt.Errorf("ReserveFiatBalance: amount must be greater than zero, got %s", amount.String())
	}

	internalTx := false
	if tx == nil {
		if err := svc.ValidateAndFixBalances(ctx, providerID, currencyCode); err != nil {
			logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to validate or fix balances before fiat reservation")
			return fmt.Errorf("balance validation failed: %w", err)
		}
		var txErr error
		tx, txErr = svc.client.Tx(ctx)
		if txErr != nil {
			logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", txErr), "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to start transaction for fiat reservation")
			return fmt.Errorf("failed to start transaction: %w", txErr)
		}
		internalTx = true
		defer func() { _ = tx.Rollback() }()
	}

	bal, err := tx.ProviderBalances.Query().
		Where(
			providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)),
			providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to get provider fiat balance for reservation")
		return fmt.Errorf("failed to get provider fiat balance: %w", err)
	}
	if bal.AvailableBalance.LessThan(amount) {
		logger.WithFields(logger.Fields{"ProviderID": providerID, "Currency": currencyCode, "AvailableBalance": bal.AvailableBalance.String(), "RequestedAmount": amount.String()}).Warnf("Insufficient available fiat balance for reservation")
		return fmt.Errorf("insufficient available balance: available=%s, requested=%s", bal.AvailableBalance.String(), amount.String())
	}

	newAvail := bal.AvailableBalance.Sub(amount)
	newReserved := bal.ReservedBalance.Add(amount)
	_, err = bal.Update().SetAvailableBalance(newAvail).SetReservedBalance(newReserved).SetUpdatedAt(time.Now()).Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to reserve fiat balance")
		return fmt.Errorf("failed to reserve fiat balance: %w", err)
	}
	if internalTx {
		if err := tx.Commit(); err != nil {
			logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to commit fiat reservation transaction")
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
	}
	logger.WithFields(logger.Fields{"ProviderID": providerID, "Currency": currencyCode, "ReservedAmount": amount.String(), "NewAvailable": newAvail.String(), "NewReserved": newReserved.String()}).Infof("Fiat balance reserved successfully")
	return nil
}

// ReserveTokenBalance reserves an amount from a provider's available token balance.
// If tx is nil, a new transaction will be created and committed.
func (svc *BalanceManagementService) ReserveTokenBalance(ctx context.Context, providerID string, tokenID int, amount decimal.Decimal, tx *ent.Tx) error {
	// Reject non-positive amounts before any transaction operations
	if amount.LessThanOrEqual(decimal.Zero) {
		logger.WithFields(logger.Fields{"ProviderID": providerID, "TokenID": tokenID, "Amount": amount.String()}).Errorf("ReserveTokenBalance: invalid amount - must be greater than zero")
		return fmt.Errorf("ReserveTokenBalance: amount must be greater than zero, got %s", amount.String())
	}

	internalTx := false
	if tx == nil {
		var txErr error
		tx, txErr = svc.client.Tx(ctx)
		if txErr != nil {
			logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", txErr), "ProviderID": providerID, "TokenID": tokenID}).Errorf("Failed to start transaction for token reservation")
			return fmt.Errorf("failed to start transaction: %w", txErr)
		}
		internalTx = true
		defer func() { _ = tx.Rollback() }()
	}

	bal, err := tx.ProviderBalances.Query().
		Where(
			providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)),
			providerbalances.HasTokenWith(token.IDEQ(tokenID)),
		).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "TokenID": tokenID}).Errorf("Failed to get provider token balance for reservation")
		return fmt.Errorf("failed to get provider token balance: %w", err)
	}
	if bal.AvailableBalance.LessThan(amount) {
		logger.WithFields(logger.Fields{"ProviderID": providerID, "TokenID": tokenID, "AvailableBalance": bal.AvailableBalance.String(), "RequestedAmount": amount.String()}).Warnf("Insufficient available token balance for reservation")
		return fmt.Errorf("insufficient available token balance: available=%s, requested=%s", bal.AvailableBalance.String(), amount.String())
	}

	newAvail := bal.AvailableBalance.Sub(amount)
	newReserved := bal.ReservedBalance.Add(amount)
	_, err = bal.Update().SetAvailableBalance(newAvail).SetReservedBalance(newReserved).SetUpdatedAt(time.Now()).Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "TokenID": tokenID}).Errorf("Failed to reserve token balance")
		return fmt.Errorf("failed to reserve token balance: %w", err)
	}
	if internalTx {
		if err := tx.Commit(); err != nil {
			logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "TokenID": tokenID}).Errorf("Failed to commit token reservation transaction")
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
	}
	logger.WithFields(logger.Fields{"ProviderID": providerID, "TokenID": tokenID, "ReservedAmount": amount.String(), "NewAvailable": newAvail.String(), "NewReserved": newReserved.String()}).Infof("Token balance reserved successfully")
	return nil
}

// ReleaseFiatBalance releases a previously reserved fiat amount.
// If tx is provided, the operation is performed within that transaction.
func (svc *BalanceManagementService) ReleaseFiatBalance(ctx context.Context, providerID string, currencyCode string, amount decimal.Decimal, tx *ent.Tx) error {
	// Reject non-positive amounts before any transaction operations
	if amount.LessThanOrEqual(decimal.Zero) {
		logger.WithFields(logger.Fields{"ProviderID": providerID, "Currency": currencyCode, "Amount": amount.String()}).Errorf("ReleaseFiatBalance: invalid amount - must be greater than zero")
		return fmt.Errorf("ReleaseFiatBalance: amount must be greater than zero, got %s", amount.String())
	}

	if tx == nil {
		if err := svc.ValidateAndFixBalances(ctx, providerID, currencyCode); err != nil {
			logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to validate or fix balances before fiat release")
			return fmt.Errorf("balance validation failed: %w", err)
		}
	}
	var bal *ent.ProviderBalances
	var err error
	var shouldCommit bool
	if tx != nil {
		bal, err = tx.ProviderBalances.Query().
			Where(providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)), providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currencyCode))).
			Only(ctx)
	} else {
		tx, err = svc.client.Tx(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to start transaction for fiat release")
			return fmt.Errorf("failed to start transaction: %w", err)
		}
		shouldCommit = true
		defer func() { _ = tx.Rollback() }()
		bal, err = tx.ProviderBalances.Query().
			Where(providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)), providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currencyCode))).
			Only(ctx)
	}
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to get provider fiat balance for release")
		return fmt.Errorf("failed to get provider fiat balance: %w", err)
	}
	amountToRelease := amount
	if bal.ReservedBalance.LessThan(amount) {
		if !bal.ReservedBalance.Equal(decimal.Zero) {
			logger.WithFields(logger.Fields{"ProviderID": providerID, "Currency": currencyCode, "ReservedBalance": bal.ReservedBalance.String(), "ReleaseAmount": amount.String()}).Warnf("Insufficient reserved fiat balance for release")
			return fmt.Errorf("insufficient reserved balance: reserved=%s, requested=%s", bal.ReservedBalance.String(), amount.String())
		}
		// Reserved is zero, nothing to release
		amountToRelease = decimal.Zero
		logger.WithFields(logger.Fields{"ProviderID": providerID, "Currency": currencyCode, "Requested": amount.String()}).Infof("Provider has zero reserved fiat balance, skipping release")
	}
	newReserved := bal.ReservedBalance.Sub(amountToRelease)
	newAvail := bal.AvailableBalance.Add(amountToRelease)
	_, err = bal.Update().SetAvailableBalance(newAvail).SetReservedBalance(newReserved).SetUpdatedAt(time.Now()).Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to release reserved fiat balance")
		return fmt.Errorf("failed to release reserved fiat balance: %w", err)
	}
	if shouldCommit {
		if err := tx.Commit(); err != nil {
			logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to commit fiat release transaction")
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
	}
	logger.WithFields(logger.Fields{"ProviderID": providerID, "Currency": currencyCode, "ReleasedAmount": amount.String(), "NewAvailable": newAvail.String(), "NewReserved": newReserved.String()}).Infof("Reserved fiat balance released successfully")
	return nil
}

// ReleaseTokenBalance releases a previously reserved token amount.
// If tx is provided, the operation is performed within that transaction.
func (svc *BalanceManagementService) ReleaseTokenBalance(ctx context.Context, providerID string, tokenID int, amount decimal.Decimal, tx *ent.Tx) error {
	// Reject non-positive amounts before any transaction operations
	if amount.LessThanOrEqual(decimal.Zero) {
		logger.WithFields(logger.Fields{"ProviderID": providerID, "TokenID": tokenID, "Amount": amount.String()}).Errorf("ReleaseTokenBalance: invalid amount - must be greater than zero")
		return fmt.Errorf("ReleaseTokenBalance: amount must be greater than zero, got %s", amount.String())
	}

	var bal *ent.ProviderBalances
	var err error
	var shouldCommit bool
	if tx != nil {
		bal, err = tx.ProviderBalances.Query().
			Where(providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)), providerbalances.HasTokenWith(token.IDEQ(tokenID))).
			Only(ctx)
	} else {
		tx, err = svc.client.Tx(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "TokenID": tokenID}).Errorf("Failed to start transaction for token release")
			return fmt.Errorf("failed to start transaction: %w", err)
		}
		shouldCommit = true
		defer func() { _ = tx.Rollback() }()
		bal, err = tx.ProviderBalances.Query().
			Where(providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)), providerbalances.HasTokenWith(token.IDEQ(tokenID))).
			Only(ctx)
	}
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "TokenID": tokenID}).Errorf("Failed to get provider token balance for release")
		return fmt.Errorf("failed to get provider token balance: %w", err)
	}
	amountToRelease := amount
	if bal.ReservedBalance.LessThan(amount) {
		if !bal.ReservedBalance.Equal(decimal.Zero) {
			logger.WithFields(logger.Fields{"ProviderID": providerID, "TokenID": tokenID, "ReservedBalance": bal.ReservedBalance.String(), "ReleaseAmount": amount.String()}).Warnf("Insufficient reserved token balance for release")
			return fmt.Errorf("insufficient reserved token balance: reserved=%s, requested=%s", bal.ReservedBalance.String(), amount.String())
		}
		// Reserved is zero, nothing to release
		amountToRelease = decimal.Zero
		logger.WithFields(logger.Fields{"ProviderID": providerID, "TokenID": tokenID, "Requested": amount.String()}).Infof("Provider has zero reserved token balance, skipping release")
	}
	newReserved := bal.ReservedBalance.Sub(amountToRelease)
	newAvail := bal.AvailableBalance.Add(amountToRelease)
	_, err = bal.Update().SetAvailableBalance(newAvail).SetReservedBalance(newReserved).SetUpdatedAt(time.Now()).Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "TokenID": tokenID}).Errorf("Failed to release reserved token balance")
		return fmt.Errorf("failed to release reserved token balance: %w", err)
	}
	if shouldCommit {
		if err := tx.Commit(); err != nil {
			logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "TokenID": tokenID}).Errorf("Failed to commit token release transaction")
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
	}
	logger.WithFields(logger.Fields{"ProviderID": providerID, "TokenID": tokenID, "ReleasedAmount": amount.String(), "NewAvailable": newAvail.String(), "NewReserved": newReserved.String()}).Infof("Reserved token balance released successfully")
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

	bal, err := tx.ProviderBalances.Query().
		Where(
			providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)),
			providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "OrderID": orderID, "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to get provider fiat balance for order timeout")
		return fmt.Errorf("failed to get provider fiat balance: %w", err)
	}
	if bal.ReservedBalance.LessThanOrEqual(decimal.Zero) {
		logger.WithFields(logger.Fields{"OrderID": orderID, "ProviderID": providerID, "Currency": currencyCode, "Amount": amount.String()}).Infof("No reserved balance to release for timed out order")
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit timeout transaction: %w", err)
		}
		return nil
	}
	amountToRelease := decimal.Min(amount, bal.ReservedBalance)
	newReservedBalance := bal.ReservedBalance.Sub(amountToRelease)
	newAvailableBalance := bal.AvailableBalance.Add(amountToRelease)
	if newReservedBalance.LessThan(decimal.Zero) {
		newReservedBalance = decimal.Zero
	}
	_, err = bal.Update().
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

	bal, err := tx.ProviderBalances.Query().
		Where(
			providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)),
			providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "OrderID": orderID, "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to get provider fiat balance for order cancellation")
		return fmt.Errorf("failed to get provider fiat balance: %w", err)
	}
	// Only release what's actually reserved to avoid over-crediting
	amountToRelease := decimal.Min(amount, bal.ReservedBalance)
	if amountToRelease.LessThan(decimal.Zero) {
		amountToRelease = decimal.Zero
	}
	newReservedBalance := bal.ReservedBalance.Sub(amountToRelease)
	newAvailableBalance := bal.AvailableBalance.Add(amountToRelease)
	if amountToRelease.LessThan(amount) {
		logger.WithFields(logger.Fields{"OrderID": orderID, "ProviderID": providerID, "Currency": currencyCode, "RequestedAmount": amount.String(), "ActualReleased": amountToRelease.String()}).Warnf("Released less than requested for cancelled order")
	}
	_, err = bal.Update().
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
		"OrderID":         orderID,
		"ProviderID":      providerID,
		"Currency":        currencyCode,
		"RequestedAmount": amount.String(),
		"ReleasedAmount":  amountToRelease.String(),
		"NewAvailable":    newAvailableBalance.String(),
		"NewReserved":     newReservedBalance.String(),
	}).Infof("Successfully cancelled order and released reserved balance")

	return nil
}

// CancelOrderAndReleaseBalanceWithinTransaction cancels an order and releases balance within an existing transaction.
func (svc *BalanceManagementService) CancelOrderAndReleaseBalanceWithinTransaction(ctx context.Context, orderID string, providerID string, currencyCode string, amount decimal.Decimal, tx *ent.Tx) error {
	bal, err := tx.ProviderBalances.Query().
		Where(
			providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)),
			providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "OrderID": orderID, "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to get provider fiat balance for order cancellation within transaction")
		return fmt.Errorf("failed to get provider fiat balance: %w", err)
	}
	// Only release what's actually reserved to avoid over-crediting
	amountToRelease := decimal.Min(amount, bal.ReservedBalance)
	if amountToRelease.LessThan(decimal.Zero) {
		amountToRelease = decimal.Zero
	}
	newReservedBalance := bal.ReservedBalance.Sub(amountToRelease)
	newAvailableBalance := bal.AvailableBalance.Add(amountToRelease)
	if amountToRelease.LessThan(amount) {
		logger.WithFields(logger.Fields{"OrderID": orderID, "ProviderID": providerID, "Currency": currencyCode, "RequestedAmount": amount.String(), "ActualReleased": amountToRelease.String()}).Warnf("Released less than requested for cancelled order within transaction")
	}
	_, err = bal.Update().
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
	err := svc.ReleaseFiatBalance(ctx, providerID, currencyCode, amount, nil)
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

// GetProviderBalances retrieves all balances (fiat + token) for a specific provider.
func (svc *BalanceManagementService) GetProviderBalances(ctx context.Context, providerID string) ([]*ent.ProviderBalances, error) {
	list, err := svc.client.ProviderBalances.Query().
		Where(providerbalances.HasProviderWith(providerprofile.IDEQ(providerID))).
		WithProvider().
		WithFiatCurrency().
		WithToken().
		All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID}).Errorf("Failed to get provider balances")
		return nil, fmt.Errorf("failed to get provider balances: %w", err)
	}
	return list, nil
}

// CheckBalanceSufficiency checks if the given balance has sufficient available amount.
// The caller loads the balance first (e.g. via GetProviderFiatBalance or GetProviderTokenBalance).
func (svc *BalanceManagementService) CheckBalanceSufficiency(balance *ent.ProviderBalances, amount decimal.Decimal) bool {
	return balance.AvailableBalance.GreaterThanOrEqual(amount)
}

// ValidateBalanceConsistency validates that the given balance is logically consistent.
// The caller loads the balance first.
func (svc *BalanceManagementService) ValidateBalanceConsistency(balance *ent.ProviderBalances) error {
	if balance.AvailableBalance.Add(balance.ReservedBalance).GreaterThan(balance.TotalBalance) {
		return fmt.Errorf("balance inconsistency: available + reserved > total for balance %s", balance.ID)
	}
	if balance.AvailableBalance.LessThan(decimal.Zero) {
		return fmt.Errorf("negative available balance for balance %s: %s", balance.ID, balance.AvailableBalance.String())
	}
	if balance.ReservedBalance.LessThan(decimal.Zero) {
		return fmt.Errorf("negative reserved balance for balance %s: %s", balance.ID, balance.ReservedBalance.String())
	}
	if balance.TotalBalance.LessThan(decimal.Zero) {
		return fmt.Errorf("negative total balance for balance %s: %s", balance.ID, balance.TotalBalance.String())
	}
	return nil
}

// FixBalanceInconsistencies fixes common inconsistencies on the given balance within the transaction.
// The caller loads the balance and provides the transaction.
func (svc *BalanceManagementService) FixBalanceInconsistencies(ctx context.Context, balance *ent.ProviderBalances, tx *ent.Tx) error {
	var needsUpdate bool
	av, rv, tv := balance.AvailableBalance, balance.ReservedBalance, balance.TotalBalance
	if av.LessThan(decimal.Zero) {
		av = decimal.Zero
		needsUpdate = true
		logger.WithFields(logger.Fields{"BalanceID": balance.ID}).Warnf("Fixed negative available balance")
	}
	if rv.LessThan(decimal.Zero) {
		rv = decimal.Zero
		needsUpdate = true
		logger.WithFields(logger.Fields{"BalanceID": balance.ID}).Warnf("Fixed negative reserved balance")
	}
	if tv.LessThan(decimal.Zero) {
		tv = decimal.Zero
		needsUpdate = true
		logger.WithFields(logger.Fields{"BalanceID": balance.ID}).Warnf("Fixed negative total balance")
	}
	if av.Add(rv).GreaterThan(tv) {
		tv = av.Add(rv)
		needsUpdate = true
		logger.WithFields(logger.Fields{"BalanceID": balance.ID}).Warnf("Fixed balance inconsistency by adjusting total")
	}
	if needsUpdate {
		_, err := balance.Update().
			SetAvailableBalance(av).
			SetTotalBalance(tv).
			SetReservedBalance(rv).
			SetUpdatedAt(time.Now()).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to update balance after fixing inconsistencies: %w", err)
		}
		logger.WithFields(logger.Fields{"BalanceID": balance.ID, "AvailableBalance": av.String(), "TotalBalance": tv.String(), "ReservedBalance": rv.String()}).Infof("Fixed balance inconsistencies")
	}
	return nil
}

// ValidateAndFixBalances validates and fixes fiat balance inconsistencies for the given provider and currency.
func (svc *BalanceManagementService) ValidateAndFixBalances(ctx context.Context, providerID string, currencyCode string) error {
	tx, err := svc.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction for balance validation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	bal, err := tx.ProviderBalances.Query().
		Where(
			providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)),
			providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		Only(ctx)
	if err != nil {
		return fmt.Errorf("failed to get provider fiat balance for validation: %w", err)
	}

	if validationErr := svc.ValidateBalanceConsistency(bal); validationErr != nil {
		logger.WithFields(logger.Fields{"ProviderID": providerID, "Currency": currencyCode, "Error": validationErr.Error()}).Warnf("Balance validation failed, attempting to fix")
		if fixErr := svc.FixBalanceInconsistencies(ctx, bal, tx); fixErr != nil {
			return fmt.Errorf("failed to validate or fix balances: validation: %w, fix: %w", validationErr, fixErr)
		}
		bal, err = tx.ProviderBalances.Query().
			Where(providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)), providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currencyCode))).
			Only(ctx)
		if err != nil {
			return fmt.Errorf("failed to reload provider balance after fix: %w", err)
		}
		if validationErr = svc.ValidateBalanceConsistency(bal); validationErr != nil {
			return fmt.Errorf("balance validation still failed after fixing: %w", validationErr)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit balance validation transaction: %w", err)
	}
	return nil
}

// CheckBalanceHealth performs a health check on the given balance (loaded with WithProvider/WithFiatCurrency/WithToken for full labels).
func (svc *BalanceManagementService) CheckBalanceHealth(balance *ent.ProviderBalances) *BalanceHealthReport {
	providerID := ""
	if balance.Edges.Provider != nil {
		providerID = balance.Edges.Provider.ID
	}
	currencyCode := ""
	if balance.Edges.FiatCurrency != nil {
		currencyCode = balance.Edges.FiatCurrency.Code
	}

	report := &BalanceHealthReport{
		ProviderID:       providerID,
		CurrencyCode:     currencyCode,
		AvailableBalance: balance.AvailableBalance,
		ReservedBalance:  balance.ReservedBalance,
		TotalBalance:     balance.TotalBalance,
		LastUpdated:      balance.UpdatedAt,
		Issues:           []string{},
		Recommendations:  []string{},
	}

	if balance.AvailableBalance.LessThan(decimal.Zero) {
		report.Issues = append(report.Issues, fmt.Sprintf("Negative available balance: %s", balance.AvailableBalance.String()))
		report.Recommendations = append(report.Recommendations, "Reset available balance to zero")
		report.Severity = "HIGH"
	}
	if balance.ReservedBalance.LessThan(decimal.Zero) {
		report.Issues = append(report.Issues, fmt.Sprintf("Negative reserved balance: %s", balance.ReservedBalance.String()))
		report.Recommendations = append(report.Recommendations, "Reset reserved balance to zero")
		report.Severity = "HIGH"
	}
	if balance.TotalBalance.LessThan(decimal.Zero) {
		report.Issues = append(report.Issues, fmt.Sprintf("Negative total balance: %s", balance.TotalBalance.String()))
		report.Recommendations = append(report.Recommendations, "Reset total balance to zero")
		report.Severity = "HIGH"
	}
	calculatedTotal := balance.AvailableBalance.Add(balance.ReservedBalance)
	if calculatedTotal.GreaterThan(balance.TotalBalance) {
		report.Issues = append(report.Issues, fmt.Sprintf("Logical inconsistency: available + reserved (%s) > total (%s)", calculatedTotal.String(), balance.TotalBalance.String()))
		report.Recommendations = append(report.Recommendations, "Adjust total balance to match available + reserved")
		report.Severity = "MEDIUM"
	}
	if balance.AvailableBalance.Equal(decimal.Zero) && balance.ReservedBalance.Equal(decimal.Zero) && balance.TotalBalance.Equal(decimal.Zero) {
		report.Issues = append(report.Issues, "All balance fields are zero - may indicate uninitialized provider")
		report.Recommendations = append(report.Recommendations, "Verify provider balance initialization")
		report.Severity = "LOW"
	}
	if balance.ReservedBalance.GreaterThan(balance.TotalBalance) {
		report.Issues = append(report.Issues, fmt.Sprintf("Reserved balance (%s) exceeds total balance (%s)", balance.ReservedBalance.String(), balance.TotalBalance.String()))
		report.Recommendations = append(report.Recommendations, "Investigate order assignment logic")
		report.Severity = "HIGH"
	}

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
	return report
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
