package balance

import (
	"context"
	"fmt"
	"time"

	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/providerbalances"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

// ReserveFiatBalance reserves an amount from a provider's available fiat balance.
// If tx is nil, a new transaction will be created and committed.
func (svc *Service) ReserveFiatBalance(ctx context.Context, providerID string, currencyCode string, amount decimal.Decimal, tx *ent.Tx) error {
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
func (svc *Service) ReserveTokenBalance(ctx context.Context, providerID string, tokenID int, amount decimal.Decimal, tx *ent.Tx) error {
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
// If tx is nil, a new transaction will be created and committed.
// If tx is provided, it will be committed after successful balance updates.
func (svc *Service) ReleaseFiatBalance(ctx context.Context, providerID string, currencyCode string, amount decimal.Decimal, tx *ent.Tx) error {
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
	if tx == nil {
		tx, err = svc.client.Tx(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to start transaction for fiat release")
			return fmt.Errorf("failed to start transaction: %w", err)
		}
		defer func() { _ = tx.Rollback() }()
	}
	bal, err = tx.ProviderBalances.Query().
		Where(providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)), providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currencyCode))).
		Only(ctx)
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
	if err := tx.Commit(); err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "Currency": currencyCode}).Errorf("Failed to commit fiat release transaction")
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	logger.WithFields(logger.Fields{"ProviderID": providerID, "Currency": currencyCode, "ReleasedAmount": amount.String(), "NewAvailable": newAvail.String(), "NewReserved": newReserved.String()}).Infof("Reserved fiat balance released successfully")
	return nil
}

// ReleaseTokenBalance releases a previously reserved token amount.
// If tx is nil, a new transaction will be created and committed.
// If tx is provided, it will be committed after successful balance updates.
func (svc *Service) ReleaseTokenBalance(ctx context.Context, providerID string, tokenID int, amount decimal.Decimal, tx *ent.Tx) error {
	// Reject non-positive amounts before any transaction operations
	if amount.LessThanOrEqual(decimal.Zero) {
		logger.WithFields(logger.Fields{"ProviderID": providerID, "TokenID": tokenID, "Amount": amount.String()}).Errorf("ReleaseTokenBalance: invalid amount - must be greater than zero")
		return fmt.Errorf("ReleaseTokenBalance: amount must be greater than zero, got %s", amount.String())
	}

	var bal *ent.ProviderBalances
	var err error
	if tx == nil {
		tx, err = svc.client.Tx(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "TokenID": tokenID}).Errorf("Failed to start transaction for token release")
			return fmt.Errorf("failed to start transaction: %w", err)
		}
		defer func() { _ = tx.Rollback() }()
	}
	bal, err = tx.ProviderBalances.Query().
		Where(providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)), providerbalances.HasTokenWith(token.IDEQ(tokenID))).
		Only(ctx)
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
	if err := tx.Commit(); err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID, "TokenID": tokenID}).Errorf("Failed to commit token release transaction")
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	logger.WithFields(logger.Fields{"ProviderID": providerID, "TokenID": tokenID, "ReleasedAmount": amount.String(), "NewAvailable": newAvail.String(), "NewReserved": newReserved.String()}).Infof("Reserved token balance released successfully")
	return nil
}
