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
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

// UpdateProviderFiatBalance updates the fiat balance for a specific provider and currency.
//
// NOTE: The ReservedBalance field is managed internally by the aggregator (reservations for pending orders).
// External/provider-reported balance updates should NOT overwrite reserved. Use
// UpdateProviderFiatBalanceFromProvider (or UpsertProviderFiatBalance) for provider-reported totals.
func (svc *Service) UpdateProviderFiatBalance(ctx context.Context, providerID string, currencyCode string, available, total, reserved decimal.Decimal) error {
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

// UpdateProviderFiatBalanceFromProvider updates a provider's fiat balance using provider-reported values.
// It preserves the existing ReservedBalance (internal reservations) and caps AvailableBalance by
// TotalBalance - ReservedBalance to prevent inflating availability.
func (svc *Service) UpdateProviderFiatBalanceFromProvider(ctx context.Context, providerID string, currencyCode string, available, total decimal.Decimal) error {
	return svc.UpsertProviderFiatBalance(ctx, providerID, currencyCode, &types.ProviderBalance{
		AvailableBalance: available,
		TotalBalance:     total,
		ReservedBalance:  decimal.Zero, // ignored/preserved internally on update
		LastUpdated:      time.Now(),
	})
}

// GetProviderFiatBalance retrieves the fiat balance for a specific provider and currency.
func (svc *Service) GetProviderFiatBalance(ctx context.Context, providerID string, currencyCode string) (*ent.ProviderBalances, error) {
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

// UpsertProviderFiatBalance creates or updates the fiat balance for a provider and currency.
// On update, it preserves ReservedBalance (internal reservations for pending orders) and caps
// AvailableBalance by TotalBalance - ReservedBalance to prevent inflating availability.
// New entries are created with is_available=false.
func (svc *Service) UpsertProviderFiatBalance(ctx context.Context, providerID string, currencyCode string, balance *types.ProviderBalance) error {
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

// GetProviderTokenBalance retrieves the token balance for a specific provider and token.
func (svc *Service) GetProviderTokenBalance(ctx context.Context, providerID string, tokenID int) (*ent.ProviderBalances, error) {
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
func (svc *Service) UpdateProviderTokenBalance(ctx context.Context, providerID string, tokenID int, available, total, reserved decimal.Decimal) error {
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

// UpsertProviderTokenBalance creates or updates the token balance for a provider and token.
// On update, it preserves ReservedBalance and sets AvailableBalance = TotalBalance - ReservedBalance.
// New entries are created with is_available=false.
func (svc *Service) UpsertProviderTokenBalance(ctx context.Context, providerID string, tokenID int, balance *types.ProviderBalance) error {
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
