package tasks

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/providerbalances"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	tokenent "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/services/balance"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

// initializeProviderBalances creates balance entries for all providers based on their provider_order_tokens configuration.
// For each provider, it creates:
// - Token balance entries for all tokens in provider_order_tokens (with is_available=false)
// - Fiat balance entries for all currencies in provider_order_tokens (with is_available=false)
// Existing balance entries are not modified (preserves is_available status).
func initializeProviderBalances(ctx context.Context, providers []*ent.ProviderProfile) error {
	for _, provider := range providers {
		// Get all provider_order_tokens for this provider
		orderTokens, err := storage.Client.ProviderOrderToken.
			Query().
			Where(providerordertoken.HasProviderWith(providerprofile.IDEQ(provider.ID))).
			WithToken().
			WithCurrency().
			All(ctx)
		if err != nil {
			logger.Warnf("Failed to fetch provider_order_tokens for provider %s: %v", provider.ID, err)
			continue
		}

		// Track unique tokens and currencies
		tokenIDs := make(map[int]bool)
		currencyCodes := make(map[string]bool)

		for _, orderToken := range orderTokens {
			// Track unique tokens
			if orderToken.Edges.Token != nil {
				tokenIDs[orderToken.Edges.Token.ID] = true
			}
			// Track unique currencies
			if orderToken.Edges.Currency != nil {
				currencyCodes[orderToken.Edges.Currency.Code] = true
			}
		}

		// Create token balance entries for missing tokens
		for tokenID := range tokenIDs {
			exists, err := storage.Client.ProviderBalances.Query().
				Where(
					providerbalances.HasProviderWith(providerprofile.IDEQ(provider.ID)),
					providerbalances.HasTokenWith(tokenent.IDEQ(tokenID)),
				).
				Exist(ctx)
			if err != nil {
				logger.Warnf("Failed to check token balance existence for provider %s token %d: %v", provider.ID, tokenID, err)
				continue
			}
			if !exists {
				tok, err := storage.Client.Token.Get(ctx, tokenID)
				if err != nil {
					logger.Warnf("Failed to get token %d for provider %s: %v", tokenID, provider.ID, err)
					continue
				}
				_, err = storage.Client.ProviderBalances.Create().
					SetProviderID(provider.ID).
					SetToken(tok).
					SetTotalBalance(decimal.Zero).
					SetAvailableBalance(decimal.Zero).
					SetReservedBalance(decimal.Zero).
					SetIsAvailable(false).
					SetUpdatedAt(time.Now()).
					Save(ctx)
				if err != nil {
					logger.Warnf("Failed to create token balance entry for provider %s token %d: %v", provider.ID, tokenID, err)
					continue
				}
				logger.Debugf("Created token balance entry for provider %s token %d (is_available=false)", provider.ID, tokenID)
			}
		}

		// Create fiat balance entries for missing currencies
		for currencyCode := range currencyCodes {
			exists, err := storage.Client.ProviderBalances.Query().
				Where(
					providerbalances.HasProviderWith(providerprofile.IDEQ(provider.ID)),
					providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
				).
				Exist(ctx)
			if err != nil {
				logger.Warnf("Failed to check fiat balance existence for provider %s currency %s: %v", provider.ID, currencyCode, err)
				continue
			}
			if !exists {
				fiat, err := storage.Client.FiatCurrency.Query().Where(fiatcurrency.CodeEQ(currencyCode)).Only(ctx)
				if err != nil {
					logger.Warnf("Failed to get fiat currency %s for provider %s: %v", currencyCode, provider.ID, err)
					continue
				}
				_, err = storage.Client.ProviderBalances.Create().
					SetProviderID(provider.ID).
					SetFiatCurrency(fiat).
					SetTotalBalance(decimal.Zero).
					SetAvailableBalance(decimal.Zero).
					SetReservedBalance(decimal.Zero).
					SetIsAvailable(false).
					SetUpdatedAt(time.Now()).
					Save(ctx)
				if err != nil {
					logger.Warnf("Failed to create fiat balance entry for provider %s currency %s: %v", provider.ID, currencyCode, err)
					continue
				}
				logger.Debugf("Created fiat balance entry for provider %s currency %s (is_available=false)", provider.ID, currencyCode)
			}
		}
	}
	return nil
}

// FetchProviderBalances fetches balance updates from all providers
func FetchProviderBalances() error {
	ctx := context.Background()
	startTime := time.Now()
	balanceService := balance.New()

	logProviderBalanceHealth := func(providerID string, reason string, err error) {
		balances, getErr := balanceService.GetProviderBalances(ctx, providerID)
		if getErr != nil {
			logger.WithFields(logger.Fields{
				"ProviderID": providerID,
				"Reason":     reason,
				"Error":      fmt.Sprintf("%v", err),
				"GetError":   fmt.Sprintf("%v", getErr),
			}).Errorf("Balance health check skipped: failed to load provider balances")
			return
		}

		for _, bal := range balances {
			report := balanceService.CheckBalanceHealth(bal)
			if report == nil || report.Status == "HEALTHY" {
				continue
			}
			logger.WithFields(logger.Fields{
				"ProviderID":       report.ProviderID,
				"CurrencyCode":     report.CurrencyCode,
				"Status":           report.Status,
				"Severity":         report.Severity,
				"AvailableBalance": report.AvailableBalance.String(),
				"ReservedBalance":  report.ReservedBalance.String(),
				"TotalBalance":     report.TotalBalance.String(),
				"Issues":           report.Issues,
				"Recommendations":  report.Recommendations,
				"Reason":           reason,
				"Error":            fmt.Sprintf("%v", err),
			}).Errorf("Provider balance health check flagged issues")
		}
	}

	// Get all provider profiles
	providers, err := storage.Client.ProviderProfile.
		Query().
		Where(
			providerprofile.HostIdentifierNEQ(""),
			providerprofile.IsActiveEQ(true),
		).
		All(ctx)
	if err != nil {
		logger.Errorf("Failed to fetch provider profiles: %v", err)
		return err
	}

	if len(providers) == 0 {
		logger.Infof("No providers found, skipping balance fetch")
		return nil
	}

	// Initialize balance entries for all providers based on their provider_order_tokens
	// This ensures all providers have balance entries (with is_available=false) even if they haven't been fetched yet
	if err := initializeProviderBalances(ctx, providers); err != nil {
		logger.Warnf("Failed to initialize provider balances: %v (continuing with fetch)", err)
		// Don't return error - continue with balance fetch even if initialization fails
	}

	type balanceResult struct {
		providerID    string
		fiatBalances  map[string]*types.ProviderBalance
		tokenBalances map[int]*types.ProviderBalance
		err           error
	}

	results := make(chan balanceResult, len(providers))
	for _, provider := range providers {
		go func(p *ent.ProviderProfile) {
			var fiat map[string]*types.ProviderBalance
			var token map[int]*types.ProviderBalance
			var err1, err2 error

			// Fetch fiat and token balances in parallel
			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				fiat, err1 = balanceService.FetchProviderFiatBalances(ctx, p.ID)
			}()

			go func() {
				defer wg.Done()
				token, err2 = balanceService.FetchProviderTokenBalances(ctx, p.ID)
			}()

			wg.Wait()

			// Combine errors
			err := err1
			if err == nil {
				err = err2
			}
			results <- balanceResult{providerID: p.ID, fiatBalances: fiat, tokenBalances: token, err: err}
		}(provider)
	}

	successCount := 0
	errorCount := 0
	totalBalanceUpdates := 0

	for i := 0; i < len(providers); i++ {
		result := <-results
		if result.err != nil {
			logger.Errorf("Failed to fetch balances for provider %s: %v", result.providerID, result.err)
			logProviderBalanceHealth(result.providerID, "fetch_failed", result.err)
			errorCount++
			continue
		}
		hadUpsertError := false
		for currency, balance := range result.fiatBalances {
			err := utils.Retry(3, 2*time.Second, func() error {
				return balanceService.UpsertProviderFiatBalance(ctx, result.providerID, currency, balance)
			})
			if err != nil {
				logger.Errorf("Failed to update fiat balance for provider %s currency %s: %v", result.providerID, currency, err)
				hadUpsertError = true
				errorCount++
				continue
			}
			totalBalanceUpdates++
		}
		for tokenID, balance := range result.tokenBalances {
			err := utils.Retry(3, 2*time.Second, func() error {
				return balanceService.UpsertProviderTokenBalance(ctx, result.providerID, tokenID, balance)
			})
			if err != nil {
				logger.Errorf("Failed to update token balance for provider %s token %d: %v", result.providerID, tokenID, err)
				hadUpsertError = true
				errorCount++
				continue
			}
			totalBalanceUpdates++
		}
		if hadUpsertError {
			logProviderBalanceHealth(result.providerID, "upsert_failed", fmt.Errorf("one or more balance upserts failed"))
		}
		successCount++
		logger.Infof("Successfully updated balances for provider %s", result.providerID)
	}

	duration := time.Since(startTime)
	logger.Infof("Provider balance fetch completed: %d success, %d errors, %d balance updates in %v",
		successCount, errorCount, totalBalanceUpdates, duration)

	// Alert if more than 50% of providers failed
	if errorCount > 0 && float64(errorCount)/float64(len(providers)) > 0.5 {
		logger.Errorf("ALERT: More than 50%% of providers failed balance fetch: %d/%d", errorCount, len(providers))
		return fmt.Errorf("more than 50%% of providers failed balance fetch: %d/%d", errorCount, len(providers))
	}

	// Alert if no balance updates were made
	if totalBalanceUpdates == 0 {
		logger.Warnf("ALERT: No balance updates were made during this fetch cycle")
	}

	// Log performance metrics
	if duration > 30*time.Second {
		logger.Warnf("ALERT: Balance fetch took longer than expected: %v", duration)
	}

	return nil
}
