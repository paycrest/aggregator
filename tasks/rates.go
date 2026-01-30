package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	tokenent "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils"
	"github.com/shopspring/decimal"
)

// fetchExternalRate fetches the external rates (buy and sell) for a fiat currency
func fetchExternalRate(currency string) (buyRate, sellRate decimal.Decimal, err error) {
	currency = strings.ToUpper(currency)
	supportedCurrencies := []string{"KES", "NGN", "GHS", "MWK", "TZS", "UGX", "XOF", "BRL"}
	isSupported := false
	for _, supported := range supportedCurrencies {
		if currency == supported {
			isSupported = true
			break
		}
	}
	if !isSupported {
		return decimal.Zero, decimal.Zero, fmt.Errorf("ComputeMarketRate: currency not supported")
	}

	// Fetch rates from noblocks rates API
	res, err := fastshot.NewClient("https://api.rates.noblocks.xyz").
		Config().SetTimeout(30*time.Second).
		Build().GET(fmt.Sprintf("/rates/usdt/%s", strings.ToLower(currency))).
		Retry().Set(3, 5*time.Second).
		Send()
	if err != nil {
		return decimal.Zero, decimal.Zero, fmt.Errorf("ComputeMarketRate: %w", err)
	}

	// Read the response body manually since we need to parse an array, not an object
	responseBody, err := io.ReadAll(res.RawResponse.Body)
	defer res.RawResponse.Body.Close()
	if err != nil {
		return decimal.Zero, decimal.Zero, fmt.Errorf("ComputeMarketRate: failed to read response body: %w", err)
	}

	var dataArray []map[string]interface{}
	err = json.Unmarshal(responseBody, &dataArray)
	if err != nil {
		return decimal.Zero, decimal.Zero, fmt.Errorf("ComputeMarketRate: failed to parse JSON response: %w", err)
	}

	// Check if we have data
	if len(dataArray) == 0 {
		return decimal.Zero, decimal.Zero, fmt.Errorf("ComputeMarketRate: No data in the response")
	}

	// Get the first rate object
	rateData := dataArray[0]

	// Extract buy and sell rates
	buyRateFloat, ok := rateData["buyRate"].(float64)
	if !ok {
		return decimal.Zero, decimal.Zero, fmt.Errorf("ComputeMarketRate: Invalid buyRate format")
	}

	sellRateFloat, ok := rateData["sellRate"].(float64)
	if !ok {
		return decimal.Zero, decimal.Zero, fmt.Errorf("ComputeMarketRate: Invalid sellRate format")
	}

	// Swap buy and sell rates to match sender perspective
	buyRate = decimal.NewFromFloat(sellRateFloat)
	sellRate = decimal.NewFromFloat(buyRateFloat)

	return buyRate, sellRate, nil
}

// ComputeMarketRate computes the market price for fiat currencies
func ComputeMarketRate() error {
	// ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	// defer cancel()
	ctx := context.Background()

	// Fetch all fiat currencies
	currencies, err := storage.Client.FiatCurrency.
		Query().
		Where(fiatcurrency.IsEnabledEQ(true)).
		All(ctx)
	if err != nil {
		return fmt.Errorf("ComputeMarketRate: %w", err)
	}

	for _, currency := range currencies {
		// Fetch external rates (buy and sell)
		externalBuyRate, externalSellRate, err := fetchExternalRate(currency.Code)
		if err != nil {
			continue
		}

		// Fetch rates from token configs with fixed conversion rates (both buy and sell)
		tokenConfigs, err := storage.Client.ProviderOrderToken.
			Query().
			Where(
				providerordertoken.HasTokenWith(
					tokenent.SymbolIn("USDT", "USDC"),
				),
				providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(currency.Code)),
				providerordertoken.HasProviderWith(
					providerprofile.IsActiveEQ(true),
				),
			).
			All(ctx)
		if err != nil {
			continue
		}

		// Collect buy and sell rates separately from provider configs
		var buyRates []decimal.Decimal
		var sellRates []decimal.Decimal
		for _, tokenConfig := range tokenConfigs {
			if !tokenConfig.FixedBuyRate.IsZero() {
				buyRates = append(buyRates, tokenConfig.FixedBuyRate)
			}
			if !tokenConfig.FixedSellRate.IsZero() {
				sellRates = append(sellRates, tokenConfig.FixedSellRate)
			}
		}

		// Calculate medians for buy and sell
		var medianBuyRate, medianSellRate decimal.Decimal
		if len(buyRates) > 0 {
			medianBuyRate = utils.Median(buyRates)
			// Check against external buy rate
			percentDeviation := utils.AbsPercentageDeviation(externalBuyRate, medianBuyRate)
			if percentDeviation.GreaterThan(orderConf.PercentDeviationFromExternalRate) {
				medianBuyRate = externalBuyRate
			}
		} else {
			medianBuyRate = externalBuyRate
		}

		if len(sellRates) > 0 {
			medianSellRate = utils.Median(sellRates)
			// Check against external sell rate
			percentDeviation := utils.AbsPercentageDeviation(externalSellRate, medianSellRate)
			if percentDeviation.GreaterThan(orderConf.PercentDeviationFromExternalRate) {
				medianSellRate = externalSellRate
			}
		} else {
			medianSellRate = externalSellRate
		}

		// Update currency with both buy and sell market rates
		_, err = storage.Client.FiatCurrency.UpdateOneID(currency.ID).
			SetMarketBuyRate(medianBuyRate).
			SetMarketSellRate(medianSellRate).
			Save(ctx)
		if err != nil {
			continue
		}
	}

	return nil
}
