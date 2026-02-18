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

// fetchExternalRate fetches the external rate for a fiat currency
func fetchExternalRate(currency string) (decimal.Decimal, error) {
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
		return decimal.Zero, fmt.Errorf("ComputeMarketRate: currency not supported")
	}

	// Fetch rates from noblocks rates API
	res, err := fastshot.NewClient("https://api.rates.noblocks.xyz").
		Config().SetTimeout(30*time.Second).
		Build().GET(fmt.Sprintf("/rates/usdt/%s", strings.ToLower(currency))).
		Retry().Set(3, 5*time.Second).
		Send()
	if err != nil {
		return decimal.Zero, fmt.Errorf("ComputeMarketRate: %w", err)
	}

	// Read the response body manually since we need to parse an array, not an object
	responseBody, err := io.ReadAll(res.RawResponse.Body)
	defer res.RawResponse.Body.Close()
	if err != nil {
		return decimal.Zero, fmt.Errorf("ComputeMarketRate: failed to read response body: %w", err)
	}

	var dataArray []map[string]interface{}
	err = json.Unmarshal(responseBody, &dataArray)
	if err != nil {
		return decimal.Zero, fmt.Errorf("ComputeMarketRate: failed to parse JSON response: %w", err)
	}

	// Check if we have data
	if len(dataArray) == 0 {
		return decimal.Zero, fmt.Errorf("ComputeMarketRate: No data in the response")
	}

	// Get the first rate object
	rateData := dataArray[0]

	// Extract buy and sell rates
	// buyRate, ok := rateData["buyRate"].(float64)
	// if !ok {
	// 	return decimal.Zero, fmt.Errorf("ComputeMarketRate: Invalid buyRate format")
	// }

	sellRate, ok := rateData["sellRate"].(float64)
	if !ok {
		return decimal.Zero, fmt.Errorf("ComputeMarketRate: Invalid sellRate format")
	}

	return decimal.NewFromFloat(sellRate), nil
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
		// Fetch external rate
		externalRate, err := fetchExternalRate(currency.Code)
		if err != nil {
			continue
		}

		// Fetch rates from token configs with fixed conversion rate
		tokenConfigs, err := storage.Client.ProviderOrderToken.
			Query().
			Where(
				providerordertoken.HasTokenWith(
					tokenent.SymbolIn("USDT", "USDC"),
				),
				providerordertoken.ConversionRateTypeEQ(providerordertoken.ConversionRateTypeFixed),
				providerordertoken.HasProviderWith(
					providerprofile.IsActiveEQ(true),
				),
			).
			Select(providerordertoken.FieldFixedConversionRate).
			All(ctx)
		if err != nil {
			continue
		}

		var rates []decimal.Decimal
		for _, tokenConfig := range tokenConfigs {
			rates = append(rates, tokenConfig.FixedConversionRate)
		}

		// Calculate median
		median := utils.Median(rates)

		// Check the median rate against the external rate to ensure it's not too far off
		percentDeviation := utils.AbsPercentageDeviation(externalRate, median)
		if percentDeviation.GreaterThan(orderConf.PercentDeviationFromExternalRate) {
			median = externalRate
		}

		// Update currency with median rate
		_, err = storage.Client.FiatCurrency.
			UpdateOneID(currency.ID).
			SetMarketRate(median).
			Save(ctx)
		if err != nil {
			continue
		}
	}

	return nil
}
