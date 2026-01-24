package tasks

import (
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
)

func TestFetchExternalRate(t *testing.T) {
	httpmock.Activate()
	defer httpmock.Deactivate()

	// Test unsupported currency
	t.Run("UnsupportedCurrency", func(t *testing.T) {
		value, err := fetchExternalRate("KSH")
		assert.Error(t, err)
		assert.Equal(t, value, decimal.Zero)
		assert.Contains(t, err.Error(), "currency not supported")
	})

	// Test successful API response
	t.Run("SuccessfulResponse", func(t *testing.T) {
		// Mock successful response
		httpmock.RegisterResponder("GET", "https://api.rates.noblocks.xyz/rates/usdt/ngn",
			httpmock.NewStringResponder(200, `[
					{
						"stablecoin": "USDT",
						"fiat": "NGN",
						"sources": ["quidax"],
						"buyRate": 1444.36,
						"sellRate": 1451.61,
						"timestamp": "2025-11-03T13:12:50.290Z"
					}
				]`))

		value, err := fetchExternalRate("NGN")
		assert.NoError(t, err)
		expectedRate := decimal.NewFromFloat((1444.36 + 1451.61) / 2) // Average of buy and sell
		assert.True(t, value.Equal(expectedRate))
	})

	// Test API error
	t.Run("APIError", func(t *testing.T) {
		httpmock.RegisterResponder("GET", "https://api.rates.noblocks.xyz/rates/usdt/kes",
			httpmock.NewStringResponder(500, `{"error": "Internal server error"}`))

		value, err := fetchExternalRate("KES")
		assert.Error(t, err)
		assert.Equal(t, value, decimal.Zero)
		assert.Contains(t, err.Error(), "ComputeMarketRate")
	})

	// Test empty response
	t.Run("EmptyResponse", func(t *testing.T) {
		httpmock.RegisterResponder("GET", "https://api.rates.noblocks.xyz/rates/usdt/ghs",
			httpmock.NewStringResponder(200, `[]`))

		value, err := fetchExternalRate("GHS")
		assert.Error(t, err)
		assert.Equal(t, value, decimal.Zero)
		assert.Contains(t, err.Error(), "No data in the response")
	})

	// Test invalid JSON response
	t.Run("InvalidJSONResponse", func(t *testing.T) {
		httpmock.RegisterResponder("GET", "https://api.rates.noblocks.xyz/rates/usdt/mwk",
			httpmock.NewStringResponder(200, `invalid json`))

		value, err := fetchExternalRate("MWK")
		assert.Error(t, err)
		assert.Equal(t, value, decimal.Zero)
	})

	// Test malformed rate data
	t.Run("MalformedRateData", func(t *testing.T) {
		httpmock.RegisterResponder("GET", "https://api.rates.noblocks.xyz/rates/usdt/tzs",
			httpmock.NewStringResponder(200, `[
					{
						"stablecoin": "USDT",
						"fiat": "TZS",
						"sources": ["quidax"],
						"buyRate": "invalid",
						"sellRate": 1451.61,
						"timestamp": "2025-11-03T13:12:50.290Z"
					}
				]`))

		value, err := fetchExternalRate("TZS")
		assert.Error(t, err)
		assert.Equal(t, value, decimal.Zero)
		assert.Contains(t, err.Error(), "Invalid buyRate format")
	})

	// Reset httpmock after each test
	httpmock.Reset()
}
