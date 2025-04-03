package utils

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
)

func TestFetchExternalRate(t *testing.T) {
	// Mock Bitget server
	bitgetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var reqBody map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		if err != nil || reqBody["side"] != float64(2) || reqBody["coinCode"] != "USDT" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		fiatCode, ok := reqBody["fiatCode"].(string)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var response string
		switch fiatCode {
		case "NGN":
			response = `{
				"code": "00000",
				"msg": "success",
				"data": {
					"dataList": [
						{"price": "750.0", "coinCode": "USDT", "fiatCode": "NGN"},
						{"price": "755.0", "coinCode": "USDT", "fiatCode": "NGN"}
					]
				}
			}`
		case "KES":
			response = `{
				"code": "00000",
				"msg": "success",
				"data": {
					"dataList": [
						{"price": "145.0", "coinCode": "USDT", "fiatCode": "KES"},
						{"price": "146.0", "coinCode": "USDT", "fiatCode": "KES"}
					]
				}
			}`
		case "GHS":
			response = `{
				"code": "00000",
				"msg": "success",
				"data": {
					"dataList": [
						{"price": "15.0", "coinCode": "USDT", "fiatCode": "GHS"},
						{"price": "15.5", "coinCode": "USDT", "fiatCode": "GHS"}
					]
				}
			}`
		case "TZS":
			response = `{
				"code": "00000",
				"msg": "success",
				"data": {
					"dataList": [
						{"price": "2700.0", "coinCode": "USDT", "fiatCode": "TZS"},
						{"price": "2750.0", "coinCode": "USDT", "fiatCode": "TZS"}
					]
				}
			}`
		case "UGX":
			response = `{
				"code": "00000",
				"msg": "success",
				"data": {
					"dataList": [
						{"price": "3700.0", "coinCode": "USDT", "fiatCode": "UGX"},
						{"price": "3750.0", "coinCode": "USDT", "fiatCode": "UGX"}
					]
				}
			}`
		case "XOF":
			response = `{
				"code": "00000",
				"msg": "success",
				"data": {
					"dataList": [
						{"price": "600.0", "coinCode": "USDT", "fiatCode": "XOF"},
						{"price": "610.0", "coinCode": "USDT", "fiatCode": "XOF"}
					]
				}
			}`
		default:
			response = `{"code": "80001", "msg": "invalid fiatCode", "data": {"dataList": []}}`
		}
		w.Write([]byte(response))
	}))
	defer bitgetServer.Close()

	// Mock Quidax server (for NGN only)
	quidaxServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"data": {"ticker": {"buy": "755.00"}}}`
		w.Write([]byte(response))
	}))
	defer quidaxServer.Close()

	// Mock Binance server (for non-NGN currencies)
	binanceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var reqBody map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		if err != nil || reqBody["asset"] != "USDT" || reqBody["tradeType"] != "SELL" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		fiat, ok := reqBody["fiat"].(string)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var response string
		switch fiat {
		case "KES":
			response = `{"data":[{"adv":{"price":"145.50"}}]}`
		case "GHS":
			response = `{"data":[{"adv":{"price":"15.25"}}]}`
		case "TZS":
			response = `{"data":[{"adv":{"price":"2725.0"}}]}`
		case "UGX":
			response = `{"data":[{"adv":{"price":"3725.0"}}]}`
		case "XOF":
			response = `{"data":[{"adv":{"price":"605.0"}}]}`
		default:
			response = `{"data":[]}`
		}
		w.Write([]byte(response))
	}))
	defer binanceServer.Close()

	// Test cases
	tests := []struct {
		name          string
		currency      string
		expectedRate  decimal.Decimal
		expectError   bool
		errorContains string
		setup         func() // Optional setup for edge cases
	}{
		{
			name:         "NGN (Quidax & Bitget)",
			currency:     "NGN",
			expectedRate: decimal.NewFromFloat(755.00),
			expectError:  false,
		},
		{
			name:         "KES (Binance & Bitget)",
			currency:     "KES",
			expectedRate: decimal.NewFromFloat(145.50), 
			expectError:  false,
		},
		{
			name:         "GHS (Binance & Bitget)",
			currency:     "GHS",
			expectedRate: decimal.NewFromFloat(15.25), 
			expectError:  false,
		},
		{
			name:         "TZS (Binance & Bitget)",
			currency:     "TZS",
			expectedRate: decimal.NewFromFloat(2725.0), 
			expectError:  false,
		},
		{
			name:         "UGX (Binance & Bitget)",
			currency:     "UGX",
			expectedRate: decimal.NewFromFloat(3725.0),
			expectError:  false,
		},
		{
			name:         "XOF (Binance & Bitget)",
			currency:     "XOF",
			expectedRate: decimal.NewFromFloat(605.0), 
			expectError:  false,
		},
		{
			name:          "Unsupported currency",
			currency:      "USD",
			expectedRate:  decimal.Zero,
			expectError:   true,
			errorContains: "currency not supported",
		},
		{
			name:          "All APIs fail",
			currency:      "NGN",
			expectedRate:  decimal.Zero,
			expectError:   true,
			errorContains: "no valid rates found",
			setup: func() {
				BitgetAPIURL = "http://invalid-url"
				BinanceAPIURL = "http://invalid-url"
				QuidaxAPIURL = "http://invalid-url"
			},
		},
		{
			name:         "Bitget empty response (NGN with Quidax)",
			currency:     "NGN",
			expectedRate: decimal.NewFromFloat(755.00), // Quidax rate only
			expectError:  false,
			setup: func() {
				BitgetAPIURL = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					response := `{"code": "00000", "msg": "success", "data": {"dataList": []}}`
					w.Write([]byte(response))
				})).URL
			},
		},
		{
			name:          "Bitget and Binance empty (KES)",
			currency:      "KES",
			expectedRate:  decimal.Zero,
			expectError:   true,
			errorContains: "no valid rates found",
			setup: func() {
				BitgetAPIURL = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					response := `{"code": "00000", "msg": "success", "data": {"dataList": []}}`
					w.Write([]byte(response))
				})).URL
				BinanceAPIURL = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					response := `{"data":[]}`
					w.Write([]byte(response))
				})).URL
			},
		},
		{
			name:         "Bitget invalid price (KES with Binance)",
			currency:     "KES",
			expectedRate: decimal.NewFromFloat(145.50), // Only Binance rate
			expectError:  false,
			setup: func() {
				BitgetAPIURL = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					response := `{
						"code": "00000",
						"msg": "success",
						"data": {
							"dataList": [
								{"price": "invalid", "coinCode": "USDT", "fiatCode": "KES"}
							]
						}
					}`
					w.Write([]byte(response))
				})).URL
			},
		},
		{
			name:         "Binance empty response (KES with Bitget)",
			currency:     "KES",
			expectedRate: decimal.NewFromFloat(145.5), // Median of [145.0, 146.0]
			expectError:  false,
			setup: func() {
				BinanceAPIURL = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					response := `{"data":[]}`
					w.Write([]byte(response))
				})).URL
			},
		},
		{
			name:         "Quidax fails, Bitget succeeds (NGN)",
			currency:     "NGN",
			expectedRate: decimal.NewFromFloat(752.5), // Median of [750.0, 755.0]
			expectError:  false,
			setup: func() {
				QuidaxAPIURL = "http://invalid-url"
			},
		},
		{
			name:         "Bitget fails, Binance succeeds (GHS)",
			currency:     "GHS",
			expectedRate: decimal.NewFromFloat(15.25),
			expectError:  false,
			setup: func() {
				BitgetAPIURL = "http://invalid-url"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset URLs to defaults
			BitgetAPIURL = bitgetServer.URL
			BinanceAPIURL = binanceServer.URL
			QuidaxAPIURL = quidaxServer.URL

			// Apply custom setup if provided
			if tt.setup != nil {
				tt.setup()
			}

			rate, err := FetchExternalRate(tt.currency)
			if tt.expectError {
				assert.Error(t, err, "Expected an error for %s", tt.name)
				assert.Contains(t, err.Error(), tt.errorContains, "Error message mismatch for %s", tt.name)
				assert.True(t, rate.Equal(decimal.Zero), "Rate should be zero on error for %s", tt.name)
			} else {
				assert.NoError(t, err, "Unexpected error for %s: %v", tt.name, err)
				assert.Equal(t, tt.expectedRate.StringFixed(2), rate.StringFixed(2), "Rate mismatch for %s", tt.currency)
			}
		})
	}
}
