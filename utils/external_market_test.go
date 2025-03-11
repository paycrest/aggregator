package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
)

// TestFetchExternalRate with mock API servers
func TestFetchExternalRate(t *testing.T) {
	// Mock Bitget server
	bitgetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var reqBody map[string]interface{}
		json.NewDecoder(r.Body).Decode(&reqBody)

		var response string
		switch reqBody["fiat"] {
		case "NGN":
			response = `{"code":"00000","msg":"success","data":[{"price":"750.0"},{"price":"755.0"}]}`
		case "KES":
			response = `{"code":"00000","msg":"success","data":[{"price":"145.0"},{"price":"146.0"}]}`
		default:
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Write([]byte(response))
	}))
	defer bitgetServer.Close()

	quidaxServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"data": {"ticker": {"buy": "755.00"}}}`
		w.Write([]byte(response))
	}))
	defer quidaxServer.Close()

	binanceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := `{"data":[{"adv":{"price":"145.50"}}]}`
		w.Write([]byte(response))
	}))
	defer binanceServer.Close()

	// Override API URLs
	BitgetAPIURL = bitgetServer.URL
	BinanceAPIURL = binanceServer.URL
	QuidaxAPIURL = quidaxServer.URL

	// Run test cases
	t.Run("Fetch rate for NGN (Quidax & Bitget)", func(t *testing.T) {
		rate, err := FetchExternalRate("NGN")
		fmt.Println(rate, err)
		assert.NoError(t, err)
		expectedMedian := decimal.NewFromFloat(753.75)
		assert.Equal(t, expectedMedian.StringFixed(2), rate.StringFixed(2))

	})

	t.Run("Fetch rate for KES (Binance & Bitget)", func(t *testing.T) {
		rate, err := FetchExternalRate("KES")
		assert.NoError(t, err)
		expectedMedian := decimal.NewFromFloat(145.50)
		assert.Equal(t, expectedMedian.StringFixed(2), rate.StringFixed(2))

	})

	t.Run("Fetch rate for GHS (Binance & Bitget)", func(t *testing.T) {
		rate, err := FetchExternalRate("GHS")
		assert.NoError(t, err)
		expectedMedian := decimal.NewFromFloat(145.50)
		assert.Equal(t, expectedMedian.StringFixed(2), rate.StringFixed(2))

	})

	t.Run("Unsupported currency", func(t *testing.T) {
		_, err := FetchExternalRate("USD")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "currency not supported")
	})

	t.Run("API failures - No valid rates", func(t *testing.T) {
		// Simulate API failure by setting invalid URLs
		BitgetAPIURL = "http://invalid-url"
		BinanceAPIURL = "http://invalid-url"
		QuidaxAPIURL = "http://invalid-url"

		_, err := FetchExternalRate("NGN")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no valid rates found")
	})
}
