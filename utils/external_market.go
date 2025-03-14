package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"strings"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/shopspring/decimal"
)

var (
	BitgetAPIURL  = "https://www.bitget.com"
	BinanceAPIURL = "https://p2p.binance.com"
	QuidaxAPIURL  = "https://www.quidax.com"
)

// fetchExternalRate fetches the external rate for a fiat currency
func FetchExternalRate(currency string) (decimal.Decimal, error) {
	currency = strings.ToUpper(currency)
	supportedCurrencies := []string{"KES", "NGN", "GHS", "TZS", "UGX", "XOF"}
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

	var prices []decimal.Decimal

	// Fetch rates based on currency
	if currency == "NGN" {
		quidaxRate, err := FetchQuidaxRate(currency)
		if err == nil {
			prices = append(prices, quidaxRate)
		}
	} else {
		binanceRate, err := FetchBinanceRate(currency)
		if err == nil {
			prices = append(prices, binanceRate)
		}
	}

	// Fetch Bitget rate for all supported currencies
	bitgetRate, err := FetchBitgetRate(currency)
	if err == nil {
		prices = append(prices, bitgetRate)
	}

	if len(prices) == 0 {
		return decimal.Zero, fmt.Errorf("ComputeMarketRate: no valid rates found")
	}

	// Return the median price
	return Median(prices), nil
}

// FetchQuidaxRate fetches the USDT exchange rate from Quidax (NGN only)
func FetchQuidaxRate(currency string) (decimal.Decimal, error) {
	url := fmt.Sprintf("/api/v1/markets/tickers/usdt%s", strings.ToLower(currency))

	res, err := fastshot.NewClient(QuidaxAPIURL).
		Config().SetTimeout(30*time.Second).
		Build().GET(url).
		Retry().Set(3, 5*time.Second).
		Send()
	if err != nil {
		return decimal.Zero, fmt.Errorf("FetchQuidaxRate: %w", err)
	}

	data, err := ParseJSONResponse(res.RawResponse)
	if err != nil {
		return decimal.Zero, fmt.Errorf("FetchQuidaxRate: %w", err)
	}

	price, err := decimal.NewFromString(data["data"].(map[string]interface{})["ticker"].(map[string]interface{})["buy"].(string))
	if err != nil {
		return decimal.Zero, fmt.Errorf("FetchQuidaxRate: %w", err)
	}

	return price, nil
}

// FetchBinanceRate fetches the median USDT exchange rate from Binance P2P
func FetchBinanceRate(currency string) (decimal.Decimal, error) {

	res, err := fastshot.NewClient(BinanceAPIURL).
		Config().SetTimeout(30*time.Second).
		Header().Add("Content-Type", "application/json").
		Build().POST("/bapi/c2c/v2/friendly/c2c/adv/search").
		Retry().Set(3, 5*time.Second).
		Body().AsJSON(map[string]interface{}{
		"asset":     "USDT",
		"fiat":      currency,
		"tradeType": "SELL",
		"page":      1,
		"rows":      20,
	}).
		Send()
	if err != nil {
		return decimal.Zero, fmt.Errorf("FetchBinanceRate: %w", err)
	}

	resData, err := ParseJSONResponse(res.RawResponse)
	if err != nil {
		return decimal.Zero, fmt.Errorf("FetchBinanceRate: %w", err)
	}

	data, ok := resData["data"].([]interface{})
	if !ok || len(data) == 0 {
		return decimal.Zero, fmt.Errorf("FetchBinanceRate: no data in response")
	}

	var prices []decimal.Decimal
	for _, item := range data {
		adv, ok := item.(map[string]interface{})["adv"].(map[string]interface{})
		if !ok {
			continue
		}

		price, err := decimal.NewFromString(adv["price"].(string))
		if err != nil {
			continue
		}

		prices = append(prices, price)
	}

	if len(prices) == 0 {
		return decimal.Zero, fmt.Errorf("FetchBinanceRate: no valid prices found")
	}

	return Median(prices), nil
}

// FetchBitgetRate fetches the median USDT exchange rate from Bitget P2P order history
func FetchBitgetRate(currency string) (decimal.Decimal, error) {
	// Define the request payload
	payload := map[string]interface{}{
		"side":         2,
		"pageNo":       1,
		"pageSize":     20,
		"coinCode":     "USDT",
		"fiatCode":     currency,
		"languageType": 0,
	}

	// Marshal payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return decimal.Zero, fmt.Errorf("FetchBitgetRate: failed to marshal payload: %w", err)
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Prepare POST request
	req, err := http.NewRequest("POST", BitgetAPIURL+"/v1/p2p/pub/adv/queryAdvList", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return decimal.Zero, fmt.Errorf("FetchBitgetRate: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute request with retry
	var resp *http.Response
	err = Retry(3, 5*time.Second, func() error {
		var retryErr error
		resp, retryErr = client.Do(req)
		return retryErr
	})
	if err != nil {
		return decimal.Zero, fmt.Errorf("FetchBitgetRate: failed to send request after retries: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return decimal.Zero, fmt.Errorf("FetchBitgetRate: failed to read response body: %w", err)
	}

	// Parse JSON response
	var resData struct {
		Code string `json:"code"`
		Data struct {
			DataList []struct {
				Price     string `json:"price"`
				CoinCode  string `json:"coinCode"`
				FiatCode  string `json:"fiatCode"`
				Amount    string `json:"amount"`
				MinAmount string `json:"minAmount"`
				MaxAmount string `json:"maxAmount"`
			} `json:"dataList"`
		} `json:"data"`
		Msg string `json:"msg"`
	}
	err = json.Unmarshal(bodyBytes, &resData)
	if err != nil {
		fmt.Printf("FetchBitgetRate: failed to parse response, raw body: %s\n", string(bodyBytes))
		return decimal.Zero, fmt.Errorf("FetchBitgetRate: failed to parse response: %w", err)
	}

	// Check if the response is successful
	if resData.Code != "00000" {
		return decimal.Zero, fmt.Errorf("FetchBitgetRate: API error: %s", resData.Msg)
	}

	// Early check for empty data
	if len(resData.Data.DataList) == 0 {
		return decimal.Zero, fmt.Errorf("FetchBitgetRate: no sell ads found for %s/USDT", currency)
	}

	// Extract prices from the listings
	var prices []decimal.Decimal
	for i, ad := range resData.Data.DataList {
		// Verify coin and fiat match
		if ad.CoinCode != "USDT" || ad.FiatCode != currency {
			continue
		}

		price, err := decimal.NewFromString(ad.Price)
		if err != nil {
			fmt.Printf("FetchBitgetRate: skipping ad at index %d with invalid price '%s': %v\n", i, ad.Price, err)
			continue
		}

		prices = append(prices, price)
	}

	// Ensure we found at least one valid price
	if len(prices) == 0 {
		return decimal.Zero, fmt.Errorf("FetchBitgetRate: no valid sell ads found for %s/USDT", currency)
	}

	// Return median price
	return Median(prices), nil
}
