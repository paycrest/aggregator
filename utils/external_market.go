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
	"github.com/paycrest/aggregator/types"
	"github.com/shopspring/decimal"
)

var (
	BitgetAPIURL  = "https://www.bitget.com"
	BinanceAPIURL = "https://p2p.binance.com"
	QuidaxAPIURL  = "https://www.quidax.com"
)

// FetchExternalRate fetches the external rate for a fiat currency
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
		quidaxRate, err := FetchQuidaxRates(currency)
		if err == nil {
			prices = append(prices, quidaxRate)
		}
	} else {
		binanceRates, err := FetchBinanceRates(currency)
		if err == nil {
			prices = append(prices, binanceRates...)
		}
	}

	// Fetch Bitget rates for all supported currencies
	bitgetRates, err := FetchBitgetRates(currency)
	if err == nil {
		prices = append(prices, bitgetRates...)
	}

	if len(prices) == 0 {
		return decimal.Zero, fmt.Errorf("ComputeMarketRate: no valid rates found")
	}

	// Return the median price
	return Median(prices), nil
}

// FetchQuidaxRate fetches the USDT exchange rate from Quidax (NGN only)
func FetchQuidaxRates(currency string) (decimal.Decimal, error) {
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

// FetchBinanceRates fetches USDT exchange rates from Binance P2P
func FetchBinanceRates(currency string) ([]decimal.Decimal, error) {
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
		return nil, fmt.Errorf("FetchBinanceRates: %w", err)
	}

	resData, err := ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("FetchBinanceRates: %w", err)
	}

	data, ok := resData["data"].([]interface{})
	if !ok || len(data) == 0 {
		return nil, fmt.Errorf("FetchBinanceRates: no data in response")
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
		return nil, fmt.Errorf("FetchBinanceRates: no valid prices found")
	}

	return prices, nil
}

// FetchBitgetRates fetches USDT exchange rates from Bitget P2P listings
func FetchBitgetRates(currency string) ([]decimal.Decimal, error) {
	payload := map[string]interface{}{
		"side":         2,
		"pageNo":       1,
		"pageSize":     20,
		"coinCode":     "USDT",
		"fiatCode":     currency,
		"languageType": 0,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("FetchBitgetRates: failed to marshal payload: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("POST", BitgetAPIURL+"/v1/p2p/pub/adv/queryAdvList", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("FetchBitgetRates: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	var resp *http.Response
	err = Retry(3, 5*time.Second, func() error {
		var retryErr error
		resp, retryErr = client.Do(req)
		return retryErr
	})
	if err != nil {
		return nil, fmt.Errorf("FetchBitgetRates: failed to send request after retries: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("FetchBitgetRates: failed to read response body: %w", err)
	}

	var resData types.BitgetResponse
	err = json.Unmarshal(bodyBytes, &resData)
	if err != nil {
		fmt.Printf("FetchBitgetRates: failed to parse response, raw body: %s\n", string(bodyBytes))
		return nil, fmt.Errorf("FetchBitgetRates: failed to parse response: %w", err)
	}

	if resData.Code != "00000" {
		return nil, fmt.Errorf("FetchBitgetRates: API error: %s", resData.Msg)
	}

	if len(resData.Data.DataList) == 0 {
		return nil, fmt.Errorf("FetchBitgetRates: no sell ads found for %s/USDT", currency)
	}

	var prices []decimal.Decimal
	for i, ad := range resData.Data.DataList {
		if ad.CoinCode != "USDT" || ad.FiatCode != currency {
			continue
		}
		price, err := decimal.NewFromString(ad.Price)
		if err != nil {
			fmt.Printf("FetchBitgetRates: skipping ad at index %d with invalid price '%s': %v\n", i, ad.Price, err)
			continue
		}
		prices = append(prices, price)
	}

	if len(prices) == 0 {
		return nil, fmt.Errorf("FetchBitgetRates: no valid sell ads found for %s/USDT", currency)
	}

	return prices, nil
}

