package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"

	"strings"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/shopspring/decimal"
)

var (
	BitgetAPIURL  = "https://api.bitget.com"
	BinanceAPIURL = "https://api.binance.com"
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
	// TODO: FetchBitgetRate uses /api/p2p/v1/merchant/orderList, which requires an advNo (advertisement number).
	// To source this, we need to:
	// 1) Create a Bitget account,
	// 2) Become a P2P merchant (via "Buy Crypto > P2P > Post an Ad"),
	// 3) Post a sell-USDT ad to get an advNo from the "My Ads" section.
	// Hardcoded for now as a placeholder—please.
	advNo := "0987654321"
	bitgetRate, err := FetchBitgetRate(currency, advNo)
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
func FetchBitgetRate(currency string, advNo string) (decimal.Decimal, error) {
	conf := config.AuthConfig()

	// Generate timestamp
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)

	// Build query parameters according to orderList API requirements
	queryParams := map[string]string{
		"advNo":        advNo,
		"startTime":    strconv.FormatInt(time.Now().Add(-24*time.Hour).UnixMilli(), 10),
		"languageType": "en-US",
		"type":         "sell",
		"coin":         "USDT",
		"fiat":         currency,
		"endTime":      timestamp,
		"pageSize":     "20",
	}

	queryString := BuildQueryString(queryParams)
	endpoint := "/api/p2p/v1/merchant/orderList?" + queryString
	signContent := timestamp + "GET" + "/api/p2p/v1/merchant/orderList" + "?" + queryString
	h := hmac.New(sha256.New, []byte(conf.BitgetSecretKey))
	h.Write([]byte(signContent))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	client := fastshot.NewClient(BitgetAPIURL).
		Config().SetTimeout(30 * time.Second).
		Build()

	// Prepare request with authentication headers
	request := client.GET(endpoint)
	request.Header().Set("ACCESS-KEY", conf.BitgetAccessKey)
	request.Header().Set("ACCESS-SIGN", signature)
	request.Header().Set("ACCESS-PASSPHRASE", conf.BitgetPassphrase)
	request.Header().Set("ACCESS-TIMESTAMP", timestamp)
	request.Header().Set("locale", "en-US")
	request.Header().Set("Content-Type", "application/json")

	// Execute request with retry mechanism
	res, err := request.Retry().Set(3, 5*time.Second).Send()
	if err != nil {
		return decimal.Zero, fmt.Errorf("FetchBitgetRate: failed to send request: %w", err)
	}

	// Parse JSON response
	resData, err := ParseJSONResponse(res.RawResponse)
	if err != nil {
		return decimal.Zero, fmt.Errorf("FetchBitgetRate: failed to parse response: %w", err)
	}

	// Extract order list from response
	data, ok := resData["data"].(map[string]interface{})
	if !ok {
		return decimal.Zero, fmt.Errorf("FetchBitgetRate: invalid data structure in response")
	}

	orderList, ok := data["orderList"].([]interface{})
	if !ok || len(orderList) == 0 {
		return decimal.Zero, fmt.Errorf("FetchBitgetRate: no orders found in response")
	}

	// Extract and validate prices from orders
	var prices []decimal.Decimal
	for i, item := range orderList {
		order, ok := item.(map[string]interface{})
		if !ok {
			fmt.Printf("FetchBitgetRate: skipping invalid order at index %d\n", i)
			continue
		}

		// Find the price field in the order data
		priceStr, ok := order["price"].(string)
		if !ok {
			fmt.Printf("FetchBitgetRate: skipping order at index %d with no price\n", i)
			continue
		}

		price, err := decimal.NewFromString(priceStr)
		if err != nil {
			fmt.Printf("FetchBitgetRate: skipping order at index %d with invalid price: %v\n", i, err)
			continue
		}

		prices = append(prices, price)
	}

	// Ensure we found at least one valid price
	if len(prices) == 0 {
		return decimal.Zero, fmt.Errorf("FetchBitgetRate: no valid prices found")
	}

	// Return median price
	return Median(prices), nil
}
