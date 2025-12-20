package utils

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/anaskhan96/base58check"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	institutionEnt "github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providercurrencies"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	tokenEnt "github.com/paycrest/aggregator/ent/token"

	"github.com/NethermindEth/juno/core/felt"
	"github.com/NethermindEth/starknet.go/utils"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/logger"
	tokenUtils "github.com/paycrest/aggregator/utils/token"
	"github.com/shopspring/decimal"
)

// ToSubunit converts a decimal amount to the smallest subunit representation.
// It takes the amount and the number of decimal places (decimals) and returns
// the amount in subunits as a *big.Int.
func ToSubunit(amount decimal.Decimal, decimals int8) *big.Int {
	// Compute the multiplier: 10^decimals
	multiplier := decimal.NewFromFloat(float64(10)).Pow(decimal.NewFromFloat(float64(decimals)))

	// Multiply the amount by the multiplier to convert it to subunits
	subunitInDecimal := amount.Mul(multiplier)

	// Create a new big.Int from the string representation of the subunit amount
	subunit := new(big.Int)
	subunit.SetString(subunitInDecimal.String(), 10)

	return subunit
}

// FromSubunit converts an amount in subunits represented as a *big.Int back
// to its decimal representation with the given number of decimal places (decimals).
// It returns the amount as a decimal.Decimal.
func FromSubunit(amountInSubunit *big.Int, decimals int8) decimal.Decimal {
	// Compute the divisor: 10^decimals
	divisor := decimal.NewFromFloat(float64(10)).Pow(decimal.NewFromFloat(float64(decimals))).BigFloat()

	// Create a new big.Float with the desired precision and rounding mode
	f := new(big.Float).SetPrec(236) //  IEEE 754 octuple-precision binary floating-point format: binary256
	f.SetMode(big.ToNearestEven)

	// Create a new big.Float for the subunit amount with the desired precision and rounding mode
	fSubunit := new(big.Float).SetPrec(236) //  IEEE 754 octuple-precision binary floating-point format: binary256
	fSubunit.SetMode(big.ToNearestEven)

	// Divide the subunit amount by the divisor and convert it to a float64
	result, _ := f.Quo(fSubunit.SetInt(amountInSubunit), divisor).Float64()

	return decimal.NewFromFloat(result)
}

// StringToByte32 converts string to [32]byte
func StringToByte32(s string) [32]byte {
	var result [32]byte

	// Convert the input string to bytes
	inputBytes := []byte(s)

	// Copy the input bytes into the result array, limiting to 32 bytes
	copy(result[:], inputBytes)

	return result
}

// Byte32ToString converts [32]byte to string
func Byte32ToString(b [32]byte) string {

	// Find first null index if any
	nullIndex := -1
	for i, x := range b {
		if x == 0 {
			nullIndex = i
			break
		}
	}

	// Slice at first null or return full 32 bytes
	if nullIndex >= 0 {
		return string(b[:nullIndex])
	} else {
		return string(b[:])
	}
}

// HexToDecimal converts a hex string to a decimal.Decimal
func HexToDecimal(hexStr string) decimal.Decimal {
	// Remove "0x" prefix if present
	hexStr = strings.TrimPrefix(hexStr, "0x")

	// Convert hex string to big.Int
	n := new(big.Int)
	n.SetString(hexStr, 16)

	// Convert to decimal
	dec := decimal.NewFromBigInt(n, 0)
	return dec
}

// BigMin returns the minimum value between two big numbers
func BigMin(x, y *big.Int) *big.Int {
	if x.Cmp(y) < 0 {
		return x
	}
	return y
}

// FormatTimestampToGMT1 formats the timestamp to GMT+1 (Africa/Lagos time zone) and returns a formatted string.
func FormatTimestampToGMT1(timestamp time.Time) (string, error) {
	loc := time.FixedZone("GMT+1", 1*60*60)
	return timestamp.In(loc).Format("January 2, 2006 at 3:04 PM"), nil
}

// PersonalSign is an equivalent of ethers.personal_sign for signing ethereum messages
// Ref: https://github.com/etaaa/Golang-Ethereum-Personal-Sign/blob/main/main.go
func PersonalSign(message string, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	fullMessage := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := crypto.Keccak256Hash([]byte(fullMessage))
	signatureBytes, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return nil, err
	}
	signatureBytes[64] += 27
	return signatureBytes, nil
}

// Difference returns the elements in `a` that aren't in `b`.
func Difference(a, b []string) []string {
	setB := make(map[string]struct{})
	for _, x := range b {
		setB[x] = struct{}{}
	}

	var diff []string
	for _, x := range a {
		if _, found := setB[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

// ContainsString returns true if the slice contains the given string
func ContainsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Median returns the median value of a decimal slice
func Median(data []decimal.Decimal) decimal.Decimal {
	l := len(data)
	if l == 0 {
		return decimal.Zero
	}

	// Sort data in ascending order
	sort.Slice(data, func(i, j int) bool {
		return data[i].LessThan(data[j])
	})

	middle := l / 2
	result := data[middle]

	// Handle even length slices
	if l%2 == 0 {
		result = result.Add(data[middle-1])
		result = result.Div(decimal.NewFromInt(2))
	}

	return result
}

// AbsPercentageDeviation returns the absolute percentage deviation between two values
func AbsPercentageDeviation(trueValue, measuredValue decimal.Decimal) decimal.Decimal {
	if trueValue.IsZero() {
		return decimal.Zero
	}

	deviation := measuredValue.Sub(trueValue).Div(trueValue).Mul(decimal.NewFromInt(100))
	return deviation.Abs()
}

// CalculatePaymentOrderAmountInUSD calculates the amount in USD for a payment order
func CalculatePaymentOrderAmountInUSD(amount decimal.Decimal, token *ent.Token, institution *ent.Institution) decimal.Decimal {
	// Guard against nil inputs
	if token == nil || institution == nil {
		return amount
	}

	// Ensure the fiat‐currency edge is loaded
	fiatCurrency := institution.Edges.FiatCurrency
	if fiatCurrency == nil {
		institutionCurrency, err := institution.QueryFiatCurrency().Only(context.Background())
		if err != nil {
			return amount
		}
		institution.Edges.FiatCurrency = institutionCurrency
		fiatCurrency = institutionCurrency
	}

	// Only multiply when the token matches the institution's fiat currency
	if fiatCurrency != nil && token.BaseCurrency == fiatCurrency.Code && !fiatCurrency.MarketRate.IsZero() {
		return amount.Div(fiatCurrency.MarketRate)
	}

	return amount
}

// SendPaymentOrderWebhook notifies a sender when the status of a payment order changes
func SendPaymentOrderWebhook(ctx context.Context, paymentOrder *ent.PaymentOrder) error {
	var err error

	paymentOrder, err = storage.Client.PaymentOrder.
		Query().
		Where(paymentorder.IDEQ(paymentOrder.ID)).
		WithSenderProfile().
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		Only(ctx)
	if err != nil {
		return err
	}

	profile := paymentOrder.Edges.SenderProfile
	if profile == nil {
		return nil
	}
	
	// If webhook URL is empty, return
	if profile.WebhookURL == "" {
		return nil
	}

	// Determine the event
	var event string

	switch paymentOrder.Status {
	case paymentorder.StatusPending:
		event = "payment_order.pending"
	case paymentorder.StatusFulfilled:
		event = "payment_order.fulfilled"
	case paymentorder.StatusValidated:
		event = "payment_order.validated"
	case paymentorder.StatusExpired:
		event = "payment_order.expired"
	case paymentorder.StatusSettled:
		event = "payment_order.settled"
	case paymentorder.StatusRefunded:
		event = "payment_order.refunded"
	default:
		return nil
	}

	institution, err := storage.Client.Institution.
		Query().
		Where(institutionEnt.CodeEQ(paymentOrder.Institution)).
		WithFiatCurrency().
		Only(ctx)
	if err != nil {
		return err
	}

	// Create the payload
	var providerID string
	if paymentOrder.Edges.Provider != nil {
		providerID = paymentOrder.Edges.Provider.ID
	}
	payloadStruct := types.PaymentOrderWebhookPayload{
		Event: event,
		Data: types.PaymentOrderWebhookData{
			ID:             paymentOrder.ID,
			Amount:         paymentOrder.Amount,
			AmountPaid:     paymentOrder.AmountPaid,
			AmountReturned: paymentOrder.AmountReturned,
			PercentSettled: paymentOrder.PercentSettled,
			SenderFee:      paymentOrder.SenderFee,
			NetworkFee:     paymentOrder.NetworkFee,
			Rate:           paymentOrder.Rate,
			Network:        paymentOrder.Edges.Token.Edges.Network.Identifier,
			GatewayID:      paymentOrder.GatewayID,
			SenderID:       profile.ID,
			Recipient: types.PaymentOrderRecipient{
				Currency:          institution.Edges.FiatCurrency.Code,
				Institution:       paymentOrder.Institution,
				AccountIdentifier: paymentOrder.AccountIdentifier,
				AccountName:       paymentOrder.AccountName,
				ProviderID:        providerID,
				Memo:              paymentOrder.Memo,
			},
			FromAddress:   paymentOrder.FromAddress,
			ReturnAddress: paymentOrder.ReturnAddress,
			Reference:     paymentOrder.Reference,
			UpdatedAt:     paymentOrder.UpdatedAt,
			CreatedAt:     paymentOrder.CreatedAt,
			TxHash:        paymentOrder.TxHash,
			Status:        paymentOrder.Status,
		},
	}

	payload := StructToMap(payloadStruct)

	// Compute HMAC signature
	apiKey, err := profile.QueryAPIKey().Only(ctx)
	if err != nil {
		return err
	}

	decodedSecret, err := base64.StdEncoding.DecodeString(apiKey.Secret)
	if err != nil {
		return err
	}

	decryptedSecret, err := cryptoUtils.DecryptPlain(decodedSecret)
	if err != nil {
		return err
	}

	signature := tokenUtils.GenerateHMACSignature(payload, string(decryptedSecret))

	// Send the webhook
	_, err = fastshot.NewClient(profile.WebhookURL).
		Config().SetTimeout(30*time.Second).
		Header().Add("X-Paycrest-Signature", signature).
		Header().Add("Content-Type", "application/json").
		Build().POST("").
		Body().AsJSON(payload).
		Send()
	if err != nil {
		// Log retry attempt
		_, err := storage.Client.WebhookRetryAttempt.
			Create().
			SetAttemptNumber(1).
			SetNextRetryTime(time.Now().Add(2 * time.Minute)).
			SetPayload(payload).
			SetSignature(signature).
			SetWebhookURL(profile.WebhookURL).
			SetStatus("failed").
			Save(ctx)
		return err
	}

	return nil
}

// StructToMap converts a struct to a map[string]interface{}
func StructToMap(input interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// Use reflection to iterate over the struct fields
	valueOf := reflect.ValueOf(input)
	typeOf := valueOf.Type()

	for i := 0; i < valueOf.NumField(); i++ {
		field := valueOf.Field(i)
		fieldName := strings.ToLower(typeOf.Field(i).Name)

		// Convert the field value to interface{}
		result[fieldName] = field.Interface()
	}

	return result
}

func MapToStruct(m map[string]interface{}, s interface{}) error {
	v := reflect.ValueOf(s).Elem() // Get the Value of the struct
	t := v.Type()                  // Get the Type of the struct

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i) // Get the StructField
		key := f.Name   // Get the Field Name

		if val, ok := m[key]; ok { // Check if the map contains the key
			valValue := reflect.ValueOf(val) // Get the Value of the map value
			if !valValue.IsValid() || valValue.IsNil() {
				return fmt.Errorf("value is invalid or nil")
			}

			// Correctly get the type of the struct field
			fieldType := f.Type
			if valValue.Kind() != fieldType.Kind() {
				return fmt.Errorf("type mismatch: expected %v, got %v", fieldType.Kind(), valValue.Kind())
			}

			v.Field(i).Set(valValue) // Set the struct field value
		} else {
			return fmt.Errorf("missing key: %s", key)
		}
	}

	return nil
}

// IsValidMobileNumber checks if a string is a valid mobile number
func IsValidMobileNumber(number string) bool {
	// Pattern for valid mobile numbers (generalized)
	pattern := `^\+?[1-9]\d{1,14}$` // Matches international format
	matched, _ := regexp.MatchString(pattern, number)
	return matched
}

/*
	IsValidFileURL checks if a URL is a valid file URL

(supports only file urls ending with .jpg, .jpeg, .png, or .pdf)
*/
func IsValidFileURL(url string) bool {
	// Pattern for URLs ending with .jpg, .jpeg, .png, or .pdf
	pattern := `^(http(s)?://)?([\w-]+\.)+[\w-]+(/[\w- ;,./?%&=]*)?\.(jpg|jpeg|png|pdf)$`
	matched, _ := regexp.MatchString(pattern, url)
	return matched
}

// IsValidEthereumAddress checks if a string is a valid Ethereum address
func IsValidEthereumAddress(address string) bool {
	pattern := `^0x[a-fA-F0-9]{40}$`
	matched, _ := regexp.MatchString(pattern, address)
	return matched
}

// IsValidTronAddress checks if a string is a valid Tron address
func IsValidTronAddress(address string) bool {
	// Tron addresses are base58check encoded and start with 'T'
	if len(address) != 34 || !strings.HasPrefix(address, "T") {
		return false
	}

	// Try to decode the address
	_, err := base58check.Decode(address)
	return err == nil
}

// CallProviderWithHMAC makes an authenticated HTTP request to a provider with HMAC signature
// Returns the parsed JSON response data and error
func CallProviderWithHMAC(ctx context.Context, providerID, method, path string, payload map[string]interface{}) (map[string]interface{}, error) {
	// Get provider with API key
	provider, err := storage.Client.ProviderProfile.
		Query().
		Where(providerprofile.IDEQ(providerID)).
		WithAPIKey().
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	// Check if provider has host identifier
	if provider.HostIdentifier == "" {
		return nil, fmt.Errorf("provider %s has no host identifier", providerID)
	}

	// Check if provider has API key
	if provider.Edges.APIKey == nil {
		return nil, fmt.Errorf("provider %s has no API key (data integrity issue)", providerID)
	}

	// Decrypt API key secret
	decodedSecret, err := base64.StdEncoding.DecodeString(provider.Edges.APIKey.Secret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode API key secret: %v", err)
	}
	decryptedSecret, err := cryptoUtils.DecryptPlain(decodedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt API key secret: %v", err)
	}

	// Generate HMAC signature
	signature := tokenUtils.GenerateHMACSignature(payload, string(decryptedSecret))

	// Create HTTP client and make request
	client := fastshot.NewClient(provider.HostIdentifier).
		Config().SetTimeout(30*time.Second).
		Header().Add("X-Request-Signature", signature).
		Build()

	var res fastshot.Response
	var reqErr error

	switch method {
	case "GET":
		res, reqErr = client.GET(path).
			Body().AsJSON(payload).
			Send()
	case "POST":
		res, reqErr = client.POST(path).
			Body().AsJSON(payload).
			Send()
	default:
		return nil, fmt.Errorf("unsupported HTTP method: %s", method)
	}

	if reqErr != nil {
		return nil, fmt.Errorf("failed to make HTTP request: %v", reqErr)
	}

	// Parse JSON response
	data, err := ParseJSONResponse(res.RawResponse)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
			"Path":       path,
		}).Errorf("failed to parse JSON response from provider")
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return data, nil
}

// Retry is a function that attempts to execute a given function multiple times until it succeeds or the maximum number of attempts is reached.
// It sleeps for a specified duration between each attempt.
// Parameters:
// - attempts: The maximum number of attempts to execute the function.
// - sleep: The duration to sleep between each attempt.
// - fn: The function to be executed.
// Returns:
// - error: The error returned by the function, if any.
func Retry(attempts int, sleep time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		time.Sleep(sleep)
	}
	return err
}

// ParseTopicToTronAddress converts a padded hex string to a Tron address
func ParseTopicToTronAddress(paddedHexString string) string {
	addressBytes, err := hex.DecodeString(paddedHexString)
	if err != nil {
		return ""
	}
	addressHex := common.BytesToAddress(addressBytes).Hex()
	addressBase58, err := base58check.Encode("41", addressHex[2:])
	if err != nil {
		return ""
	}

	// Check if the address is a valid Tron address
	if !IsValidTronAddress(addressBase58) {
		return ""
	}

	return addressBase58
}

// ParseTopicToBigInt converts a padded hex string to a big.Int
func ParseTopicToBigInt(paddedHexString string) *big.Int {
	addressBytes, err := hex.DecodeString(paddedHexString)
	if err != nil {
		return nil
	}
	return new(big.Int).SetBytes(addressBytes)
}

// ParseTopicToByte32 converts a padded hex string to a [32]byte
func ParseTopicToByte32(paddedHexString string) [32]byte {
	addressBytes, err := hex.DecodeString(paddedHexString)
	if err != nil {
		return [32]byte{}
	}

	return [32]byte(addressBytes)
}

// ParseTopicToByte32Flexible handles both string and [32]uint8 inputs for compatibility
func ParseTopicToByte32Flexible(topic interface{}) [32]byte {
	switch v := topic.(type) {
	case string:
		// Handle string input (hex string)
		return ParseTopicToByte32(v)
	case [32]uint8:
		// Handle direct byte array input
		return [32]byte(v)
	default:
		// Try to convert to string as fallback
		str := fmt.Sprintf("%v", v)
		return ParseTopicToByte32(str)
	}
}

// UnpackEventData unpacks the data from a padded hex string using the ABI
func UnpackEventData(paddedHexString, contractABI, eventName string) ([]interface{}, error) {
	rawData, err := hex.DecodeString(paddedHexString)
	if err != nil {
		return nil, err
	}

	abiObj, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		return nil, err
	}

	data, err := abiObj.Unpack(eventName, rawData)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// IsBase64 checks if a string is a valid Base64 encoded string
func IsBase64(s string) bool {
	// Check if the string matches the Base64 pattern
	const base64Pattern = `^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$`
	match, _ := regexp.MatchString(base64Pattern, s)
	if match {
		// Try to decode the string
		_, err := base64.StdEncoding.DecodeString(s)
		return err == nil
	}
	return false
}

// GetTokenRateFromQueue gets the rate of a token from the priority queue
func GetTokenRateFromQueue(tokenSymbol string, orderAmount decimal.Decimal, fiatCurrency string, marketRate decimal.Decimal) (decimal.Decimal, error) {
	ctx := context.Background()

	// Get rate from priority queue
	keys, _, err := storage.RedisClient.Scan(ctx, uint64(0), "bucket_"+fiatCurrency+"_*_*", 100).Result()
	if err != nil {
		return decimal.Decimal{}, err
	}

	rateResponse := marketRate
	highestMaxAmount := decimal.NewFromInt(0)

	// Scan through the buckets to find a suitable rate
	for _, key := range keys {
		bucketData := strings.Split(key, "_")
		minAmount, _ := decimal.NewFromString(bucketData[2])
		maxAmount, _ := decimal.NewFromString(bucketData[3])

		for index := 0; ; index++ {
			// Get the topmost provider in the priority queue of the bucket
			providerData, err := storage.RedisClient.LIndex(ctx, key, int64(index)).Result()
			if err != nil {
				break
			}
			parts := strings.Split(providerData, ":")
			if len(parts) != 5 {
				logger.WithFields(logger.Fields{
					"Error":        fmt.Sprintf("%v", err),
					"ProviderData": providerData,
					"Token":        tokenSymbol,
					"Currency":     fiatCurrency,
					"MinAmount":    minAmount,
					"MaxAmount":    maxAmount,
				}).Errorf("GetTokenRate.InvalidProviderData: %v", providerData)
				continue
			}

			// Skip entry if token doesn't match
			if parts[1] != tokenSymbol {
				continue
			}

			// Skip entry if order amount is not within provider's min and max order amount
			minOrderAmount, err := decimal.NewFromString(parts[3])
			if err != nil {
				continue
			}

			maxOrderAmount, err := decimal.NewFromString(parts[4])
			if err != nil {
				continue
			}

			if orderAmount.LessThan(minOrderAmount) || orderAmount.GreaterThan(maxOrderAmount) {
				continue
			}

			// Get fiat equivalent of the token amount
			rate, _ := decimal.NewFromString(parts[2])
			fiatAmount := orderAmount.Mul(rate)

			// Check if fiat amount is within the bucket range and set the rate
			if fiatAmount.GreaterThanOrEqual(minAmount) && fiatAmount.LessThanOrEqual(maxAmount) {
				rateResponse = rate
				break
			} else if maxAmount.GreaterThan(highestMaxAmount) {
				// Get the highest max amount
				highestMaxAmount = maxAmount
				rateResponse = rate
			}
		}
	}

	return rateResponse, nil
}

// GetInstitutionByCode returns the institution for a given institution code
func GetInstitutionByCode(ctx context.Context, institutionCode string, enabledFiatCurrency bool) (*ent.Institution, error) {
	institutionQuery := storage.Client.Institution.
		Query().
		Where(institutionEnt.CodeEQ(institutionCode))

	if enabledFiatCurrency {
		institutionQuery = institutionQuery.WithFiatCurrency(
			func(fcq *ent.FiatCurrencyQuery) {
				fcq.Where(fiatcurrency.IsEnabledEQ(true))
			},
		)
	} else {
		institutionQuery = institutionQuery.WithFiatCurrency()
	}

	institution, err := institutionQuery.Only(ctx)
	if err != nil {
		return nil, err
	}
	return institution, nil
}

// Helper function to validate HTTPS URL
func IsValidHttpsUrl(urlStr string) bool {
	// Check if URL starts with https://
	if !strings.HasPrefix(strings.ToLower(urlStr), "https://") {
		return false
	}

	// Parse URL to ensure it's valid
	parsedUrl, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// Verify scheme is https and host is present
	return parsedUrl.Scheme == "https" && parsedUrl.Host != ""
}

// RateValidationResult contains the result of rate validation
type RateValidationResult struct {
	Rate       decimal.Decimal
	ProviderID string
	OrderType  paymentorder.OrderType
}

// ValidateRate validates if a provided rate is achievable for the given parameters
// Returns the rate, provider ID (if found), and order type (regular or OTC)
func ValidateRate(ctx context.Context, token *ent.Token, currency *ent.FiatCurrency, amount decimal.Decimal, providerID, networkFilter string) (RateValidationResult, error) {
	isDirectMatch := strings.EqualFold(token.BaseCurrency, currency.Code)

	// Determine which validation function to use
	var result RateValidationResult
	var err error
	if providerID != "" {
		result, err = validateProviderRate(ctx, token, currency, amount, providerID, networkFilter)
	} else {
		result, err = validateBucketRate(ctx, token, currency, amount, networkFilter)
	}

	if err != nil {
		return RateValidationResult{}, err
	}

	// For direct currency matches, rate is always 1:1
	// Both Redis queues and DB store rate 1 for direct matches (e.g., CNGN->NGN in NGN bucket)
	// We explicitly return 1.0 here for clarity and to ensure consistency
	if isDirectMatch {
		result.Rate = decimal.NewFromInt(1)
	}

	return result, nil
}

// validateProviderRate handles provider-specific rate validation
func validateProviderRate(ctx context.Context, token *ent.Token, currency *ent.FiatCurrency, amount decimal.Decimal, providerID, networkFilter string) (RateValidationResult, error) {
	// Get the provider from the database
	provider, err := storage.Client.ProviderProfile.
		Query().
		Where(providerprofile.IDEQ(providerID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return RateValidationResult{}, fmt.Errorf("provider not found")
		}
		return RateValidationResult{}, fmt.Errorf("internal server error")
	}

	// Get the provider's order token configuration to validate min/max amounts
	providerOrderTokenQuery := storage.Client.ProviderOrderToken.
		Query().
		Where(
			providerordertoken.HasProviderWith(providerprofile.IDEQ(provider.ID)),
			providerordertoken.HasTokenWith(tokenEnt.IDEQ(token.ID)),
			providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(currency.Code)),
		)

	// Filter by network if provided
	if networkFilter != "" {
		providerOrderTokenQuery = providerOrderTokenQuery.Where(
			providerordertoken.NetworkEQ(networkFilter),
		)
	}

	providerOrderToken, err := providerOrderTokenQuery.First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return RateValidationResult{}, fmt.Errorf("provider does not support this token/currency combination")
		}
		return RateValidationResult{}, fmt.Errorf("internal server error")
	}

	// Determine order type before validation
	orderType := DetermineOrderType(providerOrderToken, amount)

	// Check minimum amount first (applies to both regular and OTC)
	if amount.LessThan(providerOrderToken.MinOrderAmount) {
		return RateValidationResult{}, fmt.Errorf("amount must be at least %s for this provider", providerOrderToken.MinOrderAmount)
	}

	// Get rate first (needed for fiat conversion and OTC validation)
	var rateResponse decimal.Decimal
	redisRate, found := getProviderRateFromRedis(ctx, providerID, token.Symbol, currency.Code, amount)
	if found {
		rateResponse = redisRate
	} else {
		// Fallback to database rate if Redis rate not found
		if providerOrderToken.ConversionRateType == "fixed" {
			rateResponse = providerOrderToken.FixedConversionRate
		} else {
			// For floating rates, use market rate + floating adjustment
			rateResponse = currency.MarketRate.Add(providerOrderToken.FloatingConversionRate)
		}
	}

	// Validate amount limits: if exceeds regular max, check OTC limits
	// OTC limits are denominated in token amounts (same as regular limits)
	if amount.GreaterThan(providerOrderToken.MaxOrderAmount) {
		// Amount exceeds regular max - check if it falls within OTC limits
		if providerOrderToken.MinOrderAmountOtc.IsZero() || providerOrderToken.MaxOrderAmountOtc.IsZero() {
			return RateValidationResult{}, fmt.Errorf("amount exceeds maximum order amount (%s) for this provider", providerOrderToken.MaxOrderAmount)
		}
		if amount.LessThan(providerOrderToken.MinOrderAmountOtc) || amount.GreaterThan(providerOrderToken.MaxOrderAmountOtc) {
			if amount.LessThan(providerOrderToken.MinOrderAmountOtc) {
				return RateValidationResult{}, fmt.Errorf("amount is below minimum order amount (%s) for this provider", providerOrderToken.MinOrderAmountOtc)
			} else {
				return RateValidationResult{}, fmt.Errorf("amount exceeds maximum order amount (%s) for this provider", providerOrderToken.MaxOrderAmountOtc)
			}
		}
		// Amount is within OTC limits - allow it (order will be classified as OTC)
	} else {
		// Amount is within regular limits - proceed normally
	}

	// Check if provider has sufficient balance
	_, err = storage.Client.ProviderCurrencies.
		Query().
		Where(
			providercurrencies.HasProviderWith(providerprofile.IDEQ(provider.ID)),
			providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currency.Code)),
			providercurrencies.AvailableBalanceGT(amount.Mul(rateResponse)),
			providercurrencies.IsAvailableEQ(true),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return RateValidationResult{}, fmt.Errorf("provider has insufficient liquidity for %s", currency.Code)
		}
		return RateValidationResult{}, fmt.Errorf("internal server error")
	}

	return RateValidationResult{
		Rate:       rateResponse,
		ProviderID: providerID,
		OrderType:  orderType,
	}, nil
}

// getProviderRateFromRedis retrieves the provider's current rate from Redis queue
func getProviderRateFromRedis(ctx context.Context, providerID, tokenSymbol, currencyCode string, amount decimal.Decimal) (decimal.Decimal, bool) {
	// Get redis keys for provision buckets for this currency
	keys, _, err := storage.RedisClient.Scan(ctx, uint64(0), "bucket_"+currencyCode+"_*_*", 100).Result()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
			"Token":      tokenSymbol,
			"Currency":   currencyCode,
		}).Debugf("Failed to scan Redis buckets for provider rate")
		return decimal.Zero, false
	}

	// Scan through the buckets to find the provider's rate
	for _, key := range keys {
		_, err := parseBucketKey(key)
		if err != nil {
			continue
		}

		// Get all providers in this bucket
		providers, err := storage.RedisClient.LRange(ctx, key, 0, -1).Result()
		if err != nil {
			continue
		}

		// Look for the specific provider
		for _, providerData := range providers {
			parts := strings.Split(providerData, ":")
			if len(parts) != 5 {
				continue
			}

			// Check if this is the provider we're looking for
			if parts[0] == providerID && parts[1] == tokenSymbol {
				// Parse the rate
				rate, err := decimal.NewFromString(parts[2])
				if err != nil {
					continue
				}

				// Parse min/max order amounts
				minOrderAmount, err := decimal.NewFromString(parts[3])
				if err != nil {
					continue
				}

				maxOrderAmount, err := decimal.NewFromString(parts[4])
				if err != nil {
					continue
				}

				// Check if amount is within provider's limits
				if amount.GreaterThanOrEqual(minOrderAmount) && amount.LessThanOrEqual(maxOrderAmount) {
					return rate, true
				}
			}
		}
	}

	return decimal.Zero, false
}

// validateBucketRate handles bucket-based rate validation
func validateBucketRate(ctx context.Context, token *ent.Token, currency *ent.FiatCurrency, amount decimal.Decimal, networkIdentifier string) (RateValidationResult, error) {
	// Get redis keys for provision buckets
	keys, _, err := storage.RedisClient.Scan(ctx, uint64(0), "bucket_"+currency.Code+"_*_*", 100).Result()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Currency": currency.Code,
			"Network":  networkIdentifier,
		}).Errorf("Failed to scan Redis buckets for bucket rate")
		return RateValidationResult{}, fmt.Errorf("internal server error")
	}

	// Track the best available rate and reason for logging
	var bestRate decimal.Decimal
	var foundExactMatch bool
	var selectedProviderID string
	var selectedOrderType paymentorder.OrderType

	// Scan through the buckets to find a matching rate
	for _, key := range keys {
		bucketData, err := parseBucketKey(key)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Key":   key,
				"Error": err,
			}).Errorf("ValidateRate.InvalidBucketKey: failed to parse bucket key")
			continue
		}

		// Get all providers in this bucket to find the first suitable one (priority queue order)
		providers, err := storage.RedisClient.LRange(ctx, key, 0, -1).Result()
		if err != nil {
			logger.WithFields(logger.Fields{
				"Key":   key,
				"Error": err,
			}).Errorf("ValidateRate.FailedToGetProviders: failed to get providers from bucket")
			continue
		}

		// Find the first provider at the top of the queue that matches our criteria
		result := findSuitableProviderRate(ctx, providers, token.Symbol, networkIdentifier, amount, bucketData)
		if result.Found {
			foundExactMatch = true
			bestRate = result.Rate
			selectedProviderID = result.ProviderID
			selectedOrderType = result.OrderType
			break // Found exact match, no need to continue
		}

		// Track the best available rate for logging purposes
		if result.Rate.GreaterThan(bestRate) {
			bestRate = result.Rate
		}
	}

	// If no exact match found, return error with details
	if !foundExactMatch {
		logger.WithFields(logger.Fields{
			"Token":         token.Symbol,
			"Currency":      currency.Code,
			"Amount":        amount,
			"NetworkFilter": networkIdentifier,
			"BestRate":      bestRate,
		}).Warnf("ValidateRate.NoSuitableProvider: no provider found for the given parameters")

		// Provide more specific error message
		networkMsg := networkIdentifier
		if networkMsg == "" {
			networkMsg = "any network"
		}
		return RateValidationResult{}, fmt.Errorf("no provider available for %s to %s conversion with amount %s on %s",
			token.Symbol, currency.Code, amount, networkMsg)
	}

	return RateValidationResult{
		Rate:       bestRate,
		ProviderID: selectedProviderID,
		OrderType:  selectedOrderType,
	}, nil
}

// parseBucketKey parses and validates bucket key format
type BucketData struct {
	Currency  string
	MinAmount decimal.Decimal
	MaxAmount decimal.Decimal
}

func parseBucketKey(key string) (*BucketData, error) {
	// Expected format: "bucket_{currency}_{minAmount}_{maxAmount}"
	parts := strings.Split(key, "_")
	if len(parts) != 4 && len(parts) != 5 {
		return nil, fmt.Errorf("invalid bucket key format: expected 4 parts, got %d", len(parts))
	}

	if parts[0] != "bucket" {
		return nil, fmt.Errorf("invalid bucket key prefix: expected 'bucket', got '%s'", parts[0])
	}

	currency := parts[1]
	if currency == "" {
		return nil, fmt.Errorf("empty currency in bucket key")
	}

	minAmount, err := decimal.NewFromString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid min amount '%s': %v", parts[2], err)
	}

	maxAmount, err := decimal.NewFromString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid max amount '%s': %v", parts[3], err)
	}

	if minAmount.GreaterThanOrEqual(maxAmount) {
		return nil, fmt.Errorf("min amount (%s) must be less than max amount (%s)", minAmount, maxAmount)
	}

	return &BucketData{
		Currency:  currency,
		MinAmount: minAmount,
		MaxAmount: maxAmount,
	}, nil
}

// ProviderRateResult contains the result of finding a suitable provider rate
type ProviderRateResult struct {
	Rate       decimal.Decimal
	ProviderID string
	OrderType  paymentorder.OrderType
	Found      bool
}

// findSuitableProviderRate finds the first suitable provider rate from the provider list
// Returns the rate, provider ID, order type, and a boolean indicating if an exact match was found
// An exact match means: amount within limits, within bucket range, and provider has sufficient balance
func findSuitableProviderRate(ctx context.Context, providers []string, tokenSymbol string, networkIdentifier string, tokenAmount decimal.Decimal, bucketData *BucketData) ProviderRateResult {
	var bestRate decimal.Decimal
	var foundExactMatch bool

	// Track reasons for debugging when no match is found
	var skipReasons []string

	for _, providerData := range providers {
		parts := strings.Split(providerData, ":")
		if len(parts) != 5 {
			logger.WithFields(logger.Fields{
				"ProviderData": providerData,
				"Token":        tokenSymbol,
				"Currency":     bucketData.Currency,
				"MinAmount":    bucketData.MinAmount,
				"MaxAmount":    bucketData.MaxAmount,
			}).Errorf("ValidateRate.InvalidProviderData: provider data format is invalid")
			continue
		}

		// Skip entry if token doesn't match
		if parts[1] != tokenSymbol {
			continue
		}

		// Fetch provider order token for network validation and OTC limits check
		// TODO: Move this to redis cache. Provider's network should be in the key.
		var providerOrderToken *ent.ProviderOrderToken
		if networkIdentifier != "" {
			// Network filter provided - fetch with network constraint
			pot, err := storage.Client.ProviderOrderToken.
				Query().
				Where(
					providerordertoken.HasProviderWith(
						providerprofile.IDEQ(parts[0]),
						providerprofile.HasProviderCurrenciesWith(
							providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(bucketData.Currency)),
							providercurrencies.IsAvailableEQ(true),
						),
					),
					providerordertoken.HasTokenWith(tokenEnt.SymbolEQ(parts[1])),
					providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(bucketData.Currency)),
					providerordertoken.NetworkEQ(networkIdentifier),
					providerordertoken.AddressNEQ(""),
				).Only(ctx)
			if err != nil {
				if ent.IsNotFound(err) {
					continue
				}
				logger.WithFields(logger.Fields{
					"ProviderData": providerData,
					"Error":        err,
				}).Errorf("ValidateRate.InvalidProviderData: failed to fetch provider configuration")
				continue
			}
			providerOrderToken = pot
		} else {
			// No network filter - fetch first matching entry
			pot, err := storage.Client.ProviderOrderToken.
				Query().
				Where(
					providerordertoken.HasProviderWith(
						providerprofile.IDEQ(parts[0]),
						providerprofile.HasProviderCurrenciesWith(
							providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(bucketData.Currency)),
							providercurrencies.IsAvailableEQ(true),
						),
					),
					providerordertoken.HasTokenWith(tokenEnt.SymbolEQ(parts[1])),
					providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(bucketData.Currency)),
					providerordertoken.AddressNEQ(""),
				).First(ctx)
			if err != nil {
				if ent.IsNotFound(err) {
					continue
				}
				logger.WithFields(logger.Fields{
					"ProviderData": providerData,
					"Error":        err,
				}).Errorf("ValidateRate.InvalidProviderData: failed to fetch provider configuration")
				continue
			}
			providerOrderToken = pot
		}

		// Parse provider order amounts
		minOrderAmount, err := decimal.NewFromString(parts[3])
		if err != nil {
			logger.WithFields(logger.Fields{
				"ProviderData": providerData,
				"Error":        err,
			}).Errorf("ValidateRate.InvalidMinOrderAmount: failed to parse min order amount")
			continue
		}

		maxOrderAmount, err := decimal.NewFromString(parts[4])
		if err != nil {
			logger.WithFields(logger.Fields{
				"ProviderData": providerData,
				"Error":        err,
			}).Errorf("ValidateRate.InvalidMaxOrderAmount: failed to parse max order amount")
			continue
		}

		// Check if order amount is within provider's regular min/max limits
		// If not, check OTC limits as fallback
		if tokenAmount.LessThan(minOrderAmount) {
			// Amount below regular min - skip
			skipReasons = append(skipReasons, fmt.Sprintf("amount %s below min %s", tokenAmount, minOrderAmount))
			continue
		} else if tokenAmount.GreaterThan(maxOrderAmount) {
			// Amount exceeds regular max - check OTC limits using already fetched providerOrderToken
			// Check if token amount is within OTC limits
			if providerOrderToken.MinOrderAmountOtc.IsZero() || providerOrderToken.MaxOrderAmountOtc.IsZero() {
				// OTC limits not configured - skip
				skipReasons = append(skipReasons, fmt.Sprintf("amount %s exceeds max %s, OTC limits not configured", tokenAmount, maxOrderAmount))
				continue
			}

			if tokenAmount.LessThan(providerOrderToken.MinOrderAmountOtc) || tokenAmount.GreaterThan(providerOrderToken.MaxOrderAmountOtc) {
				// Amount outside OTC limits - skip
				skipReasons = append(skipReasons, fmt.Sprintf("amount %s outside OTC range [%s, %s]", tokenAmount, providerOrderToken.MinOrderAmountOtc, providerOrderToken.MaxOrderAmountOtc))
				continue
			}

			// Amount is within OTC limits - proceed to rate parsing
		}

		// Parse rate
		rate, err := decimal.NewFromString(parts[2])
		if err != nil {
			logger.WithFields(logger.Fields{
				"ProviderData": providerData,
				"Error":        err,
			}).Errorf("ValidateRate.InvalidRate: failed to parse rate")
			continue
		}

		providerID := parts[0]

		// Track the best rate we've seen (for logging purposes)
		if rate.GreaterThan(bestRate) {
			bestRate = rate
		}

		// Calculate fiat equivalent of the token amount
		fiatAmount := tokenAmount.Mul(rate)

		// Check if fiat amount is within the bucket range
		if fiatAmount.GreaterThanOrEqual(bucketData.MinAmount) && fiatAmount.LessThanOrEqual(bucketData.MaxAmount) {
			// Amount is within bucket range - check provider balance before returning
			_, err := storage.Client.ProviderCurrencies.
				Query().
				Where(
					providercurrencies.HasProviderWith(providerprofile.IDEQ(providerID)),
					providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(bucketData.Currency)),
					providercurrencies.AvailableBalanceGT(fiatAmount),
					providercurrencies.IsAvailableEQ(true),
				).
				Only(ctx)
			if err != nil {
				if ent.IsNotFound(err) {
					skipReasons = append(skipReasons, fmt.Sprintf("provider %s has insufficient balance (need %s %s)", providerID, fiatAmount, bucketData.Currency))
					continue
				}
				return ProviderRateResult{Found: false}
			}

			// Determine order type for this provider
			orderType := DetermineOrderType(providerOrderToken, tokenAmount)

			// Provider has balance and amount is within bucket range - exact match
			return ProviderRateResult{
				Rate:       rate,
				ProviderID: providerID,
				OrderType:  orderType,
				Found:      true,
			}
		}

		// Amount is outside bucket range - skip this provider
		skipReasons = append(skipReasons, fmt.Sprintf("fiat amount %s outside bucket range [%s, %s]", fiatAmount, bucketData.MinAmount, bucketData.MaxAmount))
		continue
	}

	// Return the best rate we found (even if no exact match) for logging purposes
	// Log skip reasons for debugging if no match was found
	if !foundExactMatch && len(skipReasons) > 0 {
		maxReasons := 5
		if len(skipReasons) < maxReasons {
			maxReasons = len(skipReasons)
		}
		logger.WithFields(logger.Fields{
			"Token":       tokenSymbol,
			"Amount":      tokenAmount,
			"SkipReasons": skipReasons[:maxReasons], // Log first 5 reasons
		}).Debugf("ValidateRate.NoSuitableProvider: providers skipped due to limits/balance")
	}

	return ProviderRateResult{
		Rate:  bestRate,
		Found: foundExactMatch,
	}
}

// ValidateAccount validates if an account exists for the given institution and account identifier
// Returns the account name if verification is successful, or an error if verification fails
func ValidateAccount(ctx context.Context, institutionCode, accountIdentifier string) (string, error) {
	// Get institution with enabled fiat currency
	institution, err := storage.Client.Institution.
		Query().
		Where(institutionEnt.CodeEQ(institutionCode)).
		WithFiatCurrency(func(fq *ent.FiatCurrencyQuery) {
			fq.Where(fiatcurrency.IsEnabledEQ(true))
		}).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return "", fmt.Errorf("institution %s is not supported", institutionCode)
		}
		return "", fmt.Errorf("failed to fetch institution: %v", err)
	}

	// Skip account verification for mobile money institutions
	if institution.Type == institutionEnt.TypeMobileMoney {
		return "OK", nil
	}

	// Find available providers for the currency
	providers, err := storage.Client.ProviderProfile.
		Query().
		Where(
			providerprofile.HasProviderCurrenciesWith(
				providercurrencies.HasCurrencyWith(
					fiatcurrency.CodeEQ(institution.Edges.FiatCurrency.Code),
				),
				providercurrencies.IsAvailableEQ(true),
			),
			providerprofile.HostIdentifierNotNil(),
			providerprofile.IsActiveEQ(true),
			providerprofile.VisibilityModeEQ(providerprofile.VisibilityModePublic),
		).
		All(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to fetch providers: %v", err)
	}

	if len(providers) == 0 {
		return "", fmt.Errorf("no available providers found for currency %s", institution.Edges.FiatCurrency.Code)
	}

	// Prepare payload for account verification
	payload := map[string]interface{}{
		"institution":       institutionCode,
		"accountIdentifier": accountIdentifier,
	}

	// Try each provider until one succeeds
	for _, provider := range providers {
		// Call provider /verify_account endpoint using utility function
		data, err := CallProviderWithHMAC(ctx, provider.ID, "POST", "/verify_account", payload)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":             fmt.Sprintf("%v", err),
				"ProviderID":        provider.ID,
				"Institution":       institutionCode,
				"AccountIdentifier": accountIdentifier,
			}).Warnf("Failed to verify account with provider %s", provider.ID)
			continue
		}

		// Extract account name from response
		if accountName, ok := data["data"].(string); ok && accountName != "" && accountName != "OK" {
			return accountName, nil
		}
	}

	return "", fmt.Errorf("failed to verify account with any provider")
}

// DetermineOrderType determines the order type based on the order token OTC config and token amount.
// OTC limits are denominated in token amounts (same as regular limits).
// OTC is only used when the amount exceeds regular max AND falls within OTC limits.
func DetermineOrderType(orderToken *ent.ProviderOrderToken, tokenAmount decimal.Decimal) paymentorder.OrderType {
	if orderToken == nil {
		return paymentorder.OrderTypeRegular
	}

	// Check if amount is within regular limits
	if tokenAmount.LessThanOrEqual(orderToken.MaxOrderAmount) {
		return paymentorder.OrderTypeRegular
	}

	// Amount exceeds regular max - check if OTC is configured
	minOTC := orderToken.MinOrderAmountOtc
	maxOTC := orderToken.MaxOrderAmountOtc
	if minOTC.IsZero() || maxOTC.IsZero() || minOTC.GreaterThan(maxOTC) {
		// OTC limits not configured - cannot be OTC, return regular (will fail validation)
		return paymentorder.OrderTypeRegular
	}

	// OTC limits are configured - any amount exceeding regular max should be treated as OTC attempt
	// Validation will catch if it's outside the valid OTC range (gap between MaxOrderAmount and MinOrderAmountOtc, or > MaxOrderAmountOtc)
	return paymentorder.OrderTypeOtc
}


// ParseByteArray converts Cairo ByteArray format to string
// ByteArray format: [num_full_chunks, ...full_chunks, pending_word, pending_word_len]
func ParseByteArray(data []*felt.Felt) string {
	if len(data) < 3 {
		return ""
	}

	numFullChunks := int(data[0].BigInt(big.NewInt(0)).Int64())

	if len(data) < numFullChunks+3 {
		return ""
	}

	var result []byte

	// Process full chunks (31 bytes each)
	for i := 0; i < numFullChunks; i++ {
		chunk := data[1+i]
		chunkBytes := chunk.Bytes()

		// Convert [32]byte to slice and take last 31 bytes
		chunkSlice := chunkBytes[:]
		if len(chunkSlice) >= 31 {
			result = append(result, chunkSlice[len(chunkSlice)-31:]...)
		} else {
			// If less than 31 bytes, pad with zeros at the front
			padding := make([]byte, 31-len(chunkSlice))
			result = append(result, padding...)
			result = append(result, chunkSlice...)
		}
	}

	// Process pending word
	pendingWord := data[1+numFullChunks]
	pendingWordLen := int(data[2+numFullChunks].BigInt(big.NewInt(0)).Int64())

	if pendingWordLen > 0 {
		pendingBytes := pendingWord.Bytes()
		pendingSlice := pendingBytes[:]

		if len(pendingSlice) > pendingWordLen {
			pendingSlice = pendingSlice[len(pendingSlice)-pendingWordLen:]
		}
		result = append(result, pendingSlice...)
	}

	return string(result)
}

func ParseByteArrayFromJSON(messageHashData map[string]interface{}) (string, error) {
	if messageHashData == nil {
		return "", fmt.Errorf("messageHashData is nil")
	}

	// Extract data array
	data, ok := messageHashData["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("data field missing or invalid")
	}

	dataValue, ok := data["value"].([]interface{})
	if !ok {
		dataValue = []interface{}{} // Empty array if not present
	}

	// Extract pending_word
	pendingWordMap, ok := messageHashData["pending_word"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("pending_word field missing or invalid")
	}
	pendingWordStr, ok := pendingWordMap["value"].(string)
	if !ok {
		return "", fmt.Errorf("pending_word value missing or invalid")
	}

	// Extract pending_word_len
	pendingWordLenMap, ok := messageHashData["pending_word_len"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("pending_word_len field missing or invalid")
	}
	pendingWordLenStr, ok := pendingWordLenMap["value"].(string)
	if !ok {
		return "", fmt.Errorf("pending_word_len value missing or invalid")
	}

	// Convert to []*felt.Felt array
	felts := make([]*felt.Felt, 0)

	// 1. Number of full chunks
	felts = append(felts, new(felt.Felt).SetUint64(uint64(len(dataValue))))

	// 2. Full chunks
	for _, item := range dataValue {
		if str, ok := item.(string); ok {
			felt, err := utils.HexToFelt(str)
			if err != nil {
				continue
			}
			felts = append(felts, felt)
		}
	}

	// 3. Pending word
	pendingWordFelt, err := utils.HexToFelt(pendingWordStr)
	if err != nil {
		return "", fmt.Errorf("invalid pending_word: %w", err)
	}
	felts = append(felts, pendingWordFelt)

	// 4. Pending word length
	pendingWordLenFelt, err := utils.HexToFelt(pendingWordLenStr)
	if err != nil {
		return "", fmt.Errorf("invalid pending_word_len: %w", err)
	}
	felts = append(felts, pendingWordLenFelt)

	// Use the existing ParseByteArray function
	return ParseByteArray(felts), nil
}

func ParseStringAsDecimals(strVal string) (decimal.Decimal, error) {
	if strVal == "" {
		return decimal.Zero, fmt.Errorf("empty string")
	}

	// Check if it's a hex string
	if strings.HasPrefix(strVal, "0x") || strings.HasPrefix(strVal, "0X") {
		return parseHexString(strVal)
	}

	// Try parsing as decimal string
	result, err := decimal.NewFromString(strVal)
	if err != nil {
		return decimal.Zero, fmt.Errorf("invalid decimal string '%s': %w", strVal, err)
	}

	return result, nil
}


// parseHexString converts hex string to decimal
func parseHexString(hexStr string) (decimal.Decimal, error) {
	// Remove 0x prefix and convert to lowercase
	hexStr = strings.TrimPrefix(strings.ToLower(hexStr), "0x")

	if hexStr == "" {
		return decimal.Zero, nil
	}

	// Parse hex to big.Int
	bigInt := new(big.Int)
	_, success := bigInt.SetString(hexStr, 16)
	if !success {
		return decimal.Zero, fmt.Errorf("invalid hex string: 0x%s", hexStr)
	}

	return decimal.NewFromBigInt(bigInt, 0), nil
}