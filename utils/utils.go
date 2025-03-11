package utils

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
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
	institutionEnt "github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/paymentorder"
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

// BigMin returns the minimum value between two big numbers
func BigMin(x, y *big.Int) *big.Int {
	if x.Cmp(y) < 0 {
		return x
	}
	return y
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

// SendPaymentOrderWebhook notifies a sender when the status of a payment order changes
func SendPaymentOrderWebhook(ctx context.Context, paymentOrder *ent.PaymentOrder) error {
	var err error

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
	case paymentorder.StatusExpired:
		event = "payment_order.expired"
	case paymentorder.StatusSettled:
		event = "payment_order.settled"
	case paymentorder.StatusRefunded:
		event = "payment_order.refunded"
	default:
		return nil
	}

	// Fetch the recipient
	recipient, err := paymentOrder.QueryRecipient().Only(ctx)
	if err != nil {
		return err
	}

	// Fetch the token
	token, err := paymentOrder.
		QueryToken().
		WithNetwork().
		Only(ctx)
	if err != nil {
		return err
	}

	institution, err := storage.Client.Institution.
		Query().
		Where(institutionEnt.CodeEQ(recipient.Institution)).
		WithFiatCurrency().
		Only(ctx)
	if err != nil {
		return err
	}

	// Create the payload
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
			Network:        token.Edges.Network.Identifier,
			GatewayID:      paymentOrder.GatewayID,
			SenderID:       profile.ID,
			Recipient: types.PaymentOrderRecipient{
				Currency:          institution.Edges.FiatCurrency.Code,
				Institution:       recipient.Institution,
				AccountIdentifier: recipient.AccountIdentifier,
				AccountName:       recipient.AccountName,
				ProviderID:        recipient.ProviderID,
				Memo:              recipient.Memo,
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
	pattern := `^T[a-zA-Z0-9]{33}$`
	matched, _ := regexp.MatchString(pattern, address)
	return matched
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
				logger.Errorf("utils.GetTokenRateFromQueue.InvalidProviderData: %v", providerData)
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

type contextKey string

const skipSoftDeleteKey contextKey = "skipSoftDelete"

// SkipSoftDelete adds a context value to skip soft delete logic.
func SkipSoftDelete(ctx context.Context) context.Context {
	return context.WithValue(ctx, skipSoftDeleteKey, true)
}

// IsSkipSoftDelete returns true if the context indicates that soft delete should be skipped.
func IsSkipSoftDelete(ctx context.Context) bool {
	val := ctx.Value(skipSoftDeleteKey)
	if val != nil {
		return val.(bool)
	}
	return false
}