package utils

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/anaskhan96/base58check"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	institutionEnt "github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/paymentorderfulfillment"
	"github.com/paycrest/aggregator/ent/providerbalances"
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

// CalculatePaymentOrderAmountInUSD calculates the amount in USD for a payment order.
// It uses MarketBuyRate for onramp (when non-zero) and MarketSellRate for offramp or when buy rate is zero.
func CalculatePaymentOrderAmountInUSD(amount decimal.Decimal, token *ent.Token, institution *ent.Institution, direction paymentorder.Direction) decimal.Decimal {
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

	if fiatCurrency == nil || token.BaseCurrency != fiatCurrency.Code {
		return amount
	}

	// Onramp: use buy rate (crypto bought with fiat); offramp or zero buy rate: use sell rate
	var rate decimal.Decimal
	if direction == paymentorder.DirectionOnramp && !fiatCurrency.MarketBuyRate.IsZero() {
		rate = fiatCurrency.MarketBuyRate
	} else if !fiatCurrency.MarketSellRate.IsZero() {
		rate = fiatCurrency.MarketSellRate
	} else {
		return amount
	}
	return amount.Div(rate)
}

// SendPaymentOrderWebhook notifies a sender when the status of a payment order changes
func SendPaymentOrderWebhook(ctx context.Context, paymentOrder *ent.PaymentOrder) error {
	var err error

	paymentOrder, err = storage.Client.PaymentOrder.
		Query().
		Where(paymentorder.IDEQ(paymentOrder.ID)).
		WithSenderProfile().
		WithProvider().
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
	case paymentorder.StatusDeposited:
		event = "payment_order.deposited"
	case paymentorder.StatusPending:
		event = "payment_order.pending"
	case paymentorder.StatusValidated:
		event = "payment_order.validated"
	case paymentorder.StatusSettling:
		event = "payment_order.settling"
	case paymentorder.StatusSettled:
		event = "payment_order.settled"
	case paymentorder.StatusRefunding:
		event = "payment_order.refunding"
	case paymentorder.StatusRefunded:
		event = "payment_order.refunded"
	case paymentorder.StatusExpired:
		event = "payment_order.expired"
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

	var providerID string
	if paymentOrder.Edges.Provider != nil {
		providerID = paymentOrder.Edges.Provider.ID
	}

	webhookVersion := profile.WebhookVersion
	if webhookVersion == "" {
		webhookVersion = "1"
	}

	var payload map[string]interface{}
	if webhookVersion == "2" {
		// V2: aligned with API schema — providerAccount, source, destination (same types as V2PaymentOrderResponse).
		source, destination, providerAccount := BuildV2OrderSourceDestinationProviderAccount(paymentOrder, institution)

		payloadStructV2 := types.V2PaymentOrderWebhookPayload{
			Event:          event,
			WebhookVersion: webhookVersion,
			Data: types.V2PaymentOrderWebhookData{
				ID:              paymentOrder.ID,
				Direction:       string(paymentOrder.Direction),
				Amount:          paymentOrder.Amount,
				AmountInUSD:     paymentOrder.AmountInUsd,
				AmountPaid:      paymentOrder.AmountPaid,
				AmountReturned:  paymentOrder.AmountReturned,
				PercentSettled:  paymentOrder.PercentSettled,
				SenderFee:       paymentOrder.SenderFee,
				TransactionFee:  paymentOrder.NetworkFee.Add(paymentOrder.ProtocolFee),
				Rate:            paymentOrder.Rate,
				GatewayID:       paymentOrder.GatewayID,
				SenderID:        profile.ID,
				ProviderAccount: providerAccount,
				Source:          source,
				Destination:     destination,
				FromAddress:     paymentOrder.FromAddress,
				Reference:       paymentOrder.Reference,
				Timestamp:       time.Now().UTC(),
				TxHash:          paymentOrder.TxHash,
				Status:          paymentOrder.Status,
			},
		}
		// Use JSON round-trip so field names honor json tags (e.g. webhookVersion not webhookversion)
		payloadBytes, _ := json.Marshal(payloadStructV2)
		_ = json.Unmarshal(payloadBytes, &payload)
	} else {
		// V1: current payload (backward compatible)
		payloadStruct := types.PaymentOrderWebhookPayload{
			Event:          event,
			WebhookVersion: webhookVersion,
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
				ReturnAddress: paymentOrder.RefundOrRecipientAddress,
				RefundAddress: paymentOrder.RefundOrRecipientAddress,
				Reference:     paymentOrder.Reference,
				UpdatedAt:     paymentOrder.UpdatedAt,
				CreatedAt:     paymentOrder.CreatedAt,
				TxHash:        paymentOrder.TxHash,
				Status:        paymentOrder.Status,
			},
		}
		// Use JSON round-trip so field names honor json tags (e.g. webhookVersion not webhookversion)
		payloadBytes, _ := json.Marshal(payloadStruct)
		_ = json.Unmarshal(payloadBytes, &payload)
	}

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
		Config().SetCustomTransport(GetHTTPClient().Transport).Config().SetTimeout(30*time.Second).
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

// ParseValidUntilFromMetadata extracts a time from metadata validUntil (string RFC3339 or numeric Unix seconds).
func ParseValidUntilFromMetadata(v interface{}) (time.Time, bool) {
	if v == nil {
		return time.Time{}, false
	}
	switch x := v.(type) {
	case string:
		t, err := time.Parse(time.RFC3339, x)
		if err != nil {
			return time.Time{}, false
		}
		return t, true
	case float64:
		return time.Unix(int64(x), 0), true
	case int:
		return time.Unix(int64(x), 0), true
	case int64:
		return time.Unix(x, 0), true
	case int32:
		return time.Unix(int64(x), 0), true
	default:
		return time.Time{}, false
	}
}

// BuildV2OrderSourceDestinationProviderAccount builds source, destination, and providerAccount for v2 API/get responses.
// paymentOrder must have Token and Token.Edges.Network loaded. institution is required for fiat (currency); use nil only if unavailable (then currency/institution display may be empty).
func BuildV2OrderSourceDestinationProviderAccount(paymentOrder *ent.PaymentOrder, institution *ent.Institution) (source, destination, providerAccount any) {
	networkID := ""
	if paymentOrder.Edges.Token != nil && paymentOrder.Edges.Token.Edges.Network != nil {
		networkID = paymentOrder.Edges.Token.Edges.Network.Identifier
	}
	tokenSymbol := ""
	if paymentOrder.Edges.Token != nil {
		tokenSymbol = paymentOrder.Edges.Token.Symbol
	}
	currencyCode := ""
	if institution != nil && institution.Edges.FiatCurrency != nil {
		currencyCode = institution.Edges.FiatCurrency.Code
	}
	providerID := ""
	if paymentOrder.Edges.Provider != nil {
		providerID = paymentOrder.Edges.Provider.ID
	}

	isOnramp := paymentOrder.Direction == paymentorder.DirectionOnramp
	if isOnramp {
		if paymentOrder.Metadata != nil {
			if pa, ok := paymentOrder.Metadata["providerAccount"].(map[string]interface{}); ok {
				var inst, acctID, acctName string
				if v, ok := pa["institution"].(string); ok {
					inst = v
				}
				if v, ok := pa["accountIdentifier"].(string); ok {
					acctID = v
				}
				if v, ok := pa["accountName"].(string); ok {
					acctName = v
				}
				var validUntil time.Time
				if t, ok := ParseValidUntilFromMetadata(pa["validUntil"]); ok {
					validUntil = t
				}
				var amountToTransfer, currency string
				if v, ok := pa["amountToTransfer"].(string); ok {
					amountToTransfer = v
				}
				if v, ok := pa["currency"].(string); ok {
					currency = v
				}
				providerAccount = &types.V2FiatProviderAccount{
					Institution:       inst,
					AccountIdentifier: acctID,
					AccountName:       acctName,
					ValidUntil:        validUntil,
					AmountToTransfer:  amountToTransfer,
					Currency:          currency,
				}
			}
		}
		refundAccountMetadata := (map[string]interface{})(nil)
		if paymentOrder.Metadata != nil {
			if m, ok := paymentOrder.Metadata["refundAccountMetadata"].(map[string]interface{}); ok {
				refundAccountMetadata = m
			}
		}
		country := ""
		if paymentOrder.Metadata != nil {
			if c, ok := paymentOrder.Metadata["country"].(string); ok {
				country = c
			}
		}
		source = &types.V2FiatSource{
			Type:     "fiat",
			Currency: currencyCode,
			Country:  country,
			RefundAccount: types.V2FiatRefundAccount{
				Institution:       paymentOrder.Institution,
				AccountIdentifier: paymentOrder.AccountIdentifier,
				AccountName:       paymentOrder.AccountName,
				Metadata:          refundAccountMetadata,
			},
		}
		destination = &types.V2CryptoDestinationOnrampResponse{
			Type:       "crypto",
			Currency:   tokenSymbol,
			ProviderID: providerID,
			Recipient:  types.V2CryptoRecipientOnrampResponse{Address: paymentOrder.RefundOrRecipientAddress},
		}
	} else {
		if paymentOrder.ReceiveAddress != "" {
			providerAccount = &types.V2CryptoProviderAccount{
				Network:        networkID,
				ReceiveAddress: paymentOrder.ReceiveAddress,
				ValidUntil:     paymentOrder.ReceiveAddressExpiry,
			}
		}
		source = &types.V2CryptoSource{
			Type:          "crypto",
			Currency:      tokenSymbol,
			Network:       networkID,
			RefundAddress: paymentOrder.RefundOrRecipientAddress,
		}
		destCountry := ""
		if paymentOrder.Metadata != nil {
			if c, ok := paymentOrder.Metadata["country"].(string); ok {
				destCountry = c
			}
		}
		// Allowlist recipient metadata to avoid leaking KYC/internal fields
		recipientMeta := make(map[string]interface{})
		if paymentOrder.Metadata != nil {
			for _, key := range []string{"bank_code", "branch", "reference", "reference2"} {
				if v, ok := paymentOrder.Metadata[key]; ok {
					recipientMeta[key] = v
				}
			}
		}
		destination = &types.V2FiatDestination{
			Type:       "fiat",
			Currency:   currencyCode,
			Country:    destCountry,
			ProviderID: providerID,
			Recipient: types.V2FiatRecipient{
				Institution:       paymentOrder.Institution,
				AccountIdentifier: paymentOrder.AccountIdentifier,
				AccountName:       paymentOrder.AccountName,
				Memo:              paymentOrder.Memo,
				Metadata:          recipientMeta,
			},
		}
	}
	return source, destination, providerAccount
}

// BuildV2PaymentOrderGetResponse builds a full V2PaymentOrderGetResponse from payment order and optional provider fields.
func BuildV2PaymentOrderGetResponse(
	paymentOrder *ent.PaymentOrder,
	institution *ent.Institution,
	transactionLogs []types.TransactionLog,
	cancellationReasons []string,
	otcExpiry *time.Time,
) *types.V2PaymentOrderGetResponse {
	source, destination, providerAccount := BuildV2OrderSourceDestinationProviderAccount(paymentOrder, institution)
	txFee := paymentOrder.NetworkFee.Add(paymentOrder.ProtocolFee)
	senderFeePercentStr := ""
	if !paymentOrder.FeePercent.IsZero() {
		senderFeePercentStr = paymentOrder.FeePercent.String()
	} else if !paymentOrder.Amount.IsZero() {
		senderFeePercentStr = paymentOrder.SenderFee.Div(paymentOrder.Amount).Mul(decimal.NewFromInt(100)).String()
	}
	resp := &types.V2PaymentOrderGetResponse{
		ID:                  paymentOrder.ID,
		Status:              string(paymentOrder.Status),
		Direction:           string(paymentOrder.Direction),
		CreatedAt:           paymentOrder.CreatedAt,
		UpdatedAt:           paymentOrder.UpdatedAt,
		Amount:              paymentOrder.Amount.String(),
		AmountInUsd:         paymentOrder.AmountInUsd.String(),
		AmountPaid:          paymentOrder.AmountPaid.String(),
		AmountReturned:      paymentOrder.AmountReturned.String(),
		PercentSettled:      paymentOrder.PercentSettled.String(),
		Rate:                paymentOrder.Rate.String(),
		SenderFee:           paymentOrder.SenderFee.String(),
		SenderFeePercent:    senderFeePercentStr,
		TransactionFee:      txFee.String(),
		Reference:           paymentOrder.Reference,
		ProviderAccount:     providerAccount,
		Source:              source,
		Destination:         destination,
		TxHash:              paymentOrder.TxHash,
		TransactionLogs:     transactionLogs,
		CancellationReasons: cancellationReasons,
		OTCExpiry:           otcExpiry,
	}
	return resp
}

// V2OrderListExtra returns optional cancellation reasons and OTC expiry for a payment order (used by provider list).
type V2OrderListExtra func(po *ent.PaymentOrder) (cancellationReasons []string, otcExpiry *time.Time)

// BuildV2PaymentOrderGetResponseList batch-fetches institutions and builds V2 get responses for the given orders.
// If extra is non-nil it is called per order to supply cancellationReasons and otcExpiry (e.g. for provider list).
func BuildV2PaymentOrderGetResponseList(ctx context.Context, paymentOrders []*ent.PaymentOrder, extra V2OrderListExtra) ([]types.V2PaymentOrderGetResponse, error) {
	if len(paymentOrders) == 0 {
		return nil, nil
	}
	codes := make(map[string]bool)
	for _, po := range paymentOrders {
		codes[po.Institution] = true
	}
	codeSlice := make([]string, 0, len(codes))
	for c := range codes {
		codeSlice = append(codeSlice, c)
	}
	institutions, err := storage.Client.Institution.
		Query().
		Where(institutionEnt.CodeIn(codeSlice...)).
		WithFiatCurrency().
		All(ctx)
	if err != nil {
		return nil, err
	}
	instMap := make(map[string]*ent.Institution)
	for _, inst := range institutions {
		instMap[inst.Code] = inst
	}

	out := make([]types.V2PaymentOrderGetResponse, 0, len(paymentOrders))
	for _, po := range paymentOrders {
		inst := instMap[po.Institution]
		var txLogs []types.TransactionLog
		for _, tx := range po.Edges.Transactions {
			txLogs = append(txLogs, types.TransactionLog{ID: tx.ID, GatewayId: tx.GatewayID, Status: tx.Status, TxHash: tx.TxHash, CreatedAt: tx.CreatedAt})
		}
		var cancellationReasons []string
		var otcExpiry *time.Time
		if extra != nil {
			cancellationReasons, otcExpiry = extra(po)
		}
		resp := BuildV2PaymentOrderGetResponse(po, inst, txLogs, cancellationReasons, otcExpiry)
		out = append(out, *resp)
	}
	return out, nil
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

	// Build URL and body so the request respects ctx (client disconnect / deadline cancels the call)
	base := strings.TrimSuffix(provider.HostIdentifier, "/")
	pathPart := strings.TrimPrefix(path, "/")
	reqURL := base
	if pathPart != "" {
		reqURL = base + "/" + pathPart
	}
	var jsonBody []byte
	if len(payload) > 0 {
		var jErr error
		jsonBody, jErr = json.Marshal(payload)
		if jErr != nil {
			return nil, fmt.Errorf("failed to marshal request body: %v", jErr)
		}
	}
	// Sign the exact body bytes so provider's VerifyHMACSignatureBytes accepts the request
	var signature string
	if len(jsonBody) > 0 {
		signature = tokenUtils.SignRequestBody(jsonBody, string(decryptedSecret))
	} else {
		signature = tokenUtils.SignRequestBody([]byte{}, string(decryptedSecret))
	}
	var bodyReader io.Reader
	if len(jsonBody) > 0 {
		bodyReader = bytes.NewReader(jsonBody)
	}
	req, reqErr := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if reqErr != nil {
		return nil, fmt.Errorf("failed to create request: %v", reqErr)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Signature", signature)

	resp, reqErr := GetHTTPClient().Do(req)
	if reqErr != nil {
		return nil, fmt.Errorf("failed to make HTTP request: %v", reqErr)
	}
	defer func() { _ = resp.Body.Close() }()

	// Parse JSON response
	data, err := ParseJSONResponse(resp)
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

// GetTokenRateFromQueue is deprecated: Redis provision-bucket queues were removed. Callers should use marketRate / ValidateRate instead.
func GetTokenRateFromQueue(_ string, _ decimal.Decimal, _ string, marketRate decimal.Decimal, _ RateSide) (decimal.Decimal, error) {
	return marketRate, nil
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

// RateSide represents the direction of the rate (buy for onramp, sell for offramp)
type RateSide string

const (
	RateSideBuy  RateSide = "buy"  // Onramp: fiat per 1 token the sender pays to buy crypto
	RateSideSell RateSide = "sell" // Offramp: fiat per 1 token the sender receives when selling crypto
)

// RateValidationResult contains the result of rate validation
type RateValidationResult struct {
	Rate       decimal.Decimal
	ProviderID string
	OrderType  paymentorder.OrderType
}

// ValidateRate validates if a provided rate is achievable for the given parameters
// Returns the rate, provider ID (if found), and order type (regular or OTC)
// side parameter determines whether to use buy rates (onramp) or sell rates (offramp)
func ValidateRate(ctx context.Context, token *ent.Token, currency *ent.FiatCurrency, amount decimal.Decimal, providerID, networkFilter string, side RateSide) (RateValidationResult, error) {
	isDirectMatch := strings.EqualFold(token.BaseCurrency, currency.Code)

	// Determine which validation function to use
	var result RateValidationResult
	var err error
	if providerID != "" {
		result, err = validateProviderRate(ctx, token, currency, amount, providerID, networkFilter, side)
	} else {
		result, err = validatePublicQuoteRate(ctx, token, currency, amount, networkFilter, side)
	}

	if err != nil {
		return RateValidationResult{}, err
	}

	// For direct currency matches, rate is always 1:1
	// We explicitly return 1.0 here for clarity and to ensure consistency
	if isDirectMatch {
		result.Rate = decimal.NewFromInt(1)
	}

	return result, nil
}

// validateProviderRate handles provider-specific rate validation
func validateProviderRate(ctx context.Context, token *ent.Token, currency *ent.FiatCurrency, amount decimal.Decimal, providerID, networkFilter string, side RateSide) (RateValidationResult, error) {
	// Get the provider from the database
	provider, err := storage.Client.ProviderProfile.
		Query().
		Where(providerprofile.IDEQ(providerID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return RateValidationResult{}, fmt.Errorf("provider not found: %s", providerID)
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

	// Rate from DB (fixed or floating vs live fiat market); quotes do not use Redis bucket queues.
	var rateResponse decimal.Decimal
	switch side {
	case RateSideBuy:
		if !providerOrderToken.FixedBuyRate.IsZero() {
			rateResponse = providerOrderToken.FixedBuyRate
		} else if !providerOrderToken.FloatingBuyDelta.IsZero() && !currency.MarketBuyRate.IsZero() {
			rateResponse = currency.MarketBuyRate.Add(providerOrderToken.FloatingBuyDelta).RoundBank(2)
		}
	case RateSideSell:
		if !providerOrderToken.FixedSellRate.IsZero() {
			rateResponse = providerOrderToken.FixedSellRate
		} else if !providerOrderToken.FloatingSellDelta.IsZero() && !currency.MarketSellRate.IsZero() {
			rateResponse = currency.MarketSellRate.Add(providerOrderToken.FloatingSellDelta).RoundBank(2)
		}
	}

	if rateResponse.IsZero() {
		return RateValidationResult{}, fmt.Errorf("provider rate not configured for this token/currency/side (set fixed or floating rate)")
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

	// Onramp (buy): check provider has sufficient token balance. Offramp (sell): check fiat balance.
	if side == RateSideBuy {
		_, err = storage.Client.ProviderBalances.Query().
			Where(
				providerbalances.HasProviderWith(providerprofile.IDEQ(provider.ID)),
				providerbalances.HasTokenWith(tokenEnt.IDEQ(token.ID)),
				providerbalances.AvailableBalanceGT(amount),
				providerbalances.IsAvailableEQ(true),
			).
			Only(ctx)
	} else {
		_, err = storage.Client.ProviderBalances.Query().
			Where(
				providerbalances.HasProviderWith(providerprofile.IDEQ(provider.ID)),
				providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currency.Code)),
				providerbalances.AvailableBalanceGT(amount.Mul(rateResponse)),
				providerbalances.IsAvailableEQ(true),
			).
			Only(ctx)
	}
	if err != nil {
		if ent.IsNotFound(err) {
			if side == RateSideBuy {
				return RateValidationResult{}, fmt.Errorf("provider has insufficient %s balance", token.Symbol)
			}
			return RateValidationResult{}, fmt.Errorf("provider has insufficient liquidity for %s", currency.Code)
		}
		return RateValidationResult{}, fmt.Errorf("internal server error")
	}

	// Regular orders: reject if provider is at or over stuck fulfillment threshold
	if orderType == paymentorder.OrderTypeRegular {
		orderConf := config.OrderConfig()
		if orderConf.ProviderStuckFulfillmentThreshold > 0 {
			stuckCount, errStuck := GetProviderStuckOrderCount(ctx, providerID)
			if errStuck == nil && stuckCount >= orderConf.ProviderStuckFulfillmentThreshold {
				return RateValidationResult{}, &types.ErrNoProviderDueToStuck{CurrencyCode: currency.Code}
			}
		}
	}

	return RateValidationResult{
		Rate:       rateResponse,
		ProviderID: providerID,
		OrderType:  orderType,
	}, nil
}

// quoteRecentVolumeWindow matches assignment fairness (24h successful fiat volume; hardcoded).
const quoteRecentVolumeWindow = 24 * time.Hour

// RecentFiatVolumeByProvider returns per-provider SUM(amount*rate) for validated/settled orders
// with updated_at >= since. Uses the ent client so it works with any dialect (Postgres prod, SQLite tests).
// When storage.Client is nil, returns zero volume for each id (no error).
func RecentFiatVolumeByProvider(ctx context.Context, since time.Time, providerIDs []string) (map[string]decimal.Decimal, error) {
	out := make(map[string]decimal.Decimal)
	for _, pid := range providerIDs {
		out[pid] = decimal.Zero
	}
	if len(providerIDs) == 0 || storage.Client == nil {
		return out, nil
	}
	for _, pid := range providerIDs {
		rows, err := storage.Client.PaymentOrder.Query().
			Where(
				paymentorder.HasProviderWith(providerprofile.IDEQ(pid)),
				paymentorder.StatusIn(paymentorder.StatusValidated, paymentorder.StatusSettled),
				paymentorder.UpdatedAtGTE(since),
			).
			Select(paymentorder.FieldAmount, paymentorder.FieldRate).
			All(ctx)
		if err != nil {
			return nil, err
		}
		var sum decimal.Decimal
		for _, po := range rows {
			sum = sum.Add(po.Amount.Mul(po.Rate))
		}
		out[pid] = sum
	}
	return out, nil
}

func quoteRecentFiatVolumeByProvider(ctx context.Context, providerIDs []string) (map[string]decimal.Decimal, error) {
	since := time.Now().Add(-quoteRecentVolumeWindow)
	return RecentFiatVolumeByProvider(ctx, since, providerIDs)
}

func quoteRateForPublicCandidate(pot *ent.ProviderOrderToken, side RateSide, currency *ent.FiatCurrency) decimal.Decimal {
	switch side {
	case RateSideBuy:
		if !pot.FixedBuyRate.IsZero() {
			return pot.FixedBuyRate
		}
		if !currency.MarketBuyRate.IsZero() {
			return currency.MarketBuyRate.Add(pot.FloatingBuyDelta).RoundBank(2)
		}
	case RateSideSell:
		if !pot.FixedSellRate.IsZero() {
			return pot.FixedSellRate
		}
		if !currency.MarketSellRate.IsZero() {
			return currency.MarketSellRate.Add(pot.FloatingSellDelta).RoundBank(2)
		}
	}
	return decimal.Zero
}

func amountInRangeForPublicQuote(pot *ent.ProviderOrderToken, amount decimal.Decimal, isOTC bool) bool {
	if isOTC {
		return !amount.LessThan(pot.MinOrderAmountOtc) && !amount.GreaterThan(pot.MaxOrderAmountOtc)
	}
	if amount.GreaterThan(pot.MaxOrderAmount) {
		if pot.MinOrderAmountOtc.IsZero() || pot.MaxOrderAmountOtc.IsZero() {
			return false
		}
		return !amount.LessThan(pot.MinOrderAmountOtc) && !amount.GreaterThan(pot.MaxOrderAmountOtc)
	}
	return !amount.LessThan(pot.MinOrderAmount) && !amount.GreaterThan(pot.MaxOrderAmount)
}

func tryFallbackPublicQuote(ctx context.Context, token *ent.Token, currency *ent.FiatCurrency, amount decimal.Decimal, networkIdentifier string, side RateSide, bestRate decimal.Decimal, anySkippedDueToStuck bool, currencyForStuck string) (RateValidationResult, error) {
	if fallbackID := config.OrderConfig().FallbackProviderID; fallbackID != "" {
		fallbackResult, fallbackErr := validateProviderRate(ctx, token, currency, amount, fallbackID, networkIdentifier, side)
		if fallbackErr == nil {
			if bestRate.GreaterThan(decimal.Zero) {
				return RateValidationResult{
					Rate:       bestRate,
					ProviderID: fallbackResult.ProviderID,
					OrderType:  fallbackResult.OrderType,
				}, nil
			}
			return fallbackResult, nil
		}
		var errStuck *types.ErrNoProviderDueToStuck
		if errors.As(fallbackErr, &errStuck) {
			return RateValidationResult{}, fallbackErr
		}
	}
	if anySkippedDueToStuck && currencyForStuck != "" {
		return RateValidationResult{}, &types.ErrNoProviderDueToStuck{CurrencyCode: currencyForStuck}
	}
	logger.WithFields(logger.Fields{
		"Token":         token.Symbol,
		"Currency":      currency.Code,
		"Amount":        amount,
		"NetworkFilter": networkIdentifier,
		"BestRate":      bestRate,
	}).Warnf("ValidateRate.NoSuitableProvider: no provider found for the given parameters")
	networkMsg := networkIdentifier
	if networkMsg == "" {
		networkMsg = "any network"
	}
	from, to := token.Symbol, currency.Code
	if side == RateSideBuy {
		from, to = currency.Code, token.Symbol
	}
	return RateValidationResult{}, fmt.Errorf("no provider available for %s to %s conversion with amount %s on %s",
		from, to, amount, networkMsg)
}

// validatePublicQuoteRate walks public ProviderOrderToken rows using DB ordering for quotes:
// score DESC, recent 24h successful fiat volume ASC, id ASC (no last_order_assigned — stable vs assignment rotation).
func validatePublicQuoteRate(ctx context.Context, token *ent.Token, currency *ent.FiatCurrency, amount decimal.Decimal, networkIdentifier string, side RateSide) (RateValidationResult, error) {
	orderConf := config.OrderConfig()
	q := storage.Client.ProviderOrderToken.Query().
		Where(
			providerordertoken.HasCurrencyWith(fiatcurrency.IDEQ(currency.ID)),
			providerordertoken.HasTokenWith(tokenEnt.IDEQ(token.ID)),
			providerordertoken.SettlementAddressNEQ(""),
			providerordertoken.HasProviderWith(
				providerprofile.IsActive(true),
				providerprofile.VisibilityModeEQ(providerprofile.VisibilityModePublic),
			),
		)
	if networkIdentifier != "" {
		q = q.Where(providerordertoken.NetworkEQ(networkIdentifier))
	}
	if orderConf.FallbackProviderID != "" {
		q = q.Where(providerordertoken.HasProviderWith(providerprofile.IDNEQ(orderConf.FallbackProviderID)))
	}
	pots, err := q.WithProvider().All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": err.Error()}).Errorf("ValidateRate: candidate query failed")
		return RateValidationResult{}, fmt.Errorf("internal server error")
	}
	if len(pots) == 0 {
		return tryFallbackPublicQuote(ctx, token, currency, amount, networkIdentifier, side, decimal.Zero, false, "")
	}

	provSeen := make(map[string]struct{})
	var provIDs []string
	for _, pot := range pots {
		pid := pot.Edges.Provider.ID
		if _, ok := provSeen[pid]; ok {
			continue
		}
		provSeen[pid] = struct{}{}
		provIDs = append(provIDs, pid)
	}
	volMap, volErr := quoteRecentFiatVolumeByProvider(ctx, provIDs)
	if volErr != nil {
		logger.WithFields(logger.Fields{"Error": volErr.Error()}).Warnf("ValidateRate: recent volume query failed; using zero volume")
		volMap = map[string]decimal.Decimal{}
	}
	slices.SortStableFunc(pots, func(a, b *ent.ProviderOrderToken) int {
		if c := b.Score.Cmp(a.Score); c != 0 {
			return c
		}
		va := volMap[a.Edges.Provider.ID]
		vb := volMap[b.Edges.Provider.ID]
		if c := va.Cmp(vb); c != 0 {
			return c
		}
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})

	var bestRate decimal.Decimal
	var consideredStuck, skippedStuck int

	for _, pot := range pots {
		ot := DetermineOrderType(pot, amount)
		isOTC := ot == paymentorder.OrderTypeOtc
		if !amountInRangeForPublicQuote(pot, amount, isOTC) {
			continue
		}
		if amount.LessThan(pot.MinOrderAmount) {
			continue
		}
		rate := quoteRateForPublicCandidate(pot, side, currency)
		if rate.IsZero() {
			continue
		}
		if rate.GreaterThan(bestRate) {
			bestRate = rate
		}
		pid := pot.Edges.Provider.ID
		var balErr error
		if side == RateSideBuy {
			_, balErr = storage.Client.ProviderBalances.Query().
				Where(
					providerbalances.HasProviderWith(providerprofile.IDEQ(pid)),
					providerbalances.HasTokenWith(tokenEnt.IDEQ(token.ID)),
					providerbalances.AvailableBalanceGT(amount),
					providerbalances.IsAvailableEQ(true),
				).
				Only(ctx)
		} else {
			fiatAmt := amount.Mul(rate)
			_, balErr = storage.Client.ProviderBalances.Query().
				Where(
					providerbalances.HasProviderWith(providerprofile.IDEQ(pid)),
					providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currency.Code)),
					providerbalances.AvailableBalanceGT(fiatAmt),
					providerbalances.IsAvailableEQ(true),
				).
				Only(ctx)
		}
		if balErr != nil {
			if ent.IsNotFound(balErr) {
				continue
			}
			return RateValidationResult{}, fmt.Errorf("internal server error")
		}
		if ot == paymentorder.OrderTypeRegular && orderConf.ProviderStuckFulfillmentThreshold > 0 {
			consideredStuck++
			stuckCount, errStuck := GetProviderStuckOrderCount(ctx, pid)
			if errStuck == nil && stuckCount >= orderConf.ProviderStuckFulfillmentThreshold {
				skippedStuck++
				continue
			}
		}
		return RateValidationResult{Rate: rate, ProviderID: pid, OrderType: ot}, nil
	}

	anySkippedDueToStuck := consideredStuck > 0 && skippedStuck == consideredStuck
	currencyForStuck := ""
	if anySkippedDueToStuck {
		currencyForStuck = currency.Code
	}
	return tryFallbackPublicQuote(ctx, token, currency, amount, networkIdentifier, side, bestRate, anySkippedDueToStuck, currencyForStuck)
}

// GetProviderStuckOrderCount returns the number of stuck orders for a provider (status=fulfilled, pending fulfillment, updated_at <= now - OrderRefundTimeout, regular only).
// Used by both services/priority_queue and rate validation in this package.
func GetProviderStuckOrderCount(ctx context.Context, providerID string) (int, error) {
	orderConf := config.OrderConfig()
	if orderConf.ProviderStuckFulfillmentThreshold <= 0 {
		return 0, nil
	}
	cutoff := time.Now().Add(-orderConf.OrderRefundTimeout)
	count, err := storage.Client.PaymentOrder.Query().
		Where(
			paymentorder.StatusEQ(paymentorder.StatusFulfilled),
			paymentorder.OrderTypeEQ(paymentorder.OrderTypeRegular),
			paymentorder.UpdatedAtLTE(cutoff),
			paymentorder.HasProviderWith(providerprofile.IDEQ(providerID)),
			paymentorder.HasFulfillmentsWith(
				paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusPending),
			),
		).
		Count(ctx)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// NormalizeMobileMoneyAccountIdentifier ensures the account identifier has a country dial code
// and no leading '+'. Used for mobile money institutions so providers receive e.g. "256701234567".
// TODO: add dial_code to fiat_currency DB schema and use it here instead of switch.
func NormalizeMobileMoneyAccountIdentifier(currencyCode, accountIdentifier string) string {
	digits := strings.TrimPrefix(accountIdentifier, "+")
	digits = strings.TrimSpace(digits)
	if digits == "" {
		return accountIdentifier
	}
	digitOnly := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, digits)
	if digitOnly == "" {
		return ""
	}
	var dialCode string
	switch strings.ToUpper(currencyCode) {
	case "UGX":
		dialCode = "256"
	case "TZS":
		dialCode = "255"
	case "KES":
		dialCode = "254"
	case "GHS":
		dialCode = "233"
	case "MWK":
		dialCode = "265"
	default:
		return digitOnly
	}
	if strings.HasPrefix(digitOnly, dialCode) {
		return digitOnly // already has dial code; return cleaned digits
	}
	// Strip domestic trunk prefix (leading 0) before adding country code
	if len(digitOnly) > 1 && digitOnly[0] == '0' {
		digitOnly = digitOnly[1:]
	}
	return dialCode + digitOnly
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
			providerprofile.HasProviderBalancesWith(
				providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(institution.Edges.FiatCurrency.Code)),
				providerbalances.IsAvailableEQ(true),
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

	// Overall deadline so we don't exceed typical client/LB timeout (e.g. 60s)
	ctx, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()

	// Try each provider until one succeeds (10s per provider so we can try several within the overall deadline)
	for _, provider := range providers {
		providerCtx, providerCancel := context.WithTimeout(ctx, 10*time.Second)
		data, err := CallProviderWithHMAC(providerCtx, provider.ID, "POST", "/verify_account", payload)
		providerCancel()
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
