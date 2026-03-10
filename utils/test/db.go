package test

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/paymentorderfulfillment"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/senderordertoken"
	"github.com/paycrest/aggregator/ent/senderprofile"
	"github.com/paycrest/aggregator/ent/token"
	db "github.com/paycrest/aggregator/storage"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
)

// CreateTestUser creates a test user with default or custom values
func CreateTestUser(overrides map[string]interface{}) (*ent.User, error) {

	// Default payload
	payload := map[string]interface{}{
		"firstName":       "John",
		"lastName":        "Doe",
		"email":           "johndoe@test.com",
		"password":        "password",
		"scope":           "sender",
		"isEmailVerified": false,
	}

	// Apply overrides
	for key, value := range overrides {
		payload[key] = value
	}

	// Create user
	user, err := db.Client.User.
		Create().
		SetFirstName(payload["firstName"].(string)).
		SetLastName(payload["lastName"].(string)).
		SetEmail(strings.ToLower(payload["email"].(string))).
		SetPassword(payload["password"].(string)).
		SetScope(payload["scope"].(string)).
		SetIsEmailVerified(payload["isEmailVerified"].(bool)).
		Save(context.Background())

	return user, err
}

// CreateERC20Token creates a test token with default or custom values
func CreateERC20Token(overrides map[string]interface{}) (*ent.Token, error) {

	// Default payload
	payload := map[string]interface{}{
		"symbol":     "TST",
		"decimals":   6,
		"networkRPC": "ws://localhost:8545",
		"is_enabled": true,
		"identifier": "localhost",
		"chainID":    int64(1337),
	}

	// Apply overrides
	for key, value := range overrides {
		payload[key] = value
	}

	// Use a fixed test contract address
	contractAddress := "0xd4E96eF8eee8678dBFf4d535E033Ed1a4F7605b7"

	// Create Network
	networkId, err := db.Client.Network.
		Create().
		SetIdentifier(payload["identifier"].(string)).
		SetChainID(payload["chainID"].(int64)).
		SetRPCEndpoint(payload["networkRPC"].(string)).
		SetBlockTime(decimal.NewFromFloat(3.0)).
		SetFee(decimal.NewFromFloat(0.1)).
		SetIsTestnet(true).
		OnConflict().
		UpdateNewValues().
		ID(context.Background())

	if err != nil {
		return nil, fmt.Errorf("CreateERC20Token.networkId: %w", err)
	}
	// Create token
	tokenId := db.Client.Token.
		Create().
		SetSymbol(payload["symbol"].(string)).
		SetContractAddress(contractAddress).
		SetDecimals(int8(payload["decimals"].(int))).
		SetNetworkID(networkId).
		SetIsEnabled(payload["is_enabled"].(bool)).
		OnConflict().
		// Use the new values that were set on create.
		UpdateNewValues().
		IDX(context.Background())

	token, err := db.Client.Token.
		Query().
		Where(token.IDEQ(tokenId)).
		WithNetwork().
		Only(context.Background())

	return token, err
}

// CreateTRC20Token creates a test token with default or custom values
func CreateTRC20Token(overrides map[string]interface{}) (*ent.Token, error) {

	// Default payload
	payload := map[string]interface{}{
		"symbol":     "TRON_ST",
		"decimals":   6,
		"networkRPC": "ws://localhost:8544",
		"is_enabled": true,
		"identifier": "tron",
		"chainID":    int64(13378),
	}

	contractAddress := "TFRKiHrHCeSyWL67CEwydFvUMYJ6CbYYX6"

	// Apply overrides
	for key, value := range overrides {
		payload[key] = value
	}

	// Create Network
	networkId, err := db.Client.Network.
		Create().
		SetIdentifier(payload["identifier"].(string)).
		SetChainID(payload["chainID"].(int64)).
		SetRPCEndpoint(payload["networkRPC"].(string)).
		SetBlockTime(decimal.NewFromFloat(3.0)).
		SetFee(decimal.NewFromFloat(0.1)).
		SetIsTestnet(true).
		OnConflict().
		UpdateNewValues().
		ID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("CreateTRC20Token.networkId: %w", err)
	}

	// Create token
	tokenId := db.Client.Token.
		Create().
		SetSymbol(payload["symbol"].(string)).
		SetContractAddress(contractAddress).
		SetDecimals(int8(payload["decimals"].(int))).
		SetNetworkID(networkId).
		SetIsEnabled(payload["is_enabled"].(bool)).
		OnConflict().
		UpdateNewValues().
		IDX(context.Background())

	token, err := db.Client.Token.
		Query().
		Where(token.IDEQ(tokenId)).
		WithNetwork().
		Only(context.Background())

	return token, err
}

// CreateTestPaymentOrder creates a test PaymentOrder with default or custom values
// Can create a sender order (when "sender" is provided), provider order (when "provider" is provided), or both
// If both are provided, the order will have both sender_profile and provider edges set
// If token is provided as a parameter, it will be used; otherwise a test token will be created (or fetched from token_id for provider orders)
func CreateTestPaymentOrder(token *ent.Token, overrides map[string]interface{}) (*ent.PaymentOrder, error) {
	// Determine if this is a sender or provider order
	hasSender := overrides["sender"] != nil
	hasProvider := overrides["provider"] != nil

	// Default payload
	payload := map[string]interface{}{
		"amount":             100.50,
		"amount_in_usd":      100.50,
		"rate":               750.0,
		"status":             "pending",
		"institution":        "ABNGNGLA",
		"account_identifier": "1234567890",
		"account_name":       "Test Account",
		"memo":               "Shola Kehinde - rent for May 2021",
	}

	// Provider-specific defaults
	if hasProvider {
		payload["gateway_id"] = "order-123"
		payload["protocol_fee"] = 5.0
		payload["block_number"] = 12345
		payload["updatedAt"] = time.Now()
		payload["cancellation_reasons"] = []string{}
		payload["token_id"] = 0
	}

	// Sender-specific defaults
	if hasSender {
		payload["fee_percent"] = 0.0
		payload["fee_address"] = "0x1234567890123456789012345678901234567890"
		payload["return_address"] = "0x0987654321098765432109876543210987654321"
	}

	// Apply overrides
	for key, value := range overrides {
		payload[key] = value
	}

	// Handle token
	var tokenToUse *ent.Token
	var err error
	if token != nil {
		tokenToUse = token
	} else if hasProvider {
		// For provider orders, check if token_id is in overrides
		if tokenID, ok := payload["token_id"]; ok && tokenID != nil {
			if tokenIDInt, ok := tokenID.(int); ok && tokenIDInt != 0 {
				// Fetch existing token
				tokenToUse, err = db.Client.Token.Get(context.Background(), tokenIDInt)
				if err != nil {
					return nil, fmt.Errorf("failed to fetch token: %w", err)
				}
			} else {
				// Create test token for provider orders if token_id is 0 or not set
				createdToken, err := CreateERC20Token(map[string]interface{}{})
				if err != nil {
					return nil, err
				}
				tokenToUse = createdToken
			}
		} else {
			// Create test token for provider orders if token_id not in overrides
			createdToken, err := CreateERC20Token(map[string]interface{}{})
			if err != nil {
				return nil, err
			}
			tokenToUse = createdToken
		}
	} else {
		return nil, fmt.Errorf("token must be provided for sender orders")
	}

	// Generate receive address and salt for sender orders
	var address string
	var salt []byte
	var expiry time.Time
	if hasSender {
		// Generate 20 random bytes for address (40 hex chars)
		addressBytes := make([]byte, 20)
		if _, err := rand.Read(addressBytes); err != nil {
			return nil, fmt.Errorf("failed to generate random address: %w", err)
		}
		address = "0x" + hex.EncodeToString(addressBytes)

		// Generate random salt (32 bytes)
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("failed to generate random salt: %w", err)
		}

		expiry = time.Now().Add(time.Millisecond * 5)
		time.Sleep(time.Second)
	}

	// Build the order (wallet_type is derived from token -> network.wallet_service)
	orderBuilder := db.Client.PaymentOrder.
		Create().
		SetAmount(decimal.NewFromFloat(payload["amount"].(float64))).
		SetAmountInUsd(decimal.NewFromFloat(payload["amount_in_usd"].(float64))).
		SetRate(decimal.NewFromFloat(payload["rate"].(float64))).
		SetStatus(paymentorder.Status(payload["status"].(string))).
		SetInstitution(payload["institution"].(string)).
		SetAccountIdentifier(payload["account_identifier"].(string)).
		SetAccountName(payload["account_name"].(string)).
		SetToken(tokenToUse)

	// Set sender-specific fields
	if hasSender {
		senderProfile := overrides["sender"].(*ent.SenderProfile)
		orderBuilder = orderBuilder.
			SetSenderProfile(senderProfile).
			SetAmountPaid(decimal.NewFromInt(0)).
			SetAmountReturned(decimal.NewFromInt(0)).
			SetPercentSettled(decimal.NewFromInt(0)).
			SetNetworkFee(tokenToUse.Edges.Network.Fee).
			SetSenderFee(decimal.NewFromFloat(payload["fee_percent"].(float64)).Mul(decimal.NewFromFloat(payload["amount"].(float64))).Div(decimal.NewFromFloat(payload["rate"].(float64))).Round(int32(tokenToUse.Decimals))).
			SetReceiveAddress(address).
			SetReceiveAddressSalt(salt).
			SetReceiveAddressExpiry(expiry).
			SetFeePercent(decimal.NewFromFloat(payload["fee_percent"].(float64))).
			SetFeeAddress(payload["fee_address"].(string)).
			SetReturnAddress(payload["return_address"].(string)).
			SetMemo(payload["memo"].(string))
	}

	// Set provider-specific fields
	if hasProvider {
		providerProfile, _ := overrides["provider"].(*ent.ProviderProfile)
		orderBuilder = orderBuilder.
			SetGatewayID(payload["gateway_id"].(string)).
			SetProtocolFee(decimal.NewFromFloat(payload["protocol_fee"].(float64))).
			SetOrderPercent(decimal.NewFromFloat(100.0)).
			SetBlockNumber(int64(payload["block_number"].(int))).
			SetProvider(providerProfile).
			SetUpdatedAt(payload["updatedAt"].(time.Time)).
			SetCancellationReasons(payload["cancellation_reasons"].([]string))
		if payload["memo"] != nil {
			orderBuilder = orderBuilder.SetMemo(payload["memo"].(string))
		}
	}

	order, err := orderBuilder.Save(context.Background())
	if err != nil {
		return nil, err
	}

	return order, err
}

// CreateTestPaymentOrderFulfillment creates a test PaymentOrderFulfillment with defaults or custom values
func CreateTestPaymentOrderFulfillment(overrides map[string]interface{}) (*ent.PaymentOrderFulfillment, error) {

	// Default payload
	payload := map[string]interface{}{
		"tx_id":             "0x123...",
		"validation_status": "pending",
		"validation_errors": []string{},
		"orderId":           nil,
	}

	// Apply overrides
	for key, value := range overrides {
		payload[key] = value
	}

	// Create payment order if not provided
	if payload["orderId"] == nil {
		// Create a provider order by default for fulfillments
		token, _ := CreateERC20Token(map[string]interface{}{})
		order, _ := CreateTestPaymentOrder(token, map[string]interface{}{"provider": nil})
		payload["orderId"] = order.ID.String()
	}

	// Create PaymentOrderFulfillment
	fulfillment, err := db.Client.PaymentOrderFulfillment.
		Create().
		SetTxID(payload["tx_id"].(string)).
		SetOrderID(payload["orderId"].(uuid.UUID)).
		SetValidationStatus(paymentorderfulfillment.ValidationStatus(payload["validation_status"].(string))).
		Save(context.Background())

	return fulfillment, err
}

// CreateTestSenderProfile creates a test SenderProfile with defaults or custom values
func CreateTestSenderProfile(overrides map[string]interface{}) (*ent.SenderProfile, error) {

	// Default payload
	payload := map[string]interface{}{
		"fee_percent":      "0.0",
		"webhook_url":      "https://example.com/hook",
		"domain_whitelist": []string{"example.com"},
		"fee_address":      "0x1234567890123456789012345678901234567890",
		"refund_address":   "0x0987654321098765432109876543210987654321",
		"user_id":          nil,
		"token":            "TST",
	}

	// Apply overrides
	for key, value := range overrides {
		payload[key] = value
	}

	_token, err := db.Client.Token.
		Query().
		Where(
			token.SymbolEQ(payload["token"].(string)),
		).
		Only(context.Background())
	if err != nil {
		return nil, err
	}

	feePercent, _ := decimal.NewFromString(payload["fee_percent"].(string))

	// Create SenderProfile
	profile, err := db.Client.SenderProfile.
		Create().
		SetWebhookURL(payload["webhook_url"].(string)).
		SetDomainWhitelist(payload["domain_whitelist"].([]string)).
		SetUserID(payload["user_id"].(uuid.UUID)).
		Save(context.Background())
	if err != nil {
		return nil, err
	}

	_, err = db.Client.SenderOrderToken.
		Query().
		Where(
			senderordertoken.And(
				senderordertoken.HasTokenWith(token.IDEQ(_token.ID)),
				senderordertoken.HasSenderWith(senderprofile.IDEQ(profile.ID)),
			),
		).Only(context.Background())
	if err != nil {
		if ent.IsNotFound(err) {
			_, err := db.Client.SenderOrderToken.
				Create().
				SetSenderID(profile.ID).
				SetTokenID(_token.ID).
				SetRefundAddress(payload["refund_address"].(string)).
				SetFeePercent(feePercent).
				SetMaxFeeCap(decimal.Zero). // Default to zero (no cap)
				SetFeeAddress(payload["fee_address"].(string)).
				Save(context.Background())
			if err != nil {
				return nil, fmt.Errorf("CreateTestSenderProfile: %w", err)
			}
			return profile, nil
		} else {
			return nil, fmt.Errorf("CreateTestSenderProfile: %w", err)
		}
	}
	return profile, err
}

// CreateTestProviderProfile creates a test ProviderProfile with defaults or custom values
func CreateTestProviderProfile(overrides map[string]interface{}) (*ent.ProviderProfile, error) {

	// Default payload
	payload := map[string]interface{}{
		"user_id":         uuid.New(),
		"trading_name":    "Elon Musk Trading Co.",
		"currency_id":     uuid.New(),
		"host_identifier": "https://example.com",
		"provision_mode":  "auto",
		"is_partner":      false,
		"visibility_mode": "public",
		"is_available":    true,
	}

	// Apply overrides
	for key, value := range overrides {
		payload[key] = value
	}

	// Create ProviderProfile
	profile, err := db.Client.ProviderProfile.
		Create().
		SetTradingName(payload["trading_name"].(string)).
		SetHostIdentifier(payload["host_identifier"].(string)).
		SetProvisionMode(providerprofile.ProvisionMode(payload["provision_mode"].(string))).
		SetUserID(payload["user_id"].(uuid.UUID)).
		SetVisibilityMode(providerprofile.VisibilityMode(payload["visibility_mode"].(string))).
		Save(context.Background())
	if err != nil {
		return nil, err
	}

	currencyID := payload["currency_id"].(uuid.UUID)
	currency, err := db.Client.FiatCurrency.Get(context.Background(), currencyID)
	if err != nil {
		return nil, err
	}
	_, err = db.Client.ProviderBalances.Create().
		SetFiatCurrency(currency).
		SetAvailableBalance(decimal.Zero).
		SetTotalBalance(decimal.Zero).
		SetReservedBalance(decimal.Zero).
		SetIsAvailable(true).
		SetProviderID(profile.ID).
		Save(context.Background())
	return profile, err
}

func AddProvisionBucketToPaymentOrder(order *ent.PaymentOrder, bucketId int) (*ent.PaymentOrder, error) {
	order, err := order.
		Update().
		SetProvisionBucketID(bucketId).
		Save(context.Background())
	return order, err
}

func AddProviderOrderTokenToProvider(overrides map[string]interface{}) (*ent.ProviderOrderToken, error) {
	// Default payload
	payload := map[string]interface{}{
		"currency_id":              uuid.New(),
		"fixed_conversion_rate":    decimal.NewFromFloat(1.0),
		"conversion_rate_type":     "fixed",
		"floating_conversion_rate": decimal.NewFromFloat(1.0),
		"max_order_amount":         decimal.NewFromFloat(1.0),
		"min_order_amount":         decimal.NewFromFloat(1.0),
		"max_order_amount_otc":     decimal.NewFromFloat(10000.0),
		"min_order_amount_otc":     decimal.NewFromFloat(100.0),
		"provider":                 nil,
		"token_id":                 0,
		"settlement_address":       "0x1234567890123456789012345678901234567890",
		"network":                  "localhost",
	}

	// Apply overrides
	for key, value := range overrides {
		payload[key] = value
	}

	if payload["token_id"].(int) == 0 {
		// Create test token
		token, err := CreateERC20Token(map[string]interface{}{})
		if err != nil {
			return nil, err
		}
		payload["token_id"] = token.ID
	}

	orderToken, err := db.Client.ProviderOrderToken.
		Create().
		SetProvider(payload["provider"].(*ent.ProviderProfile)).
		SetMaxOrderAmount(payload["max_order_amount"].(decimal.Decimal)).
		SetMinOrderAmount(payload["min_order_amount"].(decimal.Decimal)).
		SetMaxOrderAmountOtc(payload["max_order_amount_otc"].(decimal.Decimal)).
		SetMinOrderAmountOtc(payload["min_order_amount_otc"].(decimal.Decimal)).
		SetConversionRateType(providerordertoken.ConversionRateType(payload["conversion_rate_type"].(string))).
		SetFixedConversionRate(payload["fixed_conversion_rate"].(decimal.Decimal)).
		SetFloatingConversionRate(payload["floating_conversion_rate"].(decimal.Decimal)).
		SetSettlementAddress(payload["settlement_address"].(string)).
		SetNetwork(payload["network"].(string)).
		SetTokenID(payload["token_id"].(int)).
		SetCurrencyID(payload["currency_id"].(uuid.UUID)).
		SetRateSlippage(decimal.NewFromFloat(0.1)).
		Save(context.Background())
	if err != nil {
		return nil, err
	}

	orderToken, err = db.Client.ProviderOrderToken.
		Query().
		Where(providerordertoken.IDEQ(orderToken.ID)).
		WithCurrency().
		WithToken().
		WithProvider().
		Only(context.Background())

	return orderToken, err
}

// CreateTestProvisionBucket creates a test ProvisionBucket with defaults or custom values
func CreateTestProvisionBucket(overrides map[string]interface{}) (*ent.ProvisionBucket, error) {
	ctx := context.Background()

	// Default payload
	payload := map[string]interface{}{
		"currency_id": 1,
		"max_amount":  decimal.NewFromFloat(1.0),
		"min_amount":  decimal.NewFromFloat(1.0),
		"provider_id": nil,
	}

	// Apply overrides
	for key, value := range overrides {
		payload[key] = value
	}

	bucket, err := db.Client.ProvisionBucket.Create().
		SetMinAmount(payload["min_amount"].(decimal.Decimal)).
		SetMaxAmount(payload["max_amount"].(decimal.Decimal)).
		SetCurrencyID(payload["currency_id"].(uuid.UUID)).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	_, err = db.Client.ProviderProfile.
		UpdateOneID(payload["provider_id"].(string)).
		AddProvisionBucketIDs(bucket.ID).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	return bucket, nil
}

// CreateTestFiatCurrency creates a test FiatCurrency with defaults or custom values
func CreateTestFiatCurrency(overrides map[string]interface{}) (*ent.FiatCurrency, error) {

	// Default payload.
	payload := map[string]interface{}{
		"code":        "NGN",
		"short_name":  "Naira",
		"decimals":    2,
		"symbol":      "₦",
		"name":        "Nigerian Naira",
		"market_rate": 950.0,
	}
	// Apply overrides.
	for key, value := range overrides {
		payload[key] = value
	}

	var institutions []*ent.Institution
	var err error
	if payload["code"] == "KES" {
		// Use OnConflict to handle race conditions in parallel tests
		_, err = db.Client.Institution.
			Create().
			SetName("M-Pesa").
			SetCode("MPESAKES").
			SetType(institution.TypeMobileMoney).
			OnConflictColumns("code").
			UpdateNewValues().
			ID(context.Background())
		if err != nil {
			return nil, err
		}
		mpesa, err := db.Client.Institution.Query().Where(institution.CodeEQ("MPESAKES")).Only(context.Background())
		if err != nil {
			return nil, err
		}

		_, err = db.Client.Institution.
			Create().
			SetName("Equity Bank").
			SetCode("EQTYKES").
			OnConflictColumns("code").
			UpdateNewValues().
			ID(context.Background())
		if err != nil {
			return nil, err
		}
		equity, err := db.Client.Institution.Query().Where(institution.CodeEQ("EQTYKES")).Only(context.Background())
		if err != nil {
			return nil, err
		}

		institutions = []*ent.Institution{mpesa, equity}
	} else {
		// Use OnConflict to handle race conditions in parallel tests
		_, err = db.Client.Institution.
			Create().
			SetName("MTN Momo").
			SetCode("MOMONGPC").
			SetType(institution.TypeMobileMoney).
			OnConflictColumns("code").
			UpdateNewValues().
			ID(context.Background())
		if err != nil {
			return nil, err
		}
		mtn, err := db.Client.Institution.Query().Where(institution.CodeEQ("MOMONGPC")).Only(context.Background())
		if err != nil {
			return nil, err
		}

		_, err = db.Client.Institution.
			Create().
			SetName("Access Bank").
			SetCode("ABNGNGLA").
			OnConflictColumns("code").
			UpdateNewValues().
			ID(context.Background())
		if err != nil {
			return nil, err
		}
		access, err := db.Client.Institution.Query().Where(institution.CodeEQ("ABNGNGLA")).Only(context.Background())
		if err != nil {
			return nil, err
		}

		institutions = []*ent.Institution{mtn, access}
	}

	// Check if currency already exists
	existingCurrency, err := db.Client.FiatCurrency.
		Query().
		Where(fiatcurrency.CodeEQ(payload["code"].(string))).
		WithInstitutions().
		Only(context.Background())
	if err != nil && !ent.IsNotFound(err) {
		return nil, err
	}
	if err == nil {
		// Currency already exists, return it
		return existingCurrency, nil
	}

	// Currency doesn't exist, create it
	currency, err := db.Client.FiatCurrency.
		Create().
		SetCode(payload["code"].(string)).
		SetShortName(payload["short_name"].(string)).
		SetDecimals(payload["decimals"].(int)).
		SetSymbol(payload["symbol"].(string)).
		SetName(payload["name"].(string)).
		SetMarketRate(decimal.NewFromFloat(payload["market_rate"].(float64))).
		SetIsEnabled(true).
		AddInstitutions(institutions...).
		Save(context.Background())
	return currency, err

}

// Helper function to create test networks and tokens
func CreateTestTokenData(t *testing.T, client *ent.Client) ([]*ent.Network, []*ent.Token) {
	ctx := context.Background()

	// Create test networks
	network1, err := client.Network.Create().
		SetIdentifier("arbitrum-one").
		SetChainID(42161).
		SetRPCEndpoint("https://arb1.arbitrum.io/rpc").
		SetGatewayContractAddress("0x123").
		SetIsTestnet(false).
		SetBlockTime(decimal.NewFromFloat(3.0)).
		SetFee(decimal.NewFromFloat(0.01)).
		Save(ctx)
	assert.NoError(t, err)

	network2, err := client.Network.Create().
		SetIdentifier("polygon").
		SetChainID(137).
		SetRPCEndpoint("https://polygon-rpc.com").
		SetGatewayContractAddress("0x456").
		SetIsTestnet(false).
		SetBlockTime(decimal.NewFromFloat(3.0)).
		SetFee(decimal.NewFromFloat(0.02)).
		Save(ctx)
	assert.NoError(t, err)

	// Create test tokens
	token1, err := client.Token.Create().
		SetSymbol("USDC").
		SetContractAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").
		SetDecimals(6).
		SetBaseCurrency("USD").
		SetIsEnabled(true).
		SetNetwork(network1).
		Save(ctx)
	assert.NoError(t, err)

	token2, err := client.Token.Create().
		SetSymbol("USDT").
		SetContractAddress("0xdAC17F958D2ee523a2206206994597C13D831ec7").
		SetDecimals(6).
		SetBaseCurrency("USD").
		SetIsEnabled(true).
		SetNetwork(network2).
		Save(ctx)
	assert.NoError(t, err)

	// Disabled token (should not appear in results)
	_, err = client.Token.Create().
		SetSymbol("DAI").
		SetContractAddress("0x6B175474E89094C44Da98b954EedeAC495271d0F").
		SetDecimals(18).
		SetBaseCurrency("USD").
		SetIsEnabled(false).
		SetNetwork(network1).
		Save(ctx)
	assert.NoError(t, err)

	return []*ent.Network{network1, network2}, []*ent.Token{token1, token2}
}

// CreateEnvFile creates a new file with Key=Value format.
func CreateEnvFile(filePath string, data map[string]string) (string, error) {
	// Open the file for writing
	file, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Iterate over the map entries and write each key-value pair to the file
	for key, value := range data {
		_, err := writer.WriteString(fmt.Sprintf("%s='%s'\n", key, value))
		if err != nil {
			return "", err
		}
	}

	return filePath, nil
}

func CreateMessageHash(orderRequestData map[string]interface{}) common.Hash {
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(orderRequestData), orderRequestData)
	return crypto.Keccak256Hash([]byte(prefix))
}
