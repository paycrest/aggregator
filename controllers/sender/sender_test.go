package sender

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/enttest"
	"github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
	tokenEnt "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/routers/middleware"
	"github.com/paycrest/aggregator/services"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils/test"
	"github.com/paycrest/aggregator/utils/token"
	"github.com/redis/go-redis/v9"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
)

var testCtx = struct {
	user              *ent.SenderProfile
	token             *ent.Token
	apiKey            *ent.APIKey
	apiKeySecret      string
	client            types.RPCClient
	networkIdentifier string
}{}

func setup() error {
	// Set up test data
	user, err := test.CreateTestUser(nil)
	if err != nil {
		return err
	}

	// Create a test token without blockchain dependency
	testCtx.networkIdentifier = "localhost"

	// Create Network first
	networkId, err := db.Client.Network.
		Create().
		SetIdentifier(testCtx.networkIdentifier).
		SetChainID(int64(56)). // Use BNB Smart Chain to skip webhook creation
		SetRPCEndpoint("ws://localhost:8545").
		SetBlockTime(decimal.NewFromFloat(3.0)).
		SetFee(decimal.NewFromFloat(0.1)).
		SetIsTestnet(true).
		OnConflict().
		UpdateNewValues().
		ID(context.Background())
	if err != nil {
		return fmt.Errorf("CreateNetwork.sender_test: %w", err)
	}

	// Create token directly without blockchain
	tokenId, err := db.Client.Token.
		Create().
		SetSymbol("TST").
		SetContractAddress("0xd4E96eF8eee8678dBFf4d535E033Ed1a4F7605b7").
		SetDecimals(6).
		SetNetworkID(networkId).
		SetIsEnabled(true).
		SetBaseCurrency("NGN"). // Set to NGN to avoid Redis dependency
		OnConflict().
		UpdateNewValues().
		ID(context.Background())
	if err != nil {
		return fmt.Errorf("CreateToken.sender_test: %w", err)
	}

	token, err := db.Client.Token.
		Query().
		Where(tokenEnt.IDEQ(tokenId)).
		WithNetwork().
		Only(context.Background())
	if err != nil {
		return fmt.Errorf("GetToken.sender_test: %w", err)
	}

	// Create test fiat currency and institutions
	currency, err := test.CreateTestFiatCurrency(nil)
	if err != nil {
		return fmt.Errorf("CreateTestFiatCurrency.sender_test: %w", err)
	}

	// Create test provider with NGN currency support
	_, err = test.CreateTestProviderProfile(map[string]interface{}{
		"user_id":     user.ID,
		"currency_id": currency.ID,
		"is_active":   true,
	})
	if err != nil {
		return fmt.Errorf("CreateTestProviderProfile.sender_test: %w", err)
	}

	senderProfile, err := test.CreateTestSenderProfile(map[string]interface{}{
		"user_id":     user.ID,
		"fee_percent": "5",
		"token":       token.Symbol,
	})

	if err != nil {
		return fmt.Errorf("CreateTestSenderProfile.sender_test: %w", err)
	}
	testCtx.user = senderProfile

	apiKeyService := services.NewAPIKeyService()
	apiKey, secretKey, err := apiKeyService.GenerateAPIKey(
		context.Background(),
		nil,
		senderProfile,
		nil,
	)
	if err != nil {
		return err
	}
	testCtx.apiKey = apiKey

	testCtx.token = token
	testCtx.apiKeySecret = secretKey

	for i := 0; i < 9; i++ {
		time.Sleep(time.Duration(float64(rand.Intn(12))) * time.Second)

		// Create a simple payment order without blockchain dependency
		address := fmt.Sprintf("0x%040d", i) // Simple mock address
		salt := []byte(fmt.Sprintf("salt_%d", i))

		// Create receive address
		receiveAddress, err := db.Client.ReceiveAddress.
			Create().
			SetAddress(address).
			SetSalt(salt).
			SetStatus("unused").
			SetValidUntil(time.Now().Add(time.Millisecond * 5)).
			Save(context.Background())
		if err != nil {
			return err
		}

		// Create payment order
		paymentOrder, err := db.Client.PaymentOrder.
			Create().
			SetSenderProfile(senderProfile).
			SetAmount(decimal.NewFromFloat(100.50)).
			SetAmountPaid(decimal.NewFromInt(0)).
			SetAmountReturned(decimal.NewFromInt(0)).
			SetPercentSettled(decimal.NewFromInt(0)).
			SetNetworkFee(token.Edges.Network.Fee).
			SetSenderFee(decimal.NewFromFloat(0)).
			SetToken(token).
			SetRate(decimal.NewFromFloat(750.0)).
			SetReceiveAddress(receiveAddress).
			SetReceiveAddressText(receiveAddress.Address).
			SetFeePercent(decimal.NewFromFloat(0)).
			SetFeeAddress("0x1234567890123456789012345678901234567890").
			SetReturnAddress("0x0987654321098765432109876543210987654321").
			SetStatus("pending").
			Save(context.Background())
		if err != nil {
			return err
		}

		// Create payment order recipient
		_, err = db.Client.PaymentOrderRecipient.
			Create().
			SetInstitution("MOMONGPC").
			SetAccountIdentifier("1234567890").
			SetAccountName("OK").
			SetProviderID("").
			SetMemo("Test memo").
			SetPaymentOrder(paymentOrder).
			Save(context.Background())
		if err != nil {
			return err
		}
	}

	return nil
}

func TestSender(t *testing.T) {

	// Set up test database client
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	db.Client = client

	// Set up mock Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer redisClient.Close()

	db.RedisClient = redisClient

	// Setup test data
	err := setup()
	assert.NoError(t, err)

	senderTokens, err := client.SenderOrderToken.Query().All(context.Background())
	assert.NoError(t, err)
	assert.Greater(t, len(senderTokens), 0)

	// Set up test routers
	router := gin.New()
	router.Use(middleware.DynamicAuthMiddleware)
	router.Use(middleware.OnlySenderMiddleware)

	// Create a new instance of the SenderController with the mock service
	ctrl := NewSenderController()
	router.POST("/sender/orders", ctrl.InitiatePaymentOrder)
	router.GET("/sender/orders/:id", ctrl.GetPaymentOrderByID)
	router.GET("/sender/orders", ctrl.GetPaymentOrders)
	router.GET("/sender/stats", ctrl.Stats)

	var paymentOrderUUID uuid.UUID

	t.Run("InitiatePaymentOrder", func(t *testing.T) {

		// Fetch network from db
		network, err := db.Client.Network.
			Query().
			Where(network.IdentifierEQ(testCtx.networkIdentifier)).
			Only(context.Background())
		assert.NoError(t, err)

		payload := map[string]interface{}{
			"amount":  "100",
			"token":   testCtx.token.Symbol,
			"rate":    "750",
			"network": network.Identifier,
			"recipient": map[string]interface{}{
				"institution":       "MOMONGPC", // Use mobile money to skip account validation
				"accountIdentifier": "1234567890",
				"accountName":       "John Doe",
				"memo":              "Shola Kehinde - rent for May 2021",
			},
			"reference": "12kjdf-kjn33_REF",
		}

		headers := map[string]string{
			"API-Key": testCtx.apiKey.ID.String(),
		}

		res, err := test.PerformRequest(t, "POST", "/sender/orders", payload, headers, router)
		assert.NoError(t, err)

		// Debug: Print response body if status is not 201
		if res.Code != http.StatusCreated {
			t.Logf("Response Status: %d", res.Code)
			t.Logf("Response Body: %s", res.Body.String())
		}

		// Assert the response body
		assert.Equal(t, http.StatusCreated, res.Code)

		var response types.Response
		err = json.Unmarshal(res.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "Payment order initiated successfully", response.Message)
		data, ok := response.Data.(map[string]interface{})
		assert.True(t, ok, "response.Data is not of type map[string]interface{}")
		assert.NotNil(t, data, "response.Data is nil")

		assert.Equal(t, data["amount"], payload["amount"])
		assert.Equal(t, data["network"], payload["network"])
		assert.Equal(t, data["reference"], payload["reference"])
		assert.NotEmpty(t, data["validUntil"])

		// Parse the payment order ID string to uuid.UUID
		paymentOrderUUID, err = uuid.Parse(data["id"].(string))
		assert.NoError(t, err)

		// Query the database for the payment order
		paymentOrder, err := db.Client.PaymentOrder.
			Query().
			Where(paymentorder.IDEQ(paymentOrderUUID)).
			WithRecipient().
			Only(context.Background())
		assert.NoError(t, err)

		assert.NotNil(t, paymentOrder.Edges.Recipient)
		assert.Equal(t, paymentOrder.Edges.Recipient.AccountIdentifier, payload["recipient"].(map[string]interface{})["accountIdentifier"])
		assert.Equal(t, paymentOrder.Edges.Recipient.Memo, payload["recipient"].(map[string]interface{})["memo"])
		// For mobile money institutions, ValidateAccount returns "OK"
		assert.Equal(t, paymentOrder.Edges.Recipient.AccountName, "OK")
		assert.Equal(t, paymentOrder.Edges.Recipient.Institution, payload["recipient"].(map[string]interface{})["institution"])
		assert.Equal(t, data["senderFee"], "5")
		assert.Equal(t, data["transactionFee"], network.Fee.String())

		t.Run("Check Transaction Logs", func(t *testing.T) {
			headers := map[string]string{
				"API-Key": testCtx.apiKey.ID.String(),
			}

			res, err = test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders/%s?timestamp=%v", paymentOrderUUID.String(), payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			type Response struct {
				Status  string                     `json:"status"`
				Message string                     `json:"message"`
				Data    types.PaymentOrderResponse `json:"data"`
			}

			var response2 Response
			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			err = json.Unmarshal(res.Body.Bytes(), &response2)
			assert.NoError(t, err)
			assert.Equal(t, "The order has been successfully retrieved", response2.Message)
			assert.Equal(t, 1, len(response2.Data.Transactions), "response.Data is nil")
		})

	})

	t.Run("GetPaymentOrderByID", func(t *testing.T) {
		var payload = map[string]interface{}{
			"timestamp": time.Now().Unix(),
		}

		signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

		headers := map[string]string{
			"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
		}

		res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders/%s?timestamp=%v", paymentOrderUUID.String(), payload["timestamp"]), nil, headers, router)
		assert.NoError(t, err)

		// Assert the response body
		assert.Equal(t, http.StatusOK, res.Code)

		var response types.Response
		err = json.Unmarshal(res.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "The order has been successfully retrieved", response.Message)
		data, ok := response.Data.(map[string]interface{})
		assert.True(t, ok, "response.Data is of not type map[string]interface{}")
		assert.NotNil(t, data, "response.Data is nil")
	})

	t.Run("GetPaymentOrders", func(t *testing.T) {
		t.Run("fetch default list", func(t *testing.T) {
			// Test default params
			var payload = map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?timestamp=%v", payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Payment orders retrieved successfully", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is of not type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			assert.Equal(t, int(data["page"].(float64)), 1)
			assert.Equal(t, int(data["pageSize"].(float64)), 10) // default pageSize
			assert.NotEmpty(t, data["total"])
			assert.NotEmpty(t, data["orders"])
		})

		t.Run("when filtering is applied", func(t *testing.T) {
			// Test different status filters
			var payload = map[string]interface{}{
				"status":    "initiated",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?status=%s&timestamp=%v", payload["status"], payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Payment orders retrieved successfully", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is of not type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			assert.Equal(t, int(data["page"].(float64)), 1)
			assert.Equal(t, int(data["pageSize"].(float64)), 10) // default pageSize
			assert.NotEmpty(t, data["total"])
			assert.NotEmpty(t, data["orders"])
		})

		t.Run("with custom page and pageSize", func(t *testing.T) {
			// Test different page and pageSize values
			page := 1
			pageSize := 10
			var payload = map[string]interface{}{
				"page":      strconv.Itoa(page),
				"pageSize":  strconv.Itoa(pageSize),
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?page=%s&pageSize=%s&timestamp=%v", strconv.Itoa(page), strconv.Itoa(pageSize), payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Payment orders retrieved successfully", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is of not type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			assert.Equal(t, int(data["page"].(float64)), page)
			assert.Equal(t, int(data["pageSize"].(float64)), pageSize)
			assert.Equal(t, 10, len(data["orders"].([]interface{})))
			assert.NotEmpty(t, data["total"])
			assert.NotEmpty(t, data["orders"])
		})

		t.Run("with ordering", func(t *testing.T) {
			// Test ascending and descending ordering
			var payload = map[string]interface{}{
				"ordering":  "desc",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?ordering=%s&timestamp=%v", payload["ordering"], payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Payment orders retrieved successfully", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is of not type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			// Try to parse the first and last order time strings using a set of predefined layouts
			firstOrderTimestamp, err := time.Parse(time.RFC3339Nano, data["orders"].([]interface{})[0].(map[string]interface{})["createdAt"].(string))
			if err != nil {
				return
			}

			lastOrderTimestamp, err := time.Parse(time.RFC3339Nano, data["orders"].([]interface{})[len(data["orders"].([]interface{}))-1].(map[string]interface{})["createdAt"].(string))
			if err != nil {
				return
			}

			assert.Equal(t, int(data["page"].(float64)), 1)
			assert.Equal(t, int(data["pageSize"].(float64)), 10) // default pageSize
			assert.NotEmpty(t, data["total"])
			assert.NotEmpty(t, data["orders"])
			assert.Greater(t, len(data["orders"].([]interface{})), 0)
			assert.GreaterOrEqual(t, firstOrderTimestamp, lastOrderTimestamp)
		})

		t.Run("with filtering by network", func(t *testing.T) {
			var payload = map[string]interface{}{
				"network":   testCtx.networkIdentifier,
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?network=%s&timestamp=%v", payload["network"], payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Payment orders retrieved successfully", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is of not type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			assert.NotEmpty(t, data["total"])
			assert.NotEmpty(t, data["orders"])
			assert.Greater(t, len(data["orders"].([]interface{})), 0)

			for _, order := range data["orders"].([]interface{}) {
				assert.Equal(t, order.(map[string]interface{})["network"], payload["network"])
			}
		})

		t.Run("with filtering by token", func(t *testing.T) {
			var payload = map[string]interface{}{
				"token":     testCtx.token.Symbol,
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?token=%s&timestamp=%v", payload["token"], payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Payment orders retrieved successfully", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is of not type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			assert.NotEmpty(t, data["total"])
			assert.NotEmpty(t, data["orders"])
			assert.Greater(t, len(data["orders"].([]interface{})), 0)

			for _, order := range data["orders"].([]interface{}) {
				assert.Equal(t, order.(map[string]interface{})["token"], payload["token"])
			}
		})
	})

	t.Run("GetStats", func(t *testing.T) {
		t.Run("when no orders have been initiated", func(t *testing.T) {
			// Create a new user with no orders
			user, err := test.CreateTestUser(map[string]interface{}{
				"email": "no_order_user@test.com",
			})
			if err != nil {
				return
			}

			senderProfile, err := test.CreateTestSenderProfile(map[string]interface{}{
				"user_id":     user.ID,
				"fee_percent": "5",
			})
			if err != nil {
				return
			}

			apiKeyService := services.NewAPIKeyService()
			apiKey, secretKey, err := apiKeyService.GenerateAPIKey(
				context.Background(),
				nil,
				senderProfile,
				nil,
			)
			if err != nil {
				return
			}

			var payload = map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, secretKey)

			headers := map[string]string{
				"Authorization": "HMAC " + apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/stats?timestamp=%v", payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Sender stats retrieved successfully", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is of not type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			assert.Equal(t, int(data["totalOrders"].(float64)), 0)

			totalOrderVolumeStr, ok := data["totalOrderVolume"].(string)
			assert.True(t, ok, "totalOrderVolume is not of type string")
			totalOrderVolume, err := decimal.NewFromString(totalOrderVolumeStr)
			assert.NoError(t, err, "Failed to convert totalOrderVolume to decimal")
			assert.Equal(t, totalOrderVolume, decimal.NewFromInt(0))

			totalFeeEarningsStr, ok := data["totalFeeEarnings"].(string)
			assert.True(t, ok, "totalFeeEarnings is not of type string")
			totalFeeEarnings, err := decimal.NewFromString(totalFeeEarningsStr)
			assert.NoError(t, err, "Failed to convert totalFeeEarnings to decimal")
			assert.Equal(t, totalFeeEarnings, decimal.NewFromInt(0))
		})

		t.Run("when orders have been initiated", func(t *testing.T) {
			var payload = map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/stats?timestamp=%v", payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Sender stats retrieved successfully", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is of not type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			// Assert the totalOrders value
			totalOrders, ok := data["totalOrders"].(float64)
			assert.True(t, ok, "totalOrders is not of type float64")
			assert.Equal(t, 10, int(totalOrders))

			// Assert the totalOrderVolume value
			totalOrderVolumeStr, ok := data["totalOrderVolume"].(string)
			assert.True(t, ok, "totalOrderVolume is not of type string")
			totalOrderVolume, err := decimal.NewFromString(totalOrderVolumeStr)
			assert.NoError(t, err, "Failed to convert totalOrderVolume to decimal")
			assert.Equal(t, 0, totalOrderVolume.Cmp(decimal.NewFromInt(0)))

			// Assert the totalFeeEarnings value
			totalFeeEarningsStr, ok := data["totalFeeEarnings"].(string)
			assert.True(t, ok, "totalFeeEarnings is not of type string")
			totalFeeEarnings, err := decimal.NewFromString(totalFeeEarningsStr)
			assert.NoError(t, err, "Failed to convert totalFeeEarnings to decimal")
			assert.Equal(t, 0, totalFeeEarnings.Cmp(decimal.NewFromInt(0)))
		})

		t.Run("should only calculate volumes of settled orders", func(t *testing.T) {
			assert.NoError(t, err)

			// create settled Order
			address := "0x0000000000000000000000000000000000000009" // Use address outside the setup loop range
			salt := []byte("salt_settled")

			// Create receive address
			receiveAddress, err := db.Client.ReceiveAddress.
				Create().
				SetAddress(address).
				SetSalt(salt).
				SetStatus("unused").
				SetValidUntil(time.Now().Add(time.Millisecond * 5)).
				Save(context.Background())
			assert.NoError(t, err)

			// Create payment order
			paymentOrder, err := db.Client.PaymentOrder.
				Create().
				SetSenderProfile(testCtx.user).
				SetAmount(decimal.NewFromFloat(100.0)).
				SetAmountPaid(decimal.NewFromInt(0)).
				SetAmountReturned(decimal.NewFromInt(0)).
				SetPercentSettled(decimal.NewFromInt(0)).
				SetNetworkFee(testCtx.token.Edges.Network.Fee).
				SetSenderFee(decimal.NewFromFloat(5.0).Mul(decimal.NewFromFloat(100.0)).Div(decimal.NewFromFloat(750.0)).Round(int32(testCtx.token.Decimals))).
				SetToken(testCtx.token).
				SetRate(decimal.NewFromFloat(750.0)).
				SetReceiveAddress(receiveAddress).
				SetReceiveAddressText(receiveAddress.Address).
				SetFeePercent(decimal.NewFromFloat(5.0)).
				SetFeeAddress("0x1234567890123456789012345678901234567890").
				SetReturnAddress("0x0987654321098765432109876543210987654321").
				SetStatus("settled").
				Save(context.Background())
			assert.NoError(t, err)

			// Create payment order recipient for settled order
			_, err = db.Client.PaymentOrderRecipient.
				Create().
				SetInstitution("MOMONGPC").
				SetAccountIdentifier("1234567890").
				SetAccountName("OK").
				SetProviderID("").
				SetMemo("Test memo").
				SetPaymentOrder(paymentOrder).
				Save(context.Background())
			assert.NoError(t, err)
			assert.NoError(t, err)
			var payload = map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/stats?timestamp=%v", payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Sender stats retrieved successfully", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is of not type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			// Assert the totalOrders value
			totalOrders, ok := data["totalOrders"].(float64)
			assert.True(t, ok, "totalOrders is not of type float64")
			assert.Equal(t, 11, int(totalOrders)) // The settled order is being counted

			// Assert the totalOrderVolume value (100 NGN / 950 market rate ≈ 0.105 USD)
			totalOrderVolumeStr, ok := data["totalOrderVolume"].(string)
			assert.True(t, ok, "totalOrderVolume is not of type string")
			totalOrderVolume, err := decimal.NewFromString(totalOrderVolumeStr)
			assert.NoError(t, err, "Failed to convert totalOrderVolume to decimal")
			expectedVolume := decimal.NewFromFloat(100.0).Div(decimal.NewFromFloat(950.0))
			assert.Equal(t, 0, totalOrderVolume.Cmp(expectedVolume))

			// Assert the totalFeeEarnings value (5% of 100 NGN / 950 market rate ≈ 0.005 USD)
			totalFeeEarningsStr, ok := data["totalFeeEarnings"].(string)
			assert.True(t, ok, "totalFeeEarnings is not of type string")
			totalFeeEarnings, err := decimal.NewFromString(totalFeeEarningsStr)
			assert.NoError(t, err, "Failed to convert totalFeeEarnings to decimal")
			expectedFee := decimal.NewFromFloat(5.0).Mul(decimal.NewFromFloat(100.0)).Div(decimal.NewFromFloat(750.0)).Div(decimal.NewFromFloat(950.0))
			// Use a tolerance for decimal precision differences
			diff := totalFeeEarnings.Sub(expectedFee).Abs()
			tolerance := decimal.NewFromFloat(0.000001)
			assert.True(t, diff.LessThanOrEqual(tolerance), "Fee difference %s exceeds tolerance %s", diff.String(), tolerance.String())
		})
	})

	t.Run("TestDECIMALPrecision", func(t *testing.T) {
		t.Run("High Precision Amounts", func(t *testing.T) {
			highPrecisionAmount := "123456.123456"
			highPrecisionRate := "987654.123456"

			payload := map[string]interface{}{
				"amount":  highPrecisionAmount,
				"token":   testCtx.token.Symbol,
				"rate":    highPrecisionRate,
				"network": testCtx.networkIdentifier,
				"recipient": map[string]interface{}{
					"institution":       "MOMONGPC",
					"accountIdentifier": "PRECISION_TEST_001",
					"accountName":       "Precision Test User",
					"memo":              "Testing DECIMAL(20,8) precision with high precision values",
				},
				"reference": "DECIMAL_PRECISION_TEST_001",
			}

			headers := map[string]string{
				"API-Key": testCtx.apiKey.ID.String(),
			}

			res, err := test.PerformRequest(t, "POST", "/sender/orders", payload, headers, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusCreated, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Payment order initiated successfully", response.Message)

			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is not of type map[string]interface{}")

			paymentOrderUUID, err := uuid.Parse(data["id"].(string))
			assert.NoError(t, err)

			// Query the database to verify DECIMAL precision storage
			paymentOrder, err := db.Client.PaymentOrder.
				Query().
				Where(paymentorder.IDEQ(paymentOrderUUID)).
				Only(context.Background())
			assert.NoError(t, err)

			// Verify the amount is stored with full precision
			expectedAmount, err := decimal.NewFromString(highPrecisionAmount)
			assert.NoError(t, err)
			assert.Equal(t, 0, paymentOrder.Amount.Cmp(expectedAmount),
				"Amount precision mismatch. Expected: %s, Got: %s",
				expectedAmount.String(), paymentOrder.Amount.String())

			// Verify the rate is stored with full precision
			expectedRate, err := decimal.NewFromString(highPrecisionRate)
			assert.NoError(t, err)
			assert.Equal(t, 0, paymentOrder.Rate.Cmp(expectedRate),
				"Rate precision mismatch. Expected: %s, Got: %s",
				expectedRate.String(), paymentOrder.Rate.String())

			// Verify network fee precision
			expectedNetworkFee := testCtx.token.Edges.Network.Fee
			assert.Equal(t, 0, paymentOrder.NetworkFee.Cmp(expectedNetworkFee),
				"Network fee precision mismatch. Expected: %s, Got: %s",
				expectedNetworkFee.String(), paymentOrder.NetworkFee.String())

			// Verify sender fee calculation precision (5% of amount)
			expectedSenderFee := expectedAmount.Mul(decimal.NewFromFloat(0.05))
			// Use tolerance for rounding differences
			diff := paymentOrder.SenderFee.Sub(expectedSenderFee).Abs()
			tolerance := decimal.NewFromFloat(0.01) // Allow 0.01 tolerance
			assert.True(t, diff.LessThanOrEqual(tolerance),
				"Sender fee calculation precision mismatch. Expected: %s, Got: %s, Diff: %s",
				expectedSenderFee.String(), paymentOrder.SenderFee.String(), diff.String())
		})

		t.Run("Small Amounts", func(t *testing.T) {
			// Test with small amounts to ensure no precision loss
			// Use values that fit within the token's decimal precision (6 decimals) and pass validation
			smallAmount := "1.000001"
			smallRate := "1.000001"

			payload := map[string]interface{}{
				"amount":  smallAmount,
				"token":   testCtx.token.Symbol,
				"rate":    smallRate,
				"network": testCtx.networkIdentifier,
				"recipient": map[string]interface{}{
					"institution":       "MOMONGPC",
					"accountIdentifier": "PRECISION_TEST_002",
					"accountName":       "Small Amount Test User",
					"memo":              "Testing DECIMAL(20,8) precision with very small values",
				},
				"reference": "DECIMAL_PRECISION_TEST_002",
			}

			headers := map[string]string{
				"API-Key": testCtx.apiKey.ID.String(),
			}

			res, err := test.PerformRequest(t, "POST", "/sender/orders", payload, headers, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusCreated, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Payment order initiated successfully", response.Message)

			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is not of type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			idValue, exists := data["id"]
			assert.True(t, exists, "response.Data does not contain 'id' field")
			assert.NotNil(t, idValue, "response.Data['id'] is nil")

			paymentOrderUUID, err := uuid.Parse(idValue.(string))
			assert.NoError(t, err)

			paymentOrder, err := db.Client.PaymentOrder.
				Query().
				Where(paymentorder.IDEQ(paymentOrderUUID)).
				Only(context.Background())
			assert.NoError(t, err)

			expectedAmount, err := decimal.NewFromString(smallAmount)
			assert.NoError(t, err)
			assert.Equal(t, 0, paymentOrder.Amount.Cmp(expectedAmount),
				"Small amount precision mismatch. Expected: %s, Got: %s",
				expectedAmount.String(), paymentOrder.Amount.String())

			expectedRate, err := decimal.NewFromString(smallRate)
			assert.NoError(t, err)
			assert.Equal(t, 0, paymentOrder.Rate.Cmp(expectedRate),
				"Small rate precision mismatch. Expected: %s, Got: %s",
				expectedRate.String(), paymentOrder.Rate.String())
		})

		t.Run("Large Amounts", func(t *testing.T) {
			largeAmount := "999999.999999"
			largeRate := "999999.999999"

			payload := map[string]interface{}{
				"amount":  largeAmount,
				"token":   testCtx.token.Symbol,
				"rate":    largeRate,
				"network": testCtx.networkIdentifier,
				"recipient": map[string]interface{}{
					"institution":       "MOMONGPC",
					"accountIdentifier": "PRECISION_TEST_003",
					"accountName":       "Large Amount Test User",
					"memo":              "Testing DECIMAL(20,8) precision with very large values",
				},
				"reference": "DECIMAL_PRECISION_TEST_003",
			}

			headers := map[string]string{
				"API-Key": testCtx.apiKey.ID.String(),
			}

			res, err := test.PerformRequest(t, "POST", "/sender/orders", payload, headers, router)
			assert.NoError(t, err)

			// Assert the response
			assert.Equal(t, http.StatusCreated, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Payment order initiated successfully", response.Message)

			// Extract payment order ID
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is not of type map[string]interface{}")

			paymentOrderUUID, err := uuid.Parse(data["id"].(string))
			assert.NoError(t, err)

			// Query the database to verify precision
			paymentOrder, err := db.Client.PaymentOrder.
				Query().
				Where(paymentorder.IDEQ(paymentOrderUUID)).
				Only(context.Background())
			assert.NoError(t, err)

			// Verify large amount precision
			expectedAmount, err := decimal.NewFromString(largeAmount)
			assert.NoError(t, err)
			assert.Equal(t, 0, paymentOrder.Amount.Cmp(expectedAmount),
				"Large amount precision mismatch. Expected: %s, Got: %s",
				expectedAmount.String(), paymentOrder.Amount.String())

			// Verify large rate precision
			expectedRate, err := decimal.NewFromString(largeRate)
			assert.NoError(t, err)
			assert.Equal(t, 0, paymentOrder.Rate.Cmp(expectedRate),
				"Large rate precision mismatch. Expected: %s, Got: %s",
				expectedRate.String(), paymentOrder.Rate.String())
		})
	})
}
