package sender

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jarcoal/httpmock"
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
			SetAmountInUsd(decimal.NewFromFloat(100.50)).
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

	// Set up test database client with proper schema
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	// Run migrations to create all tables
	err := client.Schema.Create(context.Background())
	if err != nil {
		t.Fatalf("Failed to create database schema: %v", err)
	}

	db.Client = client

	// Set up in-memory Redis
	mr, err := miniredis.Run()
	assert.NoError(t, err)
	defer mr.Close()

	db.RedisClient = redis.NewClient(&redis.Options{Addr: mr.Addr()})

	// Setup test data
	setupErr := setup()
	assert.NoError(t, setupErr)

	senderTokens, err := client.SenderOrderToken.Query().All(context.Background())
	assert.NoError(t, err)
	assert.Greater(t, len(senderTokens), 0)

	// Set environment variables for engine service to match our mocks
	os.Setenv("ENGINE_BASE_URL", "https://engine.thirdweb.com")
	os.Setenv("THIRDWEB_SECRET_KEY", "test-secret-key")
	defer func() {
		os.Unsetenv("ENGINE_BASE_URL")
		os.Unsetenv("THIRDWEB_SECRET_KEY")
	}()

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

		// Activate httpmock globally to intercept all HTTP calls (including fastshot)
		httpmock.Activate()
		defer httpmock.DeactivateAndReset()

		// Mock the engine service call for receive address creation
		httpmock.RegisterResponder("POST", "https://engine.thirdweb.com/v1/accounts",
			func(r *http.Request) (*http.Response, error) {
				return httpmock.NewJsonResponse(200, map[string]interface{}{
					"result": map[string]interface{}{
						"smartAccountAddress": "0x1234567890123456789012345678901234567890",
					},
				})
			},
		)

		// Mock the engine service call for webhook creation
		httpmock.RegisterResponder("POST", "https://1.insight.thirdweb.com/v1/webhooks",
			func(r *http.Request) (*http.Response, error) {
				return httpmock.NewJsonResponse(200, map[string]interface{}{
					"data": map[string]interface{}{
						"id":             "webhook_123456789",
						"webhook_secret": "secret_123456789",
					},
				})
			},
		)

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
			t.Logf("Request payload: %+v", payload)
			t.Logf("Request headers: %+v", headers)
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
		idValue, exists := data["id"]
		if !exists || idValue == nil {
			t.Fatalf("ID field is missing or nil in response data: %+v", data)
		}
		idString, ok := idValue.(string)
		if !ok {
			t.Fatalf("ID field is not a string, got %T: %+v", idValue, idValue)
		}
		paymentOrderUUID, err = uuid.Parse(idString)
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
			ts := time.Now().Unix()
			sigPayload := map[string]interface{}{"timestamp": ts}
			sig := token.GenerateHMACSignature(sigPayload, testCtx.apiKeySecret)
			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + sig,
			}

			res, err = test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders/%s?timestamp=%v", paymentOrderUUID.String(), ts), nil, headers, router)
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
			assert.Equal(t, 10, int(totalOrders)) // 9 orders from setup + 1 from InitiatePaymentOrder test

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
				SetAmountInUsd(decimal.NewFromFloat(100.0)).
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
			assert.Equal(t, 11, int(totalOrders)) // 9 from setup + 1 from InitiatePaymentOrder + 1 settled order

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

	t.Run("SearchPaymentOrders", func(t *testing.T) {
		t.Run("should return error when search query is empty", func(t *testing.T) {
			var payload = map[string]interface{}{
				"search":    "",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?search=&timestamp=%v", payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Search query is required", response.Message)
		})


		t.Run("should search by account identifier", func(t *testing.T) {
			var payload = map[string]interface{}{
				"search":    "1234567890",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?search=%v&timestamp=%v", payload["search"], payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Payment orders found successfully", response.Message)

			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data should be map[string]interface{}")
			assert.NotNil(t, data, "response.Data should not be nil")
			assert.Greater(t, data["total"], 0.0)

			orders, ok := data["orders"].([]interface{})
			assert.True(t, ok, "orders should be []interface{}")
			assert.Greater(t, len(orders), 0)
		})

		t.Run("should return empty results for non-matching search", func(t *testing.T) {
			var payload = map[string]interface{}{
				"search":    "nonexistent_search_term",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?search=%v&timestamp=%v", payload["search"], payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Payment orders found successfully", response.Message)

			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data should be map[string]interface{}")
			assert.NotNil(t, data, "response.Data should not be nil")
			assert.Equal(t, 0.0, data["total"])

			// Handle empty orders array - could be nil or empty array
			if ordersData := data["orders"]; ordersData != nil {
				orders, ok := ordersData.([]interface{})
				assert.True(t, ok, "orders should be []interface{}")
				assert.Equal(t, 0, len(orders))
			}
		})

		t.Run("should only return orders for authenticated sender", func(t *testing.T) {
			// Create another sender with orders
			user2, err := test.CreateTestUser(map[string]interface{}{
				"email": "another_sender@test.com",
			})
			assert.NoError(t, err)

			senderProfile2, err := test.CreateTestSenderProfile(map[string]interface{}{
				"user_id":     user2.ID,
				"fee_percent": "3",
			})
			assert.NoError(t, err)

			apiKeyService := services.NewAPIKeyService()
			apiKey2, secretKey2, err := apiKeyService.GenerateAPIKey(
				context.Background(),
				nil,
				senderProfile2,
				nil,
			)
			assert.NoError(t, err)

			// Create payment order for second sender
			receiveAddress2, err := db.Client.ReceiveAddress.
				Create().
				SetAddress("0x9999999999999999999999999999999999999999").
				SetSalt([]byte("salt_another")).
				SetStatus("unused").
				SetValidUntil(time.Now().Add(time.Hour)).
				Save(context.Background())
			assert.NoError(t, err)

			paymentOrder2, err := db.Client.PaymentOrder.
				Create().
				SetSenderProfile(senderProfile2).
				SetAmount(decimal.NewFromFloat(200.0)).
				SetAmountInUsd(decimal.NewFromFloat(200.0)).
				SetAmountPaid(decimal.NewFromInt(0)).
				SetAmountReturned(decimal.NewFromInt(0)).
				SetPercentSettled(decimal.NewFromInt(0)).
				SetNetworkFee(testCtx.token.Edges.Network.Fee).
				SetSenderFee(decimal.NewFromFloat(0)).
				SetToken(testCtx.token).
				SetRate(decimal.NewFromFloat(750.0)).
				SetReceiveAddress(receiveAddress2).
				SetReceiveAddressText(receiveAddress2.Address).
				SetFeePercent(decimal.NewFromFloat(0)).
				SetFeeAddress("0x1234567890123456789012345678901234567890").
				SetReturnAddress("0x0987654321098765432109876543210987654321").
				SetReference("unique_ref_second_sender").
				SetStatus("pending").
				Save(context.Background())
			assert.NoError(t, err)

			_, err = db.Client.PaymentOrderRecipient.
				Create().
				SetInstitution("MOMONGPC").
				SetAccountIdentifier("9876543210").
				SetAccountName("Second Sender Account").
				SetPaymentOrder(paymentOrder2).
				Save(context.Background())
			assert.NoError(t, err)

			var payload = map[string]interface{}{
				"search":    paymentOrder2.ID.String(),
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?search=%v&timestamp=%v", payload["search"], payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)

			data := response.Data.(map[string]interface{})
			assert.Equal(t, 0.0, data["total"])

			// Search using second sender's credentials - should find their order
			payload2 := map[string]interface{}{
				"search":    paymentOrder2.ID.String(),
				"timestamp": time.Now().Unix(),
			}

			signature2 := token.GenerateHMACSignature(payload2, secretKey2)

			headers2 := map[string]string{
				"Authorization": "HMAC " + apiKey2.ID.String() + ":" + signature2,
			}

			res2, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?search=%v&timestamp=%v", payload2["search"], payload2["timestamp"]), nil, headers2, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res2.Code)

			var response2 types.Response
			err = json.Unmarshal(res2.Body.Bytes(), &response2)
			assert.NoError(t, err)

			data2 := response2.Data.(map[string]interface{})
			assert.Equal(t, 1.0, data2["total"])

			orders := data2["orders"].([]interface{})
			order := orders[0].(map[string]interface{})
			assert.Equal(t, paymentOrder2.ID.String(), order["id"])
		})
	})

	t.Run("ExportPaymentOrdersCSV", func(t *testing.T) {
		t.Run("should export CSV with date range", func(t *testing.T) {
			// Test with date range covering today
			today := time.Now().Format("2006-01-02")
			tomorrow := time.Now().Add(24 * time.Hour).Format("2006-01-02")

			var payload = map[string]interface{}{
				"from":      today,
				"to":        tomorrow,
				"export":    "csv",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?from=%s&to=%s&timestamp=%v&export=csv", payload["from"], payload["to"], payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)

			// Check CSV headers
			assert.Equal(t, "text/csv", res.Header().Get("Content-Type"))
			assert.Contains(t, res.Header().Get("Content-Disposition"), "attachment; filename=payment_orders_")
			assert.NotEmpty(t, res.Header().Get("X-Total-Count"))

			// Check CSV content
			csvContent := res.Body.String()
			assert.Contains(t, csvContent, "Order ID,Reference,Token Amount")
			assert.Contains(t, csvContent, "Token,Network,Amount (USD),Rate,Sender Fee")

			// Should contain the order with reference we created
			assert.Contains(t, csvContent, "12kjdf-kjn33_REF")
			assert.Contains(t, csvContent, "TST")
			assert.Contains(t, csvContent, testCtx.networkIdentifier)
		})

		t.Run("should export CSV with limit", func(t *testing.T) {
			// Test with limit that's higher than the number of orders that exist
			// This tests the limit parameter functionality without hitting the validation error
			today := time.Now().Format("2006-01-02")
			tomorrow := time.Now().Add(24 * time.Hour).Format("2006-01-02")

			var payload = map[string]interface{}{
				"from":      today,
				"to":        tomorrow,
				"limit":     "50", // Use a limit higher than expected orders to avoid validation error
				"export":    "csv",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?from=%s&to=%s&limit=%s&timestamp=%v&export=csv", payload["from"], payload["to"], payload["limit"], payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			if res.Code != http.StatusOK {
				t.Logf("Response Status: %d", res.Code)
				t.Logf("Response Body: %s", res.Body.String())
			}
			assert.Equal(t, http.StatusOK, res.Code)

			csvContent := res.Body.String()
			lines := strings.Split(strings.TrimSpace(csvContent), "\n")
			// Should have header + some data rows, all within the limit of 50
			assert.GreaterOrEqual(t, len(lines), 2) // At least header + 1 data row
			assert.LessOrEqual(t, len(lines), 51) // Header + max 50 data rows
		})

		t.Run("should return error when export exceeds limit", func(t *testing.T) {
			// Test with a very small limit to trigger the validation error
			today := time.Now().Format("2006-01-02")
			tomorrow := time.Now().Add(24 * time.Hour).Format("2006-01-02")

			var payload = map[string]interface{}{
				"from":      today,
				"to":        tomorrow,
				"limit":     "1", // Very small limit to trigger validation
				"export":    "csv",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?from=%s&to=%s&limit=%s&timestamp=%v&export=csv", payload["from"], payload["to"], payload["limit"], payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response.Message, "Export too large")
		})

		t.Run("should return error for invalid date format", func(t *testing.T) {
			var payload = map[string]interface{}{
				"from":      "invalid-date",
				"to":		"2024-12-31",
				"export":    "csv",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?from=%s&to=%s&timestamp=%v&export=csv", payload["from"], payload["to"], payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Invalid from date format", response.Message)
		})

		t.Run("should return error when no orders found", func(t *testing.T) {
			// Use date range from future
			futureDate := time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02")
			farFuture := time.Now().Add(370 * 24 * time.Hour).Format("2006-01-02")

			var payload = map[string]interface{}{
				"from":      futureDate,
				"to":        farFuture,
				"export":    "csv",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?from=%s&to=%s&timestamp=%v&export=csv", payload["from"], payload["to"], payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			if res.Code != http.StatusBadRequest {
				t.Logf("Response Status: %d", res.Code)
				t.Logf("Response Body: %s", res.Body.String())
			}
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "No orders found in the specified date range", response.Message)
		})

		t.Run("should only export orders for authenticated sender", func(t *testing.T) {
			// Create another sender with orders (if not already created)
			user2, err := test.CreateTestUser(map[string]interface{}{
				"email": "export_sender2@test.com",
			})
			assert.NoError(t, err)

			senderProfile2, err := test.CreateTestSenderProfile(map[string]interface{}{
				"user_id":     user2.ID,
				"fee_percent": "3",
			})
			assert.NoError(t, err)

			apiKeyService := services.NewAPIKeyService()
			apiKey2, secretKey2, err := apiKeyService.GenerateAPIKey(
				context.Background(),
				nil,
				senderProfile2,
				nil,
			)
			assert.NoError(t, err)

			// Export using second sender's credentials
			today := time.Now().Format("2006-01-02")
			tomorrow := time.Now().Add(24 * time.Hour).Format("2006-01-02")

			var payload = map[string]interface{}{
				"from":      today,
				"to":        tomorrow,
				"export":    "csv",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, secretKey2)

			headers := map[string]string{
				"Authorization": "HMAC " + apiKey2.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/sender/orders?from=%s&to=%s&timestamp=%v&export=csv", today, tomorrow, payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Should get empty result or no orders found error since second sender has no orders in date range
			if res.Code == http.StatusOK {
				csvContent := res.Body.String()
				lines := strings.Split(strings.TrimSpace(csvContent), "\n")
				// Should only have header row
				assert.Equal(t, 1, len(lines))
			} else {
				if res.Code != http.StatusBadRequest {
					t.Logf("Response Status: %d", res.Code)
					t.Logf("Response Body: %s", res.Body.String())
				}
				assert.Equal(t, http.StatusBadRequest, res.Code)
				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "No orders found in the specified date range", response.Message)
			}
		})
	})
}
