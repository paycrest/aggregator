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

	"github.com/google/uuid"
	"github.com/jarcoal/httpmock"
	_ "github.com/mattn/go-sqlite3"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/routers/middleware"
	"github.com/paycrest/aggregator/services"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/shopspring/decimal"

	"github.com/gin-gonic/gin"
	"github.com/paycrest/aggregator/ent/enttest"
	"github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/utils/test"
	"github.com/paycrest/aggregator/utils/token"
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

	// Set up test blockchain client
	backend, err := test.SetUpTestBlockchain()
	if err != nil {
		return err
	}

	// Create a test token
	testCtx.networkIdentifier = "localhost"
	token, err := test.CreateERC20Token(backend, map[string]interface{}{
		"identifier":     testCtx.networkIdentifier,
		"deployContract": false,
	})
	if err != nil {
		return fmt.Errorf("CreateERC20Token.sender_test: %w", err)
	}

	// Create test fiat currency and institutions
	_, err = test.CreateTestFiatCurrency(nil)
	if err != nil {
		return fmt.Errorf("CreateTestFiatCurrency.sender_test: %w", err)
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
	testCtx.client = backend

	testCtx.apiKeySecret = secretKey

	for i := 0; i < 9; i++ {
		time.Sleep(time.Duration(float64(rand.Intn(12))) * time.Second)
		_, err := test.CreateTestPaymentOrder(backend, token, map[string]interface{}{
			"sender": senderProfile,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func TestSender(t *testing.T) {
	// Activate httpmock
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Mock the /backend-wallet/create endpoint
	httpmock.RegisterResponder("POST", "https://engine.thirdweb.com/backend-wallet/create",
		func(req *http.Request) (*http.Response, error) {
			mockAddress := fmt.Sprintf("0x%040x", rand.Uint64())
			resp := map[string]interface{}{
				"result": map[string]interface{}{
					"walletAddress": mockAddress,
				},
			}
			respBytes, _ := json.Marshal(resp)
			return httpmock.NewBytesResponse(200, respBytes), nil
		},
	)

	// Set up test database client
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	db.Client = client

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
				"institution":       "ABNGNGLA",
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
		assert.Equal(t, paymentOrder.Edges.Recipient.AccountName, payload["recipient"].(map[string]interface{})["accountName"])
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
			// Check that we have orders returned (don't hardcode the number)
			orders := data["orders"].([]interface{})
			assert.Greater(t, len(orders), 0, "Should have at least one order")
			assert.LessOrEqual(t, len(orders), pageSize, "Should not exceed pageSize")
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
			assert.Greater(t, int(totalOrders), 0, "Should have at least one order")

			// Assert the totalOrderVolume value
			totalOrderVolumeStr, ok := data["totalOrderVolume"].(string)
			assert.True(t, ok, "totalOrderVolume is not of type string")
			totalOrderVolume, err := decimal.NewFromString(totalOrderVolumeStr)
			assert.NoError(t, err, "Failed to convert totalOrderVolume to decimal")
			assert.GreaterOrEqual(t, totalOrderVolume.Cmp(decimal.NewFromInt(0)), 0, "Total order volume should be non-negative")

			// Assert the totalFeeEarnings value
			totalFeeEarningsStr, ok := data["totalFeeEarnings"].(string)
			assert.True(t, ok, "totalFeeEarnings is not of type string")
			totalFeeEarnings, err := decimal.NewFromString(totalFeeEarningsStr)
			assert.NoError(t, err, "Failed to convert totalFeeEarnings to decimal")
			assert.GreaterOrEqual(t, totalFeeEarnings.Cmp(decimal.NewFromInt(0)), 0, "Total fee earnings should be non-negative")
		})

		t.Run("should only calculate volumes of settled orders", func(t *testing.T) {
			// create settled Order
			_, err = test.CreateTestPaymentOrder(testCtx.client, testCtx.token, map[string]interface{}{
				"sender":      testCtx.user,
				"amount":      100.0,
				"token":       testCtx.token.Symbol,
				"rate":        750.0,
				"status":      "settled",
				"fee_percent": 5.0,
			})
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
			assert.Greater(t, int(totalOrders), 0, "Should have at least one order")

			// Assert the totalOrderVolume value
			totalOrderVolumeStr, ok := data["totalOrderVolume"].(string)
			assert.True(t, ok, "totalOrderVolume is not of type string")
			totalOrderVolume, err := decimal.NewFromString(totalOrderVolumeStr)
			assert.NoError(t, err, "Failed to convert totalOrderVolume to decimal")
			assert.Greater(t, totalOrderVolume.Cmp(decimal.NewFromInt(0)), 0, "Total order volume should be greater than 0 for settled orders")

			// Assert the totalFeeEarnings value
			totalFeeEarningsStr, ok := data["totalFeeEarnings"].(string)
			assert.True(t, ok, "totalFeeEarnings is not of type string")
			totalFeeEarnings, err := decimal.NewFromString(totalFeeEarningsStr)
			assert.NoError(t, err, "Failed to convert totalFeeEarnings to decimal")
			assert.GreaterOrEqual(t, totalFeeEarnings.Cmp(decimal.NewFromInt(0)), 0, "Total fee earnings should be non-negative")
		})
	})
}
