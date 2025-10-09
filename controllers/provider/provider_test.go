package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/jarcoal/httpmock"
	_ "github.com/mattn/go-sqlite3"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/routers/middleware"
	"github.com/paycrest/aggregator/services"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/redis/go-redis/v9"
	"github.com/shopspring/decimal"

	"github.com/gin-gonic/gin"
	"github.com/paycrest/aggregator/ent/enttest"
	"github.com/paycrest/aggregator/utils/test"
	"github.com/paycrest/aggregator/utils/token"
	"github.com/stretchr/testify/assert"
)

var testCtx = struct {
	user         *ent.User
	provider     *ent.ProviderProfile
	apiKey       *ent.APIKey
	currency     *ent.FiatCurrency
	token        *ent.Token
	apiKeySecret string
	lockOrder    *ent.LockPaymentOrder
}{}

func setup() error {
	// Set up test data
	user, err := test.CreateTestUser(map[string]interface{}{
		"scope": "provider"})
	if err != nil {
		return err
	}
	testCtx.user = user

	currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
		"market_rate": 950.0,
	})
	if err != nil {
		return err
	}
	testCtx.currency = currency

	// Set up test blockchain client
	backend, err := test.SetUpTestBlockchain()
	if err != nil {
		return err
	}

	// Create a test token
	token, err := test.CreateERC20Token(backend, map[string]interface{}{
		"identifier":     "localhost",
		"deployContract": false,
	})
	if err != nil {
		return fmt.Errorf("CreateERC20Token.sender_test: %w", err)
	}
	testCtx.token = token

	providerProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
		"user_id":     testCtx.user.ID,
		"currency_id": currency.ID,
	})
	if err != nil {
		return err
	}
	testCtx.provider = providerProfile

	for i := 0; i < 10; i++ {
		time.Sleep(time.Duration(time.Duration(rand.Intn(10)) * time.Second))
		_, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
			"gateway_id": uuid.New().String(),
			"provider":   providerProfile,
		})
		if err != nil {
			return err
		}
		time.Sleep(time.Duration(time.Duration(rand.Intn(10)) * time.Second))

	}

	apiKeyService := services.NewAPIKeyService()
	apiKey, secretKey, err := apiKeyService.GenerateAPIKey(
		context.Background(),
		nil,
		nil,
		providerProfile,
	)
	if err != nil {
		return err
	}

	testCtx.apiKey = apiKey
	testCtx.apiKeySecret = secretKey

	return nil
}

// setupIsolatedTest creates a fresh database and Redis client for complete test isolation
func setupIsolatedTest(t *testing.T) (*ent.Client, *redis.Client, func()) {
	// Create fresh database
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	err := client.Schema.Create(context.Background())
	if err != nil {
		t.Fatalf("Failed to create database schema: %v", err)
	}

	// Create fresh Redis
	mr, err := miniredis.Run()
	assert.NoError(t, err)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	// Store original clients
	originalClient := db.Client
	originalRedis := db.RedisClient

	// Set new clients
	db.Client = client
	db.RedisClient = redisClient

	// Populate test data in the fresh database
	err = setup()
	if err != nil {
		t.Fatalf("Failed to setup test data: %v", err)
	}

	// Return cleanup function
	cleanup := func() {
		client.Close()
		mr.Close()
		db.Client = originalClient
		db.RedisClient = originalRedis
	}

	return client, redisClient, cleanup
}

// ensureDatabaseSchema makes sure the database schema is properly created
// This is especially important for tables needed by auth middleware
func ensureDatabaseSchema(t *testing.T) {
	ctx := context.Background()

	// Check if schema exists by attempting to query a critical table
	_, err := db.Client.APIKey.Query().Count(ctx)
	if err != nil {
		// Check if it's a "no such table" error
		if strings.Contains(err.Error(), "no such table") {
			t.Logf("Database schema missing, recreating entire schema...")
			err = db.Client.Schema.Create(ctx)
			if err != nil {
				t.Fatalf("Failed to recreate database schema: %v", err)
			}
			t.Logf("Database schema recreated successfully")

			// After recreating schema, we need to re-run setup to populate test data
			t.Logf("Recreating test data after schema recreation...")
			err = setup()
			if err != nil {
				t.Fatalf("Failed to recreate test data after schema recreation: %v", err)
			}
		} else {
			t.Fatalf("Unexpected database error: %v", err)
		}
	}
}

func TestProvider(t *testing.T) {
	// Set up isolated test environment (includes test data setup)
	_, _, cleanup := setupIsolatedTest(t)
	defer cleanup()

	// Set up test routers
	router := gin.New()
	router.Use(middleware.DynamicAuthMiddleware)
	router.Use(middleware.OnlyProviderMiddleware)

	// Create a new instance of the SenderController with the mock service
	ctrl := NewProviderController()
	router.GET("/orders", ctrl.GetLockPaymentOrders)
	router.GET("/stats", ctrl.Stats)
	router.GET("/node-info", ctrl.NodeInfo)
	router.GET("/orders/:id", ctrl.GetLockPaymentOrderByID)
	router.POST("/orders/:id/accept", ctrl.AcceptOrder)
	router.POST("/orders/:id/decline", ctrl.DeclineOrder)
	router.POST("/orders/:id/fulfill", ctrl.FulfillOrder)
	router.POST("/orders/:id/cancel", ctrl.CancelOrder)
	router.GET("/rates/:token/:fiat", ctrl.GetMarketRate)

	t.Run("GetLockPaymentOrders", func(t *testing.T) {
		t.Run("fetch default list", func(t *testing.T) {
			// Test default params
			var payload = map[string]interface{}{
				"currency":  "NGN",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				"Client-Type":   "backend",
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/orders?currency=NGN&timestamp=%v", payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Orders successfully retrieved", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is of not type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			assert.Equal(t, int(data["page"].(float64)), 1)
			assert.Equal(t, int(data["pageSize"].(float64)), 10) // default pageSize
			assert.NotNil(t, data["total"])
			assert.NotEmpty(t, data["orders"])
			assert.Greater(t, len(data["orders"].([]interface{})), 0)

		})

		t.Run("fetch orders with cancellation reasons", func(t *testing.T) {
			// Create a test order with cancellation reasons
			order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
				"gateway_id":           uuid.New().String(),
				"provider":             testCtx.provider,
				"cancellation_reasons": []string{"Out of stock", "Payment failed"},
			})
			assert.NoError(t, err)

			var payload = map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				"Client-Type":   "backend",
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/orders/%s?timestamp=%v", order.ID, payload["timestamp"]), nil, headers, router)

			assert.NoError(t, err, "Error performing request")

			// Check response status code
			if !assert.Equal(t, http.StatusOK, res.Code, "Response code should be 200") {
				t.Logf("Unexpected response body: %s", res.Body.String())
				return
			}

			// Parse response
			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err, "Failed to unmarshal response")
			assert.Equal(t, "The order has been successfully retrieved", response.Message)

			// Validate response data structure
			data, ok := response.Data.(map[string]interface{})
			if !assert.True(t, ok, "response.Data should be map[string]interface{}") {
				return
			}

			// Now we directly validate the fields inside `data` instead of `data.orders`
			assert.Equal(t, order.GatewayID, data["gatewayId"], "Gateway ID does not match")

			cancellationReasons, ok := data["cancellationReasons"].([]interface{})
			if assert.True(t, ok, "cancellationReasons should be []interface{}") {
				assert.Equal(t, 2, len(cancellationReasons), "Expected exactly two cancellation reasons")
				assert.Contains(t, cancellationReasons, "Out of stock", "Expected cancellation reason not found")
				assert.Contains(t, cancellationReasons, "Payment failed", "Expected cancellation reason not found")
			} else {
				t.Logf("cancellationReasons: %+v", data["cancellationReasons"])
			}
		})

		t.Run("fetch single order with cancellation reasons", func(t *testing.T) {
			// Create a test order with cancellation reasons
			order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
				"gateway_id":           uuid.New().String(),
				"provider":             testCtx.provider,
				"cancellation_reasons": []string{"Out of stock", "Payment failed"},
			})
			assert.NoError(t, err)

			var payload = map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				"Client-Type":   "backend",
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/orders/%s?timestamp=%v", order.ID, payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "The order has been successfully retrieved", response.Message)

			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is not of type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			// Check cancellation_reasons
			// cancellationReasons := data["cancellationReasons"].([]interface{})
			// assert.Equal(t, []string{"Out of stock", "Payment failed"}, cancellationReasons)
			cancellationReasons := data["cancellationReasons"].([]interface{})
			cancellationReasonsAsStrings := make([]string, len(cancellationReasons))
			for i, reason := range cancellationReasons {
				cancellationReasonsAsStrings[i] = reason.(string)
			}
			assert.Equal(t, []string{"Out of stock", "Payment failed"}, cancellationReasonsAsStrings)

		})

		t.Run("fetch order without cancellation reasons", func(t *testing.T) {
			// Create a test order without cancellation reasons
			order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
				"gateway_id":           uuid.New().String(),
				"provider":             testCtx.provider,
				"cancellation_reasons": []string{},
			})
			assert.NoError(t, err)

			var payload = map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				"Client-Type":   "backend",
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/orders/%s?timestamp=%v", order.ID, payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "The order has been successfully retrieved", response.Message)

			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is not of type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			// Ensure cancellation_reasons is empty
			cancellationReasons := data["cancellationReasons"].([]interface{})
			assert.Empty(t, cancellationReasons)
		})

		t.Run("when filtering is applied", func(t *testing.T) {
			// Test different status filters
			var payload = map[string]interface{}{
				"status":    "pending",
				"currency":  "NGN",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				"Client-Type":   "backend",
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/orders?status=%s&currency=%s&timestamp=%v", "pending", "NGN", payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Orders successfully retrieved", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is of not type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			assert.Equal(t, int(data["page"].(float64)), 1)
			assert.Equal(t, int(data["pageSize"].(float64)), 10) // default pageSize
			assert.NotNil(t, data["total"])
			assert.NotEmpty(t, data["orders"])
			assert.Greater(t, len(data["orders"].([]interface{})), 0)

		})

		t.Run("with custom page and pageSize", func(t *testing.T) {
			// Test different page and pageSize values
			page := 1
			pageSize := 5
			var payload = map[string]interface{}{
				"page":      strconv.Itoa(page),
				"pageSize":  strconv.Itoa(pageSize),
				"currency":  "NGN",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				"Client-Type":   "backend",
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/orders?page=%s&pageSize=%s&currency=%s&timestamp=%v", strconv.Itoa(page), strconv.Itoa(pageSize), "NGN", payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Orders successfully retrieved", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is of not type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			assert.Equal(t, int(data["page"].(float64)), page)
			assert.Equal(t, int(data["pageSize"].(float64)), pageSize)
			assert.NotNil(t, data["total"])
			assert.NotEmpty(t, data["orders"])
			assert.Equal(t, len(data["orders"].([]interface{})), pageSize)
			assert.Greater(t, len(data["orders"].([]interface{})), 0)

		})

		t.Run("with ordering", func(t *testing.T) {
			// Test ascending and descending ordering
			var payload = map[string]interface{}{
				"ordering":  "desc",
				"currency":  "NGN",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				"Client-Type":   "backend",
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/orders?ordering=%s&currency=%s&timestamp=%v", payload["ordering"], "NGN", payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Orders successfully retrieved", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is of not type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			// Try to parse the first and last order time strings using a set of predefined layouts
			firstOrderTimestamp, err := time.Parse(
				time.RFC3339Nano,
				data["orders"].([]interface{})[0].(map[string]interface{})["createdAt"].(string),
			)
			if err != nil {
				return
			}

			lastOrderTimestamp, err := time.Parse(
				time.RFC3339Nano,
				data["orders"].([]interface{})[len(data["orders"].([]interface{}))-1].(map[string]interface{})["createdAt"].(string),
			)
			if err != nil {
				return
			}

			assert.Equal(t, int(data["page"].(float64)), 1)
			assert.Equal(t, int(data["pageSize"].(float64)), 10) // default pageSize
			assert.NotNil(t, data["total"])
			assert.NotEmpty(t, data["orders"])
			assert.Greater(t, len(data["orders"].([]interface{})), 0)
			assert.Greater(t, firstOrderTimestamp, lastOrderTimestamp)
		})

	})

	t.Run("GetStats", func(t *testing.T) {
		// Create a new user with no orders
		user, err := test.CreateTestUser(map[string]interface{}{
			"email": "no_order_user@test.com",
		})
		if err != nil {
			return
		}

		currency, err := test.CreateTestFiatCurrency(nil)
		if err != nil {
			return
		}

		providerProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
			"user_id":     user.ID,
			"currency_id": currency.ID,
		})
		if err != nil {
			return
		}

		apiKeyService := services.NewAPIKeyService()
		apiKey, secretKey, err := apiKeyService.GenerateAPIKey(
			context.Background(),
			nil,
			nil,
			providerProfile,
		)
		if err != nil {
			return
		}

		t.Run("when no orders have been initiated", func(t *testing.T) {

			// Test default params
			var payload = map[string]interface{}{
				"currency":  "NGN",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, secretKey)

			headers := map[string]string{
				"Authorization": "HMAC " + apiKey.ID.String() + ":" + signature,
				"Client-Type":   "backend",
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/stats?currency=%s&timestamp=%v", "NGN", payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Provider stats fetched successfully", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is of not type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			assert.Equal(t, int(data["totalOrders"].(float64)), 0)

			totalFiatVolumeStr, ok := data["totalFiatVolume"].(string)
			assert.True(t, ok, "totalFiatVolume is not of type string")
			totalFiatVolume, err := decimal.NewFromString(totalFiatVolumeStr)
			assert.NoError(t, err, "Failed to convert totalFiatVolume to decimal")
			assert.Equal(t, totalFiatVolume, decimal.NewFromInt(0))

			totalCryptoVolumeStr, ok := data["totalCryptoVolume"].(string)
			assert.True(t, ok, "totalCryptoVolume is not of type string")
			totalCryptoVolume, err := decimal.NewFromString(totalCryptoVolumeStr)
			assert.NoError(t, err, "Failed to convert totalCryptoVolume to decimal")
			assert.Equal(t, totalCryptoVolume, decimal.NewFromInt(0))
		})

		t.Run("when orders have been initiated", func(t *testing.T) {
			// Test default params
			var payload = map[string]interface{}{
				"currency":  "NGN",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				"Client-Type":   "backend",
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/stats?currency=%s&timestamp=%v", "NGN", payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Provider stats fetched successfully", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is of not type *types.ProviderStatsResponse")
			assert.NotNil(t, data, "response.Data is nil")

			// Assert the totalOrders value
			totalOrders, ok := data["totalOrders"].(float64)
			assert.True(t, ok, "totalOrders is not of type float64")
			assert.Equal(t, 13, int(totalOrders))

			// Assert the totalFiatVolume value
			totalFiatVolumeStr, ok := data["totalFiatVolume"].(string)
			assert.True(t, ok, "totalFiatVolume is not of type string")
			totalFiatVolume, err := decimal.NewFromString(totalFiatVolumeStr)
			assert.NoError(t, err, "Failed to convert totalFiatVolume to decimal")
			assert.Equal(t, 0, totalFiatVolume.Cmp(decimal.NewFromInt(0)))

			// Assert the totalCryptoVolume value
			totalCryptoVolumeStr, ok := data["totalCryptoVolume"].(string)
			assert.True(t, ok, "totalCryptoVolume is not of type string")
			totalCryptoVolume, err := decimal.NewFromString(totalCryptoVolumeStr)
			assert.NoError(t, err, "Failed to convert totalCryptoVolume to decimal")
			assert.Equal(t, 0, totalCryptoVolume.Cmp(decimal.NewFromInt(0)))
		})

		t.Run("with valid currency filter", func(t *testing.T) {
			// Use the provider's assigned currency (created in setup)
			var payload = map[string]interface{}{
				"currency":  "NGN",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				"Client-Type":   "backend",
			}

			url := fmt.Sprintf("/stats?currency=%s&timestamp=%v", testCtx.currency.Code, payload["timestamp"])
			res, err := test.PerformRequest(t, "GET", url, nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Provider stats fetched successfully", response.Message)

			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is not of type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")
		})

		t.Run("with invalid currency filter", func(t *testing.T) {
			// Use an invalid currency code, e.g., "XYZ"
			var payload = map[string]interface{}{
				"currency":  "NGN",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				"Client-Type":   "backend",
			}

			url := fmt.Sprintf("/stats?currency=%s&timestamp=%v", "NGN", payload["timestamp"])
			res, err := test.PerformRequest(t, "GET", url, nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Currency not found", response.Message)
		})

		t.Run("should only calculate volumes of settled orders", func(t *testing.T) {
			// Create a settled order
			_, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
				"gateway_id": uuid.New().String(),
				"provider":   testCtx.provider,
				"status":     "settled",
			})
			assert.NoError(t, err)
			var payload = map[string]interface{}{
				"currency":  "NGN",
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				"Client-Type":   "backend",
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/stats?currency=%s&timestamp=%v", "NGN", payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Provider stats fetched successfully", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is of not type *types.ProviderStatsResponse")
			assert.NotNil(t, data, "response.Data is nil")

			// Assert the totalOrders value
			totalOrders, ok := data["totalOrders"].(float64)
			assert.True(t, ok, "totalOrders is not of type float64")
			assert.Equal(t, 14, int(totalOrders))

			// Assert the totalFiatVolume value
			totalFiatVolumeStr, ok := data["totalFiatVolume"].(string)
			assert.True(t, ok, "totalFiatVolume is not of type string")
			totalFiatVolume, err := decimal.NewFromString(totalFiatVolumeStr)
			assert.NoError(t, err, "Failed to convert totalFiatVolume to decimal")

			expectedTotalFiatVolume, err := decimal.NewFromString("75375")
			assert.NoError(t, err, "Failed to convert expectedTotalFiatVolume to decimal")
			assert.Equal(t, 0, totalFiatVolume.Cmp(expectedTotalFiatVolume))

			// Assert the totalCryptoVolume value
			totalCryptoVolumeStr, ok := data["totalCryptoVolume"].(string)
			assert.True(t, ok, "totalCryptoVolume is not of type string")
			totalCryptoVolume, err := decimal.NewFromString(totalCryptoVolumeStr)
			assert.NoError(t, err, "Failed to convert totalCryptoVolume to decimal")

			expectedTotalCryptoVolume, err := decimal.NewFromString("100.5")
			assert.NoError(t, err, "Failed to convert expectedTotalCryptoVolume to decimal")
			assert.Equal(t, 0, totalCryptoVolume.Cmp(expectedTotalCryptoVolume))
		})
	})

	t.Run("NodeInfo", func(t *testing.T) {

		t.Run("when node is healthy", func(t *testing.T) {
			// Activate httpmock
			httpmock.Activate()
			defer httpmock.Deactivate()

			// Register mock response
			httpmock.RegisterResponder("GET", "https://example.com/info",
				func(r *http.Request) (*http.Response, error) {
					return httpmock.NewJsonResponse(200, map[string]interface{}{
						"status":  "success",
						"message": "Node is live",
						"data": map[string]interface{}{
							"serviceInfo": map[string]interface{}{
								"currencies": []string{"NGN"},
							},
						},
					})
				},
			)

			// Test default params
			var payload = map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/node-info?timestamp=%v", payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Node info fetched successfully", response.Message)
		})

		t.Run("when node is unhealthy", func(t *testing.T) {
			// Activate httpmock
			httpmock.Activate()
			defer httpmock.Deactivate()

			// Register mock response
			httpmock.RegisterResponder("GET", "https://example.com/info",
				func(r *http.Request) (*http.Response, error) {
					return httpmock.NewJsonResponse(503, nil)
				},
			)

			// Test default params
			var payload = map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/node-info?timestamp=%v", payload["timestamp"]), nil, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusServiceUnavailable, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Failed to fetch node info", response.Message)
		})
	})

	t.Run("GetMarketRate", func(t *testing.T) {

		t.Run("when token does not exist", func(t *testing.T) {

			// Test default params
			var payload = map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/rates/XXXX/USD?timestamp=%v", payload["timestamp"]), payload, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Token XXXX is not supported", response.Message)
		})

		t.Run("when fiat does not exist", func(t *testing.T) {

			// Test default params
			var payload = map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/rates/%s/USD?timestamp=%v", testCtx.token.Symbol, payload["timestamp"]), payload, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Fiat currency USD is not supported", response.Message)
		})

		t.Run("when fiat exist", func(t *testing.T) {

			// Test default params
			var payload = map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/rates/%s/%s?timestamp=%v", testCtx.token.Symbol, testCtx.currency.Code, payload["timestamp"]), payload, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response struct {
				Status  string                   `json:"status"`
				Message string                   `json:"message"`
				Data    types.MarketRateResponse `json:"data"`
			}
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Rate fetched successfully", response.Message)
			assert.Equal(t, "950.0", response.Data.MarketRate.StringFixed(1))
		})
	})

	t.Run("AcceptOrder", func(t *testing.T) {

		t.Run("Invalid Request", func(t *testing.T) {

			t.Run("Invalid HMAC", func(t *testing.T) {

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}

				headers := map[string]string{
					"Authorization": "HMAC " + "testTest",
				}

				res, err := test.PerformRequest(t, "POST", "/orders/test/accept", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusUnauthorized, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid Authorization header format", response.Message)
			})

			t.Run("Invalid API key or token", func(t *testing.T) {

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}

				headers := map[string]string{
					"Authorization": "HMAC " + "test:Test",
				}

				res, err := test.PerformRequest(t, "POST", "/orders/test/accept", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusBadRequest, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid API key ID", response.Message)
			})

			t.Run("Invalid Order ID", func(t *testing.T) {

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}
				signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

				headers := map[string]string{
					"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				}

				res, err := test.PerformRequest(t, "POST", "/orders/test/accept", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusBadRequest, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid Order ID", response.Message)
			})

			t.Run("Invalid Provider ID", func(t *testing.T) {

				order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
					"gateway_id": uuid.New().String(),
					"provider":   testCtx.provider,
				})
				assert.NoError(t, err)

				orderKey := fmt.Sprintf("order_request_%s", order.ID)

				user, err := test.CreateTestUser(map[string]interface{}{
					"email": "no_providerId_user@test.com",
				})
				assert.NoError(t, err)

				providerProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
					"user_id":     user.ID,
					"currency_id": testCtx.currency.ID,
				})
				assert.NoError(t, err)

				orderRequestData := map[string]interface{}{
					"amount":      order.Amount.Mul(order.Rate).RoundBank(0).String(),
					"institution": order.Institution,
					"providerId":  providerProfile.ID,
				}

				if db.RedisClient != nil {
					err = db.RedisClient.HSet(context.Background(), orderKey, orderRequestData).Err()
					assert.NoError(t, err, fmt.Errorf("failed to map order to a provider in Redis: %v", err))
				}

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}

				signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

				headers := map[string]string{
					"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				}

				res, err := test.PerformRequest(t, "POST", "/orders/"+order.ID.String()+"/accept", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusNotFound, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Order request not found or is expired", response.Message)
			})

			t.Run("Order Id that doesn't Exist", func(t *testing.T) {

				order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
					"gateway_id": uuid.New().String(),
					"provider":   testCtx.provider,
				})
				assert.NoError(t, err)

				orderKey := fmt.Sprintf("order_request_%s", order.ID)

				user, err := test.CreateTestUser(map[string]interface{}{
					"email": "order_not_found2@test.com",
				})
				assert.NoError(t, err)

				providerProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
					"user_id":     user.ID,
					"currency_id": testCtx.currency.ID,
				})
				assert.NoError(t, err)

				orderRequestData := map[string]interface{}{
					"amount":      order.Amount.Mul(order.Rate).RoundBank(0).String(),
					"institution": order.Institution,
					"providerId":  providerProfile.ID,
				}

				if db.RedisClient != nil {
					err = db.RedisClient.HSet(context.Background(), orderKey, orderRequestData).Err()
					assert.NoError(t, err, fmt.Errorf("failed to map order to a provider in Redis: %v", err))
				}

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}

				signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

				headers := map[string]string{
					"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				}

				res, err := test.PerformRequest(t, "POST", "/orders/"+testCtx.currency.ID.String()+"/accept", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusNotFound, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Order request not found or is expired", response.Message)
			})

		})

		t.Run("when data is accurate", func(t *testing.T) {

			order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
				"gateway_id": uuid.New().String(),
				"provider":   testCtx.provider,
			})
			assert.NoError(t, err)

			orderKey := fmt.Sprintf("order_request_%s", order.ID)

			orderRequestData := map[string]interface{}{
				"amount":      order.Amount.Mul(order.Rate).RoundBank(0).String(),
				"institution": order.Institution,
				"providerId":  testCtx.provider.ID,
			}

			if db.RedisClient != nil {
				err = db.RedisClient.HSet(context.Background(), orderKey, orderRequestData).Err()
				assert.NoError(t, err, fmt.Errorf("failed to map order to a provider in Redis: %v", err))
			}

			// Test default params
			var payload = map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "POST", "/orders/"+order.ID.String()+"/accept", payload, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusCreated, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Order request accepted successfully", response.Message)
		})

	})

	t.Run("DeclineOrder", func(t *testing.T) {

		t.Run("Invalid Request", func(t *testing.T) {

			t.Run("Invalid HMAC", func(t *testing.T) {

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}

				headers := map[string]string{
					"Authorization": "HMAC " + "testTest",
				}

				res, err := test.PerformRequest(t, "POST", "/orders/test/decline", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusUnauthorized, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid Authorization header format", response.Message)
			})

			t.Run("Invalid API key or token", func(t *testing.T) {

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}

				headers := map[string]string{
					"Authorization": "HMAC " + "test:Test",
				}

				res, err := test.PerformRequest(t, "POST", "/orders/test/decline", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusBadRequest, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid API key ID", response.Message)
			})

			t.Run("Invalid Order ID", func(t *testing.T) {

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}
				signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

				headers := map[string]string{
					"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				}

				res, err := test.PerformRequest(t, "POST", "/orders/test/decline", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusBadRequest, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid Order ID", response.Message)
			})

			t.Run("Invalid Provider ID", func(t *testing.T) {

				order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
					"gateway_id": uuid.New().String(),
					"provider":   testCtx.provider,
				})
				assert.NoError(t, err)

				orderKey := fmt.Sprintf("order_request_%s", order.ID)

				user, err := test.CreateTestUser(map[string]interface{}{
					"email": "no_providerId_user1@test.com",
				})
				assert.NoError(t, err)

				providerProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
					"user_id":     user.ID,
					"currency_id": testCtx.currency.ID,
				})
				assert.NoError(t, err)

				orderRequestData := map[string]interface{}{
					"amount":      order.Amount.Mul(order.Rate).RoundBank(0).String(),
					"institution": order.Institution,
					"providerId":  providerProfile.ID,
				}

				if db.RedisClient != nil {
					err = db.RedisClient.HSet(context.Background(), orderKey, orderRequestData).Err()
					assert.NoError(t, err, fmt.Errorf("failed to map order to a provider in Redis: %v", err))
				}

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}

				signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

				headers := map[string]string{
					"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				}

				res, err := test.PerformRequest(t, "POST", "/orders/"+order.ID.String()+"/decline", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusNotFound, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Order request not found or is expired", response.Message)
			})

			t.Run("Order Id that doesn't Exist", func(t *testing.T) {

				order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
					"gateway_id": uuid.New().String(),
					"provider":   testCtx.provider,
				})
				assert.NoError(t, err)

				orderKey := fmt.Sprintf("order_request_%s", order.ID)

				user, err := test.CreateTestUser(map[string]interface{}{
					"email": "order_not_found1@test.com",
				})
				assert.NoError(t, err)

				providerProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
					"user_id":     user.ID,
					"currency_id": testCtx.currency.ID,
				})
				assert.NoError(t, err)

				orderRequestData := map[string]interface{}{
					"amount":      order.Amount.Mul(order.Rate).RoundBank(0).String(),
					"institution": order.Institution,
					"providerId":  providerProfile.ID,
				}

				if db.RedisClient != nil {
					err = db.RedisClient.HSet(context.Background(), orderKey, orderRequestData).Err()
					assert.NoError(t, err, fmt.Errorf("failed to map order to a provider in Redis: %v", err))
				}

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}

				signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

				headers := map[string]string{
					"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				}

				res, err := test.PerformRequest(t, "POST", "/orders/"+testCtx.currency.ID.String()+"/decline", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusNotFound, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Order request not found or is expired", response.Message)
			})

			t.Run("when redis is not initialized", func(t *testing.T) {
				order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
					"gateway_id": uuid.New().String(),
					"provider":   testCtx.provider,
				})
				assert.NoError(t, err)

				err = db.RedisClient.FlushAll(context.Background()).Err()
				assert.NoError(t, err)

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}

				signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

				headers := map[string]string{
					"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				}

				res, err := test.PerformRequest(t, "POST", "/orders/"+order.ID.String()+"/decline", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusNotFound, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Order request not found or is expired", response.Message)

			})
		})

		t.Run("when data is accurate", func(t *testing.T) {

			order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
				"gateway_id": uuid.New().String(),
				"provider":   testCtx.provider,
			})
			assert.NoError(t, err)

			orderKey := fmt.Sprintf("order_request_%s", order.ID)

			orderRequestData := map[string]interface{}{
				"amount":      order.Amount.Mul(order.Rate).RoundBank(0).String(),
				"institution": order.Institution,
				"providerId":  testCtx.provider.ID,
			}

			if db.RedisClient != nil {
				err = db.RedisClient.HSet(context.Background(), orderKey, orderRequestData).Err()
				assert.NoError(t, err, fmt.Errorf("failed to map order to a provider in Redis: %v", err))
			}

			// Test default params
			var payload = map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "POST", "/orders/"+order.ID.String()+"/decline", payload, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Order request declined successfully", response.Message)
		})

	})

	t.Run("CancelOrder", func(t *testing.T) {

		t.Run("Invalid Request", func(t *testing.T) {

			t.Run("Invalid HMAC", func(t *testing.T) {

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}

				headers := map[string]string{
					"Authorization": "HMAC " + "testTest",
				}

				res, err := test.PerformRequest(t, "POST", "/orders/test/cancel", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusUnauthorized, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid Authorization header format", response.Message)
			})

			t.Run("Invalid API key or token", func(t *testing.T) {

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}

				headers := map[string]string{
					"Authorization": "HMAC " + "test:Test",
				}

				res, err := test.PerformRequest(t, "POST", "/orders/test/cancel", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusBadRequest, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid API key ID", response.Message)
			})

			t.Run("No Cancel Reason in cancel", func(t *testing.T) {
				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}
				signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

				headers := map[string]string{
					"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				}

				res, err := test.PerformRequest(t, "POST", "/orders/test/cancel", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusBadRequest, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Failed to validate payload", response.Message)
			})

			t.Run("Invalid Order ID", func(t *testing.T) {

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
					"reason":    "invalid",
				}

				signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

				headers := map[string]string{
					"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				}

				res, err := test.PerformRequest(t, "POST", "/orders/test/cancel", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusBadRequest, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid Order ID", response.Message)
			})

			t.Run("Order Id that doesn't Exist", func(t *testing.T) {

				order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
					"gateway_id": uuid.New().String(),
					"provider":   testCtx.provider,
				})
				assert.NoError(t, err)

				orderKey := fmt.Sprintf("order_request_%s", order.ID)

				user, err := test.CreateTestUser(map[string]interface{}{
					"email": "order_not_found4@test.com",
				})
				assert.NoError(t, err)

				providerProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
					"user_id":     user.ID,
					"currency_id": testCtx.currency.ID,
				})
				assert.NoError(t, err)

				orderRequestData := map[string]interface{}{
					"amount":      order.Amount.Mul(order.Rate).RoundBank(0).String(),
					"institution": order.Institution,
					"providerId":  providerProfile.ID,
				}

				if db.RedisClient != nil {
					err = db.RedisClient.HSet(context.Background(), orderKey, orderRequestData).Err()
					assert.NoError(t, err, fmt.Errorf("failed to map order to a provider in Redis: %v", err))
				}

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
					"reason":    "invalid",
				}

				signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

				headers := map[string]string{
					"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				}

				res, err := test.PerformRequest(t, "POST", "/orders/"+testCtx.currency.ID.String()+"/cancel", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusNotFound, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Could not find payment order", response.Message)
			})
		})

		t.Run("exclude Order For Provider", func(t *testing.T) {

			order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
				"gateway_id": uuid.New().String(),
				"provider":   testCtx.provider,
			})
			assert.NoError(t, err)

			// Create a provision bucket for the order
			provisionBucket, err := db.Client.ProvisionBucket.
				Create().
				SetMinAmount(decimal.NewFromFloat(100.0)).
				SetMaxAmount(decimal.NewFromFloat(1000.0)).
				SetCurrency(testCtx.currency).
				Save(context.Background())
			assert.NoError(t, err)

			// Add provision bucket to the order
			order, err = order.Update().
				SetProvisionBucket(provisionBucket).
				Save(context.Background())
			assert.NoError(t, err)

			orderKey := fmt.Sprintf("order_request_%s", order.ID)

			user, err := test.CreateTestUser(map[string]interface{}{
				"email": "no_providerId_user6@test.com",
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     user.ID,
				"currency_id": testCtx.currency.ID,
			})
			assert.NoError(t, err)

			orderRequestData := map[string]interface{}{
				"amount":      order.Amount.Mul(order.Rate).RoundBank(0).String(),
				"institution": order.Institution,
				"providerId":  testCtx.provider.ID, // Use the same provider as the order
			}

			if db.RedisClient != nil {
				err = db.RedisClient.HSet(context.Background(), orderKey, orderRequestData).Err()
				assert.NoError(t, err, fmt.Errorf("failed to map order to a provider in Redis: %v", err))
			}

			// Test default params
			var payload = map[string]interface{}{
				"timestamp": time.Now().Unix(),
				"reason":    "invalid",
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "POST", "/orders/"+order.ID.String()+"/cancel", payload, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Order cancelled successfully", response.Message)
		})

		t.Run("when data is accurate", func(t *testing.T) {

			order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
				"gateway_id": uuid.New().String(),
				"provider":   testCtx.provider,
			})
			assert.NoError(t, err)

			// Create a provision bucket for the order
			provisionBucket, err := db.Client.ProvisionBucket.
				Create().
				SetMinAmount(decimal.NewFromFloat(100.0)).
				SetMaxAmount(decimal.NewFromFloat(1000.0)).
				SetCurrency(testCtx.currency).
				Save(context.Background())
			assert.NoError(t, err)

			// Add provision bucket to the order
			order, err = order.Update().
				SetProvisionBucket(provisionBucket).
				Save(context.Background())
			assert.NoError(t, err)

			orderKey := fmt.Sprintf("order_request_%s", order.ID)

			orderRequestData := map[string]interface{}{
				"amount":      order.Amount.Mul(order.Rate).RoundBank(0).String(),
				"institution": order.Institution,
				"providerId":  testCtx.provider.ID,
			}

			if db.RedisClient != nil {
				err = db.RedisClient.HSet(context.Background(), orderKey, orderRequestData).Err()
				assert.NoError(t, err, fmt.Errorf("failed to map order to a provider in Redis: %v", err))
			}

			// Test default params
			var payload = map[string]interface{}{
				"timestamp": time.Now().Unix(),
				"reason":    "invalid",
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "POST", "/orders/"+order.ID.String()+"/cancel", payload, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Order cancelled successfully", response.Message)
		})

	})

	t.Run("FulfillOrder", func(t *testing.T) {
		// Ensure database schema is properly created for all subtests
		ensureDatabaseSchema(t)

		t.Run("Invalid Request", func(t *testing.T) {
			// Ensure schema is verified before running each test
			ensureDatabaseSchema(t)
			t.Run("Invalid HMAC", func(t *testing.T) {
				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}

				headers := map[string]string{
					"Authorization": "HMAC " + "testTest",
				}

				res, err := test.PerformRequest(t, "POST", "/orders/test/cancel", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusUnauthorized, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid Authorization header format", response.Message)
			})

			t.Run("Invalid API key or token", func(t *testing.T) {
				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}

				headers := map[string]string{
					"Authorization": "HMAC " + "test:Test",
				}

				res, err := test.PerformRequest(t, "POST", "/orders/test/fulfill", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusBadRequest, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid API key ID", response.Message)
			})

			t.Run("Invalid Payload", func(t *testing.T) {
				// Ensure schema is verified before the test
				ensureDatabaseSchema(t)

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
				}
				signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

				headers := map[string]string{
					"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				}

				res, err := test.PerformRequest(t, "POST", "/orders/test/fulfill", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusBadRequest, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Failed to validate payload", response.Message)
			})

			t.Run("Invalid Order ID", func(t *testing.T) {
				// Ensure schema is verified before the test
				ensureDatabaseSchema(t)

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
					"txId":      "0x1232",
					"psp":       "psp-name",
				}

				signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

				headers := map[string]string{
					"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				}

				res, err := test.PerformRequest(t, "POST", "/orders/test/fulfill", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusBadRequest, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid Order ID", response.Message)
			})

			t.Run("Order Id that doesn't Exist", func(t *testing.T) {
				// Ensure schema is verified before the test
				ensureDatabaseSchema(t)

				order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
					"gateway_id": uuid.New().String(),
					"provider":   testCtx.provider,
				})
				assert.NoError(t, err)

				orderKey := fmt.Sprintf("order_request_%s", order.ID)

				user, err := test.CreateTestUser(map[string]interface{}{
					"email": "order_not_found8@test.com",
				})
				assert.NoError(t, err)

				providerProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
					"user_id":     user.ID,
					"currency_id": testCtx.currency.ID,
				})
				assert.NoError(t, err)

				orderRequestData := map[string]interface{}{
					"amount":      order.Amount.Mul(order.Rate).RoundBank(0).String(),
					"institution": order.Institution,
					"providerId":  providerProfile.ID,
				}

				if db.RedisClient != nil {
					err = db.RedisClient.HSet(context.Background(), orderKey, orderRequestData).Err()
					assert.NoError(t, err, fmt.Errorf("failed to map order to a provider in Redis: %v", err))
				}

				// Test default params
				var payload = map[string]interface{}{
					"timestamp": time.Now().Unix(),
					"txId":      "0x1232",
					"psp":       "psp-name",
				}

				signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

				headers := map[string]string{
					"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
				}

				res, err := test.PerformRequest(t, "POST", "/orders/"+testCtx.currency.ID.String()+"/fulfill", payload, headers, router)
				assert.NoError(t, err)

				// Assert the response body
				assert.Equal(t, http.StatusInternalServerError, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Failed to update lock order status", response.Message)
			})
		})

		t.Run("when data is accurate", func(t *testing.T) {
			order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
				"gateway_id": uuid.New().String(),
				"provider":   testCtx.provider,
				"status":     "fulfilled",
			})
			assert.NoError(t, err)

			// Create a provision bucket and associate it with the order
			provisionBucket, err := test.CreateTestProvisionBucket(map[string]interface{}{
				"currency_id": testCtx.currency.ID,
				"provider_id": testCtx.provider.ID,
				"max_amount":  decimal.NewFromFloat(1000.0),
				"min_amount":  decimal.NewFromFloat(1.0),
			})
			assert.NoError(t, err)

			// Associate the provision bucket with the order
			order, err = test.AddProvisionBucketToLockPaymentOrder(order, provisionBucket.ID)
			assert.NoError(t, err)

			tx_id := "0x123" + fmt.Sprint(rand.Intn(1000000))
			_, err = test.CreateTestLockOrderFulfillment(map[string]interface{}{
				"tx_id":             tx_id,
				"psp":               "psp-name",
				"validation_status": "success",
				"orderId":           order.ID,
			})
			assert.NoError(t, err)

			// Test default params
			var payload = map[string]interface{}{
				"timestamp":        time.Now().Unix(),
				"validationStatus": "success",
				"txId":             tx_id,
				"psp":              "psp-name",
			}

			signature := token.GenerateHMACSignature(payload, testCtx.apiKeySecret)

			headers := map[string]string{
				"Authorization": "HMAC " + testCtx.apiKey.ID.String() + ":" + signature,
			}

			res, err := test.PerformRequest(t, "POST", "/orders/"+order.ID.String()+"/fulfill", payload, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Order fulfilled successfully", response.Message)
		})
	})

}
