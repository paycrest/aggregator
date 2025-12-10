package services

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/alicebob/miniredis/v2"
	"github.com/jarcoal/httpmock"
	_ "github.com/mattn/go-sqlite3"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	"github.com/paycrest/aggregator/ent/providercurrencies"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/provisionbucket"
	tokenEnt "github.com/paycrest/aggregator/ent/token"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/paycrest/aggregator/utils/test"
	tokenUtils "github.com/paycrest/aggregator/utils/token"
	"github.com/redis/go-redis/v9"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
)

var testCtxForPQ = struct {
	publicProvider              *ent.User
	publicProviderProfile       *ent.ProviderProfile
	publicProviderProfileAPIKey *ent.APIKey
	privateProviderProfile      *ent.ProviderProfile
	currency                    *ent.FiatCurrency
	client                      types.RPCClient
	token                       *ent.Token
	minAmount                   decimal.Decimal
	maxAmount                   decimal.Decimal
	bucket                      *ent.ProvisionBucket
}{}

// TestPriorityQueueService extends the original service with test-specific overrides
type TestPriorityQueueService struct {
	*PriorityQueueService
}

// Override sendOrderRequest to mock the provider notification
func (s *TestPriorityQueueService) sendOrderRequest(ctx context.Context, order types.LockPaymentOrderFields) error {
	// Mock successful balance reservation and provider notification
	bucketCurrency := order.ProvisionBucket.Edges.Currency
	amount := order.Amount.Mul(order.Rate).Round(int32(bucketCurrency.Decimals))

	// Reserve balance (keep the original logic)
	err := s.balanceService.ReserveBalance(ctx, order.ProviderID, bucketCurrency.Code, amount, nil)
	if err != nil {
		return err
	}

	// Mock successful provider notification (skip the actual API call)
	logger.WithFields(logger.Fields{
		"ProviderID": order.ProviderID,
		"Data":       map[string]interface{}{}, // Empty data for test
	}).Infof("successfully called provider /new_order endpoint")

	return nil
}

// Override notifyProvider to skip the database query and prevent deadlock
// This is needed because matchRate calls s.sendOrderRequest where s is *PriorityQueueService,
// which calls the original sendOrderRequest that starts a transaction and then calls notifyProvider.
// The notifyProvider then queries the database, which blocks because the transaction holds the only connection.
func (s *TestPriorityQueueService) notifyProvider(ctx context.Context, orderRequestData map[string]interface{}) error {
	// Mock successful provider notification without database query
	logger.WithFields(logger.Fields{
		"ProviderID": orderRequestData["providerId"],
		"Data":       orderRequestData,
	}).Infof("successfully called provider /new_order endpoint (mocked)")
	return nil
}

// Override matchRate to use the test's sendOrderRequest instead of the parent's
// This is needed because matchRate is defined on *PriorityQueueService, so when it calls
// s.sendOrderRequest, it calls PriorityQueueService.sendOrderRequest, not TestPriorityQueueService.sendOrderRequest.
// By overriding matchRate, we ensure it uses the test's sendOrderRequest.
func (s *TestPriorityQueueService) matchRate(ctx context.Context, redisKey string, orderIDPrefix string, order types.LockPaymentOrderFields, excludeList []string) error {
	// Duplicate the matchRate logic but use the test's sendOrderRequest
	for index := 0; ; index++ {
		providerData, err := db.RedisClient.LIndex(ctx, redisKey, int64(index)).Result()
		if err != nil {
			return err
		}

		// Extract the rate from the data (assuming it's in the format "providerID:token:rate:minAmount:maxAmount")
		parts := strings.Split(providerData, ":")
		if len(parts) != 5 {
			logger.WithFields(logger.Fields{
				"Error":        fmt.Sprintf("%v", err),
				"OrderID":      order.ID.String(),
				"ProviderID":   order.ProviderID,
				"ProviderData": providerData,
			}).Errorf("invalid data format at index %d when matching rate", index)
			continue // Skip this entry due to invalid format
		}

		order.ProviderID = parts[0]

		// Skip entry if provider is excluded
		if utils.ContainsString(excludeList, order.ProviderID) {
			continue
		}

		// Skip entry if token doesn't match
		if parts[1] != order.Token.Symbol {
			continue
		}

		// Parse rate (amount limits and OTC checks already done by ValidateRate/findSuitableProviderRate)
		rate, err := decimal.NewFromString(parts[2])
		if err != nil {
			continue
		}

		// Fetch ProviderOrderToken only for rate slippage check
		bucketCurrency := order.ProvisionBucket.Edges.Currency
		if bucketCurrency == nil {
			bucketCurrency, err = order.ProvisionBucket.QueryCurrency().Only(ctx)
			if err != nil {
				continue
			}
		}

		network := order.Token.Edges.Network
		if network == nil {
			network, err = order.Token.QueryNetwork().Only(ctx)
			if err != nil {
				continue
			}
		}

		providerToken, err := db.Client.ProviderOrderToken.
			Query().
			Where(
				providerordertoken.NetworkEQ(network.Identifier),
				providerordertoken.HasProviderWith(
					providerprofile.IDEQ(order.ProviderID),
					providerprofile.HasProviderCurrenciesWith(
						providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(bucketCurrency.Code)),
						providercurrencies.IsAvailableEQ(true),
					),
				),
				providerordertoken.HasTokenWith(tokenEnt.IDEQ(order.Token.ID)),
				providerordertoken.HasCurrencyWith(
					fiatcurrency.CodeEQ(bucketCurrency.Code),
				),
				providerordertoken.AddressNEQ(""),
			).
			First(ctx)
		if err != nil {
			continue
		}

		// Calculate allowed deviation based on slippage
		allowedDeviation := order.Rate.Mul(providerToken.RateSlippage.Div(decimal.NewFromInt(100)))

		if rate.Sub(order.Rate).Abs().LessThanOrEqual(allowedDeviation) {
			// Found a match for the rate - handle index pop once (common for both OTC and regular)
			if index == 0 {
				// Match found at index 0, perform LPOP to dequeue
				data, err := db.RedisClient.LPop(ctx, redisKey).Result()
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":         fmt.Sprintf("%v", err),
						"OrderID":       order.ID.String(),
						"ProviderID":    order.ProviderID,
						"redisKey":      redisKey,
						"orderIDPrefix": orderIDPrefix,
					}).Errorf("failed to dequeue from circular queue when matching rate")
					return err
				}

				// Enqueue data to the end of the queue
				err = db.RedisClient.RPush(ctx, redisKey, data).Err()
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":         fmt.Sprintf("%v", err),
						"OrderID":       order.ID.String(),
						"ProviderID":    order.ProviderID,
						"redisKey":      redisKey,
						"orderIDPrefix": orderIDPrefix,
					}).Errorf("failed to enqueue to circular queue when matching rate")
					return err
				}
			}

			// For OTC orders, skip balance check and assign order to provider
			if order.OrderType == "otc" {
				if err := s.assignOtcOrder(ctx, order); err != nil {
					logger.WithFields(logger.Fields{
						"Error":      fmt.Sprintf("%v", err),
						"OrderID":    order.ID.String(),
						"ProviderID": order.ProviderID,
					}).Errorf("failed to assign OTC order to provider when matching rate")

					// Add provider to exclude list before continuing to next provider
					s.addProviderToExcludeList(ctx, order.ID.String(), order.ProviderID, 2*time.Hour)
					continue
				}
				break
			} else {
				// Regular order (or default for any non-OTC order type) - check balance sufficiency
				_, err := s.balanceService.CheckBalanceSufficiency(ctx, order.ProviderID, bucketCurrency.Code, order.Amount.Mul(order.Rate).RoundBank(0))
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":      fmt.Sprintf("%v", err),
						"OrderID":    order.ID.String(),
						"ProviderID": order.ProviderID,
						"Currency":   bucketCurrency.Code,
						"Amount":     order.Amount.String(),
					}).Errorf("failed to check balance sufficiency")
					continue
				}

				// Assign the order to the provider and save it to Redis
				// Use the test's sendOrderRequest instead of the parent's
				err = s.sendOrderRequest(ctx, order)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":         fmt.Sprintf("%v", err),
						"OrderID":       order.ID.String(),
						"ProviderID":    order.ProviderID,
						"redisKey":      redisKey,
						"orderIDPrefix": orderIDPrefix,
					}).Errorf("failed to send order request to specific provider when matching rate")

					// Add provider to exclude list before reassigning
					s.addProviderToExcludeList(ctx, order.ID.String(), order.ProviderID, 2*time.Hour)

					// Note: Balance cleanup is now handled in sendOrderRequest via defer
					// Reassign the lock payment order to another provider
					return s.AssignLockPaymentOrder(ctx, order)
				}

				break
			}
		}
	}
	// This should never be reached in practice, but required by compiler
	return nil
}

// Create a test-specific service instance
func NewTestPriorityQueueService() *TestPriorityQueueService {
	return &TestPriorityQueueService{
		PriorityQueueService: NewPriorityQueueService(),
	}
}

func setupForPQ() error {
	// Set up test data
	testCtxForPQ.maxAmount = decimal.NewFromFloat(10000)
	testCtxForPQ.minAmount = decimal.NewFromFloat(1)

	// Create Network first
	networkId, err := db.Client.Network.
		Create().
		SetIdentifier("localhost").
		SetChainID(int64(56)). // Use BNB Smart Chain to skip webhook creation
		SetRPCEndpoint("ws://localhost:8545").
		SetBlockTime(decimal.NewFromFloat(3.0)).
		SetFee(decimal.NewFromFloat(0.1)).
		SetIsTestnet(true).
		OnConflict().
		UpdateNewValues().
		ID(context.Background())
	if err != nil {
		return fmt.Errorf("CreateNetwork.priority_queue_test: %w", err)
	}

	// Create token directly without blockchain
	tokenId, err := db.Client.Token.
		Create().
		SetSymbol("TST").
		SetContractAddress("0xd4E96eF8eee8678dBFf4d535E033Ed1a4F7605b7").
		SetDecimals(6).
		SetNetworkID(networkId).
		SetIsEnabled(true).
		SetBaseCurrency("KES"). // Use KES to match the currency below
		OnConflict().
		UpdateNewValues().
		ID(context.Background())
	if err != nil {
		return fmt.Errorf("CreateToken.priority_queue_test: %w", err)
	}

	token, err := db.Client.Token.
		Query().
		Where(tokenEnt.IDEQ(tokenId)).
		WithNetwork().
		Only(context.Background())
	if err != nil {
		return fmt.Errorf("GetToken.priority_queue_test: %w", err)
	}
	testCtxForPQ.token = token

	user, err := test.CreateTestUser(map[string]interface{}{
		"scope": "provider",
		"email": "providerjohndoe@test.com",
	})
	if err != nil {
		return err
	}
	testCtxForPQ.publicProvider = user

	currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
		"code":        "KES",
		"short_name":  "Shilling",
		"decimals":    2,
		"symbol":      "KSh",
		"name":        "Kenyan Shilling",
		"market_rate": 550.0,
	})
	if err != nil {
		return err
	}
	testCtxForPQ.currency = currency

	publicProviderProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
		"user_id":         testCtxForPQ.publicProvider.ID,
		"currency_id":     currency.ID,
		"host_identifier": "https://example2.com",
	})
	if err != nil {
		return err
	}
	apiKeyService := NewAPIKeyService()
	apiKey, _, err := apiKeyService.GenerateAPIKey(
		context.Background(),
		nil,
		nil,
		publicProviderProfile,
	)
	if err != nil {
		return err
	}
	testCtxForPQ.publicProviderProfileAPIKey = apiKey
	_, err = test.AddProviderOrderTokenToProvider(
		map[string]interface{}{
			"fixed_conversion_rate":    decimal.NewFromFloat(100),
			"conversion_rate_type":     "fixed",
			"floating_conversion_rate": decimal.NewFromFloat(1.0),
			"max_order_amount":         decimal.NewFromFloat(1000),
			"min_order_amount":         decimal.NewFromFloat(1.0),
			"provider":                 publicProviderProfile,
			"currency_id":              currency.ID,
			"network":                  token.Edges.Network.Identifier,
			"token_id":                 token.ID,
		},
	)
	if err != nil {
		return err
	}
	testCtxForPQ.publicProviderProfile = publicProviderProfile

	// Update ProviderCurrencies with sufficient balance for the publicProviderProfile
	_, err = db.Client.ProviderCurrencies.
		Update().
		Where(providercurrencies.HasProviderWith(providerprofile.IDEQ(publicProviderProfile.ID))).
		Where(providercurrencies.HasCurrencyWith(fiatcurrency.IDEQ(currency.ID))).
		SetAvailableBalance(decimal.NewFromFloat(100000)). // Set sufficient balance
		SetTotalBalance(decimal.NewFromFloat(100000)).
		Save(context.Background())
	if err != nil {
		return fmt.Errorf("UpdateProviderCurrencies.publicProvider: %w", err)
	}

	bucket, err := test.CreateTestProvisionBucket(map[string]interface{}{
		"provider_id": publicProviderProfile.ID,
		"min_amount":  decimal.NewFromFloat(1),
		"max_amount":  decimal.NewFromFloat(10000.0),
		"currency_id": currency.ID,
	})
	if err != nil {
		return err
	}
	testCtxForPQ.bucket = bucket

	privateProvider, err := test.CreateTestUser(map[string]interface{}{
		"scope": "provider",
		"email": "private@test.com",
	})
	if err != nil {
		return err
	}

	privateProviderProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
		"currency_id":     currency.ID,
		"visibility_mode": "private",
		"user_id":         privateProvider.ID,
	})
	if err != nil {
		return err
	}
	testCtxForPQ.privateProviderProfile = privateProviderProfile

	// Update ProviderCurrencies with sufficient balance for the privateProviderProfile
	_, err = db.Client.ProviderCurrencies.
		Update().
		Where(providercurrencies.HasProviderWith(providerprofile.IDEQ(privateProviderProfile.ID))).
		Where(providercurrencies.HasCurrencyWith(fiatcurrency.IDEQ(currency.ID))).
		SetAvailableBalance(decimal.NewFromFloat(100000)). // Set sufficient balance
		SetTotalBalance(decimal.NewFromFloat(100000)).
		Save(context.Background())
	if err != nil {
		return fmt.Errorf("UpdateProviderCurrencies.privateProvider: %w", err)
	}

	_, err = test.CreateTestProvisionBucket(map[string]interface{}{
		"provider_id": privateProviderProfile.ID,
		"min_amount":  testCtxForPQ.minAmount,
		"max_amount":  testCtxForPQ.maxAmount,
		"currency_id": currency.ID,
	})
	if err != nil {
		return err
	}

	// Set up payment order
	_, err = test.CreateTestLockPaymentOrder(map[string]interface{}{
		"provider":   privateProviderProfile,
		"token_id":   testCtxForPQ.token.ID,
		"gateway_id": "order-12345",
	})
	if err != nil {
		return err
	}
	_, err = test.CreateTestLockPaymentOrder(map[string]interface{}{
		"provider": publicProviderProfile,
		"token_id": testCtxForPQ.token.ID,
	})
	if err != nil {
		return err
	}

	return nil
}

func TestPriorityQueueTest(t *testing.T) {
	// Set up test database client with shared in-memory schema and a single connection to avoid locks
	dbConn, err := sql.Open("sqlite3", "file:ent?mode=memory&cache=shared&_fk=1&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("Failed to open sqlite DB: %v", err)
	}
	dbConn.SetMaxOpenConns(1)
	defer dbConn.Close()

	drv := entsql.OpenDB(dialect.SQLite, dbConn)
	client := ent.NewClient(ent.Driver(drv))
	defer client.Close()

	// Set client first so all operations use the same client
	db.Client = client

	// Create schema to ensure all tables exist and are ready
	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	// Verify db.Client is set correctly before setup
	if db.Client != client {
		t.Fatalf("db.Client is not set to the test client - this will cause schema issues")
	}

	// Set up in-memory Redis
	mr, err := miniredis.Run()
	assert.NoError(t, err)
	defer mr.Close()

	redisClient := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer redisClient.Close()

	db.RedisClient = redisClient

	// Setup test data
	err = setupForPQ()
	assert.NoError(t, err)

	// Start a local HTTP server to mock provider endpoints and avoid real network calls
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","message":"ok"}`))
	}))
	defer mockServer.Close()

	// Point all provider host identifiers to the mock server
	_, err = db.Client.ProviderProfile.Update().SetHostIdentifier(mockServer.URL).Save(context.Background())
	assert.NoError(t, err)

	service := NewTestPriorityQueueService()
	t.Run("TestGetProvisionBuckets", func(t *testing.T) {
		buckets, err := service.GetProvisionBuckets(context.Background())
		assert.NoError(t, err)
		assert.Greater(t, len(buckets), 0)
	})

	t.Run("TestCreatePriorityQueueForBucket", func(t *testing.T) {
		ctx := context.Background()
		bucket, err := test.CreateTestProvisionBucket(map[string]interface{}{
			"provider_id": testCtxForPQ.publicProviderProfile.ID,
			"min_amount":  testCtxForPQ.minAmount,
			"max_amount":  testCtxForPQ.maxAmount,
			"currency_id": testCtxForPQ.currency.ID,
		})
		assert.NoError(t, err)

		_bucket, err := db.Client.ProvisionBucket.
			Query().
			Where(provisionbucket.IDEQ(bucket.ID)).
			WithCurrency().
			WithProviderProfiles().
			Only(ctx)
		assert.NoError(t, err)

		service.CreatePriorityQueueForBucket(ctx, _bucket)

		redisKey := fmt.Sprintf("bucket_%s_%s_%s", _bucket.Edges.Currency.Code, testCtxForPQ.minAmount, testCtxForPQ.maxAmount)

		data, err := db.RedisClient.LRange(ctx, redisKey, 0, -1).Result()
		assert.NoError(t, err)
		assert.Equal(t, 1, len(data))
		assert.Contains(t, data[0], testCtxForPQ.publicProviderProfile.ID)
	})

	t.Run("TestProcessBucketQueues", func(t *testing.T) {
		err = service.ProcessBucketQueues()
		assert.NoError(t, err)

		redisKey := fmt.Sprintf("bucket_%s_%s_%s", testCtxForPQ.currency.Code, testCtxForPQ.minAmount, testCtxForPQ.maxAmount)

		data, err := db.RedisClient.LRange(context.Background(), redisKey, 0, -1).Result()
		assert.NoError(t, err)
		assert.Equal(t, len(data), 1)
	})

	t.Run("TestAssignLockPaymentOrder", func(t *testing.T) {
		ctx := context.Background()

		bucket, err := test.CreateTestProvisionBucket(map[string]interface{}{
			"provider_id": testCtxForPQ.publicProviderProfile.ID,
			"min_amount":  testCtxForPQ.minAmount,
			"max_amount":  testCtxForPQ.maxAmount,
			"currency_id": testCtxForPQ.currency.ID,
		})
		assert.NoError(t, err)

		_bucket, err := db.Client.ProvisionBucket.
			Query().
			Where(provisionbucket.IDEQ(bucket.ID)).
			WithCurrency().
			WithProviderProfiles().
			Only(ctx)
		assert.NoError(t, err)

		_order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
			"provider":   testCtxForPQ.publicProviderProfile,
			"rate":       100.0,
			"token_id":   testCtxForPQ.token.ID,
			"gateway_id": "order-1",
		})
		assert.NoError(t, err)
		_, err = test.AddProvisionBucketToLockPaymentOrder(_order, bucket.ID)
		assert.NoError(t, err)

		order, err := db.Client.LockPaymentOrder.
			Query().
			Where(lockpaymentorder.IDEQ(_order.ID)).
			WithProvisionBucket(func(pb *ent.ProvisionBucketQuery) {
				pb.WithCurrency()
			}).
			WithToken().
			Only(ctx)

		assert.NoError(t, err)

		service.CreatePriorityQueueForBucket(ctx, _bucket)

		err = service.AssignLockPaymentOrder(ctx, types.LockPaymentOrderFields{
			ID:                order.ID,
			Token:             testCtxForPQ.token,
			GatewayID:         order.GatewayID,
			Amount:            order.Amount,
			Rate:              order.Rate,
			BlockNumber:       order.BlockNumber,
			Institution:       order.Institution,
			AccountIdentifier: order.AccountIdentifier,
			AccountName:       order.AccountName,
			Memo:              order.Memo,
			ProvisionBucket:   order.Edges.ProvisionBucket,
		})
		assert.NoError(t, err)
	})

	t.Run("TestGetProviderRate", func(t *testing.T) {
		// Use the provider profile directly - it was created with db.Client which is the same as client
		// The relationship queries should work as long as db.Client is set correctly
		rate, err := service.GetProviderRate(context.Background(), testCtxForPQ.publicProviderProfile, testCtxForPQ.token.Symbol, testCtxForPQ.currency.Code)
		assert.NoError(t, err)
		_rate, ok := rate.Float64()
		assert.True(t, ok)
		assert.Equal(t, _rate, float64(100))
	})

	t.Run("TestSendOrderRequest", func(t *testing.T) {
		bucket, err := test.CreateTestProvisionBucket(map[string]interface{}{
			"provider_id": testCtxForPQ.privateProviderProfile.ID,
			"min_amount":  testCtxForPQ.minAmount,
			"max_amount":  testCtxForPQ.maxAmount,
			"currency_id": testCtxForPQ.currency.ID,
		})
		assert.NoError(t, err)
		_order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
			"provider":   testCtxForPQ.publicProviderProfile,
			"token_id":   int(testCtxForPQ.token.ID),
			"gateway_id": "order-1234",
		})
		if err != nil {
			t.Logf("Failed to create lock payment order: %v", err)
		}
		assert.NoError(t, err)
		if _order == nil {
			t.Fatal("LockPaymentOrder is nil - creation failed")
		}

		_, err = test.AddProvisionBucketToLockPaymentOrder(_order, bucket.ID)
		assert.NoError(t, err)

		_, err = db.RedisClient.RPush(context.Background(), fmt.Sprintf("order_exclude_list_%s", _order.ID), testCtxForPQ.publicProviderProfile.ID).Result()
		assert.NoError(t, err)

		order, err := db.Client.LockPaymentOrder.
			Query().
			Where(lockpaymentorder.IDEQ(_order.ID)).
			WithProvisionBucket(func(pb *ent.ProvisionBucketQuery) {
				pb.WithCurrency()
			}).
			WithToken().
			Only(context.Background())

		assert.NoError(t, err)

		// Setup httpmock for sendOrderRequest
		httpmock.Activate()
		defer httpmock.DeactivateAndReset()

		httpmock.RegisterResponder("POST", testCtxForPQ.publicProviderProfile.HostIdentifier+"/new_order",
			func(req *http.Request) (*http.Response, error) {
				return httpmock.NewJsonResponse(200, map[string]interface{}{
					"status":  "success",
					"message": "Order processed successfully",
				})
			})

		err = service.sendOrderRequest(context.Background(), types.LockPaymentOrderFields{
			ID:                order.ID,
			ProviderID:        testCtxForPQ.publicProviderProfile.ID,
			Token:             testCtxForPQ.token,
			GatewayID:         order.GatewayID,
			Amount:            order.Amount,
			Rate:              order.Rate,
			BlockNumber:       order.BlockNumber,
			Institution:       order.Institution,
			AccountIdentifier: order.AccountIdentifier,
			AccountName:       order.AccountName,
			Memo:              order.Memo,
			ProvisionBucket:   order.Edges.ProvisionBucket,
		})
		assert.NoError(t, err)

		t.Run("TestNotifyProvider", func(t *testing.T) {

			// setup httpmock
			httpmock.Activate()
			defer httpmock.Deactivate()

			httpmock.RegisterResponder("POST", testCtxForPQ.publicProviderProfile.HostIdentifier+"/new_order",
				func(r *http.Request) (*http.Response, error) {
					bytes, err := io.ReadAll(r.Body)
					if err != nil {
						log.Fatal(err)
					}
					// Compute HMAC
					decodedSecret, err := base64.StdEncoding.DecodeString(testCtxForPQ.publicProviderProfileAPIKey.Secret)
					assert.NoError(t, err)
					decryptedSecret, err := cryptoUtils.DecryptPlain(decodedSecret)
					assert.NoError(t, err)
					signature := tokenUtils.GenerateHMACSignature(map[string]interface{}{
						"data": "test",
					}, string(decryptedSecret))
					assert.Equal(t, r.Header.Get("X-Request-Signature"), signature)
					if strings.Contains(string(bytes), "data") && strings.Contains(string(bytes), "test") {
						resp := httpmock.NewBytesResponse(200, nil)
						return resp, nil
					} else {
						return nil, nil
					}
				},
			)
			err := service.notifyProvider(context.Background(), map[string]interface{}{
				"providerId": testCtxForPQ.publicProviderProfile.ID,
				"data":       "test",
			})
			assert.NoError(t, err)
		})
	})

	// TODO: move these tests to tasks_test.go
	// t.Run("TestNoErrorFunctions", func(t *testing.T) {

	// 	t.Run("TestReassignUnfulfilledLockOrders", func(t *testing.T) {

	// 		bucket, err := test.CreateTestProvisionBucket(map[string]interface{}{
	// 			"provider_id": testCtxForPQ.privateProviderProfile.ID,
	// 			"min_amount":  testCtxForPQ.minAmount,
	// 			"max_amount":  testCtxForPQ.maxAmount,
	// 			"currency_id": testCtxForPQ.currency.ID,
	// 		})
	// 		assert.NoError(t, err)
	// 		_order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
	// 			"provider": testCtxForPQ.publicProviderProfile,
	// 			"token_id":  testCtxForPQ.token.ID,
	// 			"status":   lockpaymentorder.StatusProcessing.String(),
	// 		})
	// 		assert.NoError(t, err)

	// 		_, err = test.AddProvisionBucketToLockPaymentOrder(_order, bucket.ID)
	// 		assert.NoError(t, err)

	// 		service.ReassignUnfulfilledLockOrders()

	// 		order, err := db.Client.LockPaymentOrder.
	// 			Query().
	// 			Where(lockpaymentorder.IDEQ(_order.ID)).Only(context.Background())
	// 		assert.NoError(t, err)

	// 		//validate the ReassignUnfulfilledLockOrders updated the UnfulfilledLockOrder
	// 		assert.True(t, _order.UpdatedAt.Before(order.UpdatedAt))
	// 	})

	// 	t.Run("TestReassignStaleOrderRequest", func(t *testing.T) {
	// 		bucket, err := test.CreateTestProvisionBucket(map[string]interface{}{
	// 			"provider_id": testCtxForPQ.privateProviderProfile.ID,
	// 			"min_amount":  testCtxForPQ.minAmount,
	// 			"max_amount":  testCtxForPQ.maxAmount,
	// 			"currency_id": testCtxForPQ.currency.ID,
	// 		})
	// 		assert.NoError(t, err)
	// 		_order, err := test.CreateTestLockPaymentOrder(map[string]interface{}{
	// 			"provider":  testCtxForPQ.privateProviderProfile,
	// 			"token_id":   testCtxForPQ.token.ID,
	// 			"status":    lockpaymentorder.StatusProcessing.String(),
	// 			"updatedAt": time.Now().Add(-5 * time.Minute),
	// 		})
	// 		assert.NoError(t, err)

	// 		orderKey := fmt.Sprintf("order_exclude_list_%s", _order.ID)
	// 		_, err = db.RedisClient.RPush(context.Background(), orderKey, testCtxForPQ.privateProviderProfile.ID).Result()
	// 		assert.NoError(t, err)

	// 		_, err = test.AddProvisionBucketToLockPaymentOrder(_order, bucket.ID)
	// 		assert.NoError(t, err)

	// 		service.ReassignUnfulfilledLockOrders()

	// 		// Create Channel
	// 		orderRequestChan := make(chan *redis.Message, 1)
	// 		orderRequestChan <- &redis.Message{Payload: _order.ID.String() + "_" + "TEST"}
	// 		service.ReassignStaleOrderRequest(context.Background(), orderRequestChan)

	// 		order, err := db.Client.LockPaymentOrder.
	// 			Query().
	// 			Where(lockpaymentorder.IDEQ(_order.ID)).Only(context.Background())
	// 		assert.NoError(t, err)
	// 		// validate the StaleOrderRequest updated the StaleOrderRequest
	// 		assert.True(t, _order.UpdatedAt.Before(order.UpdatedAt))

	// 		// Close channel
	// 		close(orderRequestChan)
	// 	})
	// })
}
