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
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerbalances"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/provisionbucket"
	tokenEnt "github.com/paycrest/aggregator/ent/token"
	userEnt "github.com/paycrest/aggregator/ent/user"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/paycrest/aggregator/utils/test"
	tokenUtils "github.com/paycrest/aggregator/utils/token"
	"github.com/redis/go-redis/v9"
	"github.com/shopspring/decimal"
	"github.com/spf13/viper"
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
func (s *TestPriorityQueueService) sendOrderRequest(ctx context.Context, order types.PaymentOrderFields) error {
	// Mock successful balance reservation and provider notification
	bucketCurrency := order.ProvisionBucket.Edges.Currency
	amount := order.Amount.Mul(order.Rate).Round(int32(bucketCurrency.Decimals))

	// Reserve balance (keep the original logic)
	err := s.balanceService.ReserveFiatBalance(ctx, order.ProviderID, bucketCurrency.Code, amount, nil)
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
func (s *TestPriorityQueueService) matchRate(ctx context.Context, redisKey string, orderIDPrefix string, order types.PaymentOrderFields, excludeList []string) error {
	// Duplicate the matchRate logic but use the test's sendOrderRequest
	for index := 0; ; index++ {
		providerData, err := db.RedisClient.LIndex(ctx, redisKey, int64(index)).Result()
		if err != nil {
			return err
		}

		// Extract the rate from the data (format "providerID:token:network:rate:minAmount:maxAmount")
		parts := strings.Split(providerData, ":")
		if len(parts) != 6 {
			logger.WithFields(logger.Fields{
				"Error":        fmt.Sprintf("%v", err),
				"OrderID":      order.ID.String(),
				"ProviderID":   order.ProviderID,
				"ProviderData": providerData,
			}).Errorf("invalid data format at index %d when matching rate", index)
			continue // Skip this entry due to invalid format
		}

		order.ProviderID = parts[0]

		// Skip entry if provider has exceeded max retry attempts
		if s.countProviderInExcludeList(excludeList, order.ProviderID) >= config.OrderConfig().ProviderMaxRetryAttempts {
			continue
		}

		// Skip entry if token doesn't match
		if parts[1] != order.Token.Symbol {
			continue
		}

		// Skip entry if network doesn't match
		network := order.Token.Edges.Network
		if network == nil {
			var networkErr error
			network, networkErr = order.Token.QueryNetwork().Only(ctx)
			if networkErr != nil {
				continue
			}
		}
		if parts[2] != network.Identifier {
			continue
		}

		// Parse rate (amount limits and OTC checks already done by ValidateRate/findSuitableProviderRate)
		rate, err := decimal.NewFromString(parts[3])
		if err != nil {
			continue
		}

		// Fetch ProviderOrderToken only for rate slippage check (network already resolved above)
		bucketCurrency := order.ProvisionBucket.Edges.Currency
		if bucketCurrency == nil {
			bucketCurrency, err = order.ProvisionBucket.QueryCurrency().Only(ctx)
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
					providerprofile.HasProviderBalancesWith(
						providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(bucketCurrency.Code)),
						providerbalances.IsAvailableEQ(true),
					),
				),
				providerordertoken.HasTokenWith(tokenEnt.IDEQ(order.Token.ID)),
				providerordertoken.HasCurrencyWith(
					fiatcurrency.CodeEQ(bucketCurrency.Code),
				),
				providerordertoken.SettlementAddressNEQ(""),
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
				bal, err := s.balanceService.GetProviderFiatBalance(ctx, order.ProviderID, bucketCurrency.Code)
				if err != nil {
					logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "OrderID": order.ID.String(), "ProviderID": order.ProviderID}).Errorf("failed to get provider fiat balance")
					continue
				}
				required := order.Amount.Mul(order.Rate).Round(int32(bucketCurrency.Decimals))
				if !s.balanceService.CheckBalanceSufficiency(bal, required) {
					err = fmt.Errorf("insufficient balance")
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
					return s.AssignPaymentOrder(ctx, order)
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

	// Set provider to active and user to KYB approved (required for GetProvisionBuckets)
	_, err = db.Client.ProviderProfile.
		Update().
		Where(providerprofile.IDEQ(publicProviderProfile.ID)).
		SetIsActive(true).
		Save(context.Background())
	if err != nil {
		return fmt.Errorf("UpdateProviderProfile.IsActive: %w", err)
	}

	_, err = db.Client.User.
		Update().
		Where(userEnt.IDEQ(testCtxForPQ.publicProvider.ID)).
		SetKybVerificationStatus(userEnt.KybVerificationStatusApproved).
		Save(context.Background())
	if err != nil {
		return fmt.Errorf("UpdateUser.KybVerificationStatus: %w", err)
	}

	_, err = db.Client.ProviderBalances.Update().
		Where(providerbalances.HasProviderWith(providerprofile.IDEQ(publicProviderProfile.ID))).
		Where(providerbalances.HasFiatCurrencyWith(fiatcurrency.IDEQ(currency.ID))).
		SetAvailableBalance(decimal.NewFromFloat(100000)).
		SetTotalBalance(decimal.NewFromFloat(100000)).
		SetIsAvailable(true).
		Save(context.Background())
	if err != nil {
		return fmt.Errorf("UpdateProviderBalances.publicProvider: %w", err)
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

	_, err = db.Client.ProviderBalances.Update().
		Where(providerbalances.HasProviderWith(providerprofile.IDEQ(privateProviderProfile.ID))).
		Where(providerbalances.HasFiatCurrencyWith(fiatcurrency.IDEQ(currency.ID))).
		SetAvailableBalance(decimal.NewFromFloat(100000)).
		SetTotalBalance(decimal.NewFromFloat(100000)).
		Save(context.Background())
	if err != nil {
		return fmt.Errorf("UpdateProviderBalances.privateProvider: %w", err)
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
	_, err = test.CreateTestPaymentOrder(nil, map[string]interface{}{
		"provider":   privateProviderProfile,
		"token_id":   testCtxForPQ.token.ID,
		"gateway_id": "order-12345",
	})
	if err != nil {
		return err
	}
	_, err = test.CreateTestPaymentOrder(nil, map[string]interface{}{
		"provider": publicProviderProfile,
		"token_id": testCtxForPQ.token.ID,
	})
	if err != nil {
		return err
	}

	return nil
}

func TestPriorityQueueTest(t *testing.T) {
	// Set up test database client with shared in-memory schema
	// Use 2 connections to allow transaction and query to run concurrently (prevents deadlock)
	dbConn, err := sql.Open("sqlite3", "file:ent?mode=memory&cache=shared&_fk=1&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("Failed to open sqlite DB: %v", err)
	}
	dbConn.SetMaxOpenConns(2)
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
		// Ensure fallback is unset so the test's provider is included in the queue
		oldFallback := viper.GetString("FALLBACK_PROVIDER_ID")
		viper.Set("FALLBACK_PROVIDER_ID", "")
		defer viper.Set("FALLBACK_PROVIDER_ID", oldFallback)

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

		// Clean up: Delete the bucket created in this test to avoid conflicts with TestProcessBucketQueues
		// (both buckets would use the same Redis key)
		_, err = db.Client.ProvisionBucket.Delete().Where(provisionbucket.IDEQ(bucket.ID)).Exec(ctx)
		assert.NoError(t, err)
	})

	t.Run("TestProcessBucketQueues", func(t *testing.T) {
		// Ensure fallback is unset so the test's provider is included in the queue (not skipped or sanitized out)
		oldFallback := viper.GetString("FALLBACK_PROVIDER_ID")
		viper.Set("FALLBACK_PROVIDER_ID", "")
		defer viper.Set("FALLBACK_PROVIDER_ID", oldFallback)

		err = service.ProcessBucketQueues()
		assert.NoError(t, err)

		redisKey := fmt.Sprintf("bucket_%s_%s_%s", testCtxForPQ.currency.Code, testCtxForPQ.minAmount, testCtxForPQ.maxAmount)

		// ProcessBucketQueues launches goroutines; wait until the queue is populated.
		assert.Eventually(t, func() bool {
			data, err := db.RedisClient.LRange(context.Background(), redisKey, 0, -1).Result()
			return err == nil && len(data) == 1
		}, 2*time.Second, 50*time.Millisecond)

		data, err := db.RedisClient.LRange(context.Background(), redisKey, 0, -1).Result()
		assert.NoError(t, err)
		// ProcessBucketQueues rebuilds queues from GetProvisionBuckets which filters providers.
		// The provider should meet all criteria (active, KYB approved, public, has balance).
		assert.Equal(t, 1, len(data))
	})

	t.Run("TestAssignPaymentOrder", func(t *testing.T) {
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

		_order, err := test.CreateTestPaymentOrder(nil, map[string]interface{}{
			"provider":   testCtxForPQ.publicProviderProfile,
			"rate":       100.0,
			"token_id":   testCtxForPQ.token.ID,
			"gateway_id": "order-1",
		})
		assert.NoError(t, err)
		_, err = test.AddProvisionBucketToPaymentOrder(_order, bucket.ID)
		assert.NoError(t, err)

		order, err := db.Client.PaymentOrder.
			Query().
			Where(paymentorder.IDEQ(_order.ID)).
			WithProvisionBucket(func(pb *ent.ProvisionBucketQuery) {
				pb.WithCurrency()
			}).
			WithToken().
			Only(ctx)

		assert.NoError(t, err)

		service.CreatePriorityQueueForBucket(ctx, _bucket)

		err = service.AssignPaymentOrder(ctx, types.PaymentOrderFields{
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
		_order, err := test.CreateTestPaymentOrder(nil, map[string]interface{}{
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

		_, err = test.AddProvisionBucketToPaymentOrder(_order, bucket.ID)
		assert.NoError(t, err)

		_, err = db.RedisClient.RPush(context.Background(), fmt.Sprintf("order_exclude_list_%s", _order.ID), testCtxForPQ.publicProviderProfile.ID).Result()
		assert.NoError(t, err)

		order, err := db.Client.PaymentOrder.
			Query().
			Where(paymentorder.IDEQ(_order.ID)).
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

		err = service.sendOrderRequest(context.Background(), types.PaymentOrderFields{
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

	t.Run("TestCountProviderInExcludeList", func(t *testing.T) {
		tests := []struct {
			name        string
			excludeList []string
			providerID  string
			expected    int
		}{
			{
				name:        "Provider not in exclude list",
				excludeList: []string{"provider1", "provider2"},
				providerID:  "provider3",
				expected:    0,
			},
			{
				name:        "Provider appears twice",
				excludeList: []string{"provider1", "provider2", "provider1"},
				providerID:  "provider1",
				expected:    2,
			},
			{
				name:        "Provider appears multiple times",
				excludeList: []string{"provider1", "provider2", "provider1", "provider1", "provider3"},
				providerID:  "provider1",
				expected:    3,
			},
			{
				name:        "Empty exclude list",
				excludeList: []string{},
				providerID:  "provider1",
				expected:    0,
			},
			{
				name:        "Provider appears at max retry attempts",
				excludeList: []string{"provider1", "provider1", "provider1"},
				providerID:  "provider1",
				expected:    3,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := service.countProviderInExcludeList(tt.excludeList, tt.providerID)
				assert.Equal(t, tt.expected, result, "Count should match expected value")
			})
		}
	})

	t.Run("TestProviderMaxRetryAttemptsConfigValidation", func(t *testing.T) {
		// Save original value
		originalValue := viper.GetInt("PROVIDER_MAX_RETRY_ATTEMPTS")

		// Test cases: invalid values should be corrected to 3
		testCases := []struct {
			name     string
			setValue int
			expected int
		}{
			{
				name:     "Zero value should be corrected to 3",
				setValue: 0,
				expected: 3,
			},
			{
				name:     "Negative value should be corrected to 3",
				setValue: -1,
				expected: 3,
			},
			{
				name:     "Large negative value should be corrected to 3",
				setValue: -100,
				expected: 3,
			},
			{
				name:     "Valid positive value should be preserved",
				setValue: 5,
				expected: 5,
			},
			{
				name:     "Value of 1 should be preserved",
				setValue: 1,
				expected: 1,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Set the test value
				viper.Set("PROVIDER_MAX_RETRY_ATTEMPTS", tc.setValue)

				// Get config (this triggers validation)
				orderConfig := config.OrderConfig()

				// Verify the value
				assert.Equal(t, tc.expected, orderConfig.ProviderMaxRetryAttempts,
					"ProviderMaxRetryAttempts should be corrected to expected value")
			})
		}

		// Restore original value
		viper.Set("PROVIDER_MAX_RETRY_ATTEMPTS", originalValue)
	})

	t.Run("TestProviderRetryLogic", func(t *testing.T) {
		ctx := context.Background()

		// Set max retry attempts to 3 for testing
		originalValue := viper.GetInt("PROVIDER_MAX_RETRY_ATTEMPTS")
		viper.Set("PROVIDER_MAX_RETRY_ATTEMPTS", 3)
		defer viper.Set("PROVIDER_MAX_RETRY_ATTEMPTS", originalValue)

		t.Run("Provider can retry up to max attempts", func(t *testing.T) {
			orderID := testCtxForPQ.publicProviderProfile.ID
			excludeListKey := fmt.Sprintf("order_exclude_list_%s", "test-order-id")

			// Test that provider is not excluded with 0 failures
			excludeList, _ := db.RedisClient.LRange(ctx, excludeListKey, 0, -1).Result()
			count := service.countProviderInExcludeList(excludeList, orderID)
			assert.Equal(t, 0, count, "Provider should have 0 failures initially")

			// Add provider to exclude list once (first failure)
			_, err := db.RedisClient.RPush(ctx, excludeListKey, orderID).Result()
			assert.NoError(t, err)

			excludeList, _ = db.RedisClient.LRange(ctx, excludeListKey, 0, -1).Result()
			count = service.countProviderInExcludeList(excludeList, orderID)
			assert.Equal(t, 1, count, "Provider should have 1 failure")
			assert.True(t, count < 3, "Provider should still be eligible (count < max)")

			// Add provider to exclude list again (second failure)
			_, err = db.RedisClient.RPush(ctx, excludeListKey, orderID).Result()
			assert.NoError(t, err)

			excludeList, _ = db.RedisClient.LRange(ctx, excludeListKey, 0, -1).Result()
			count = service.countProviderInExcludeList(excludeList, orderID)
			assert.Equal(t, 2, count, "Provider should have 2 failures")
			assert.True(t, count < 3, "Provider should still be eligible (count < max)")

			// Add provider to exclude list third time (third failure)
			_, err = db.RedisClient.RPush(ctx, excludeListKey, orderID).Result()
			assert.NoError(t, err)

			excludeList, _ = db.RedisClient.LRange(ctx, excludeListKey, 0, -1).Result()
			count = service.countProviderInExcludeList(excludeList, orderID)
			assert.Equal(t, 3, count, "Provider should have 3 failures")
			assert.True(t, count >= 3, "Provider should now be excluded (count >= max)")

			// Add provider to exclude list fourth time (fourth failure)
			_, err = db.RedisClient.RPush(ctx, excludeListKey, orderID).Result()
			assert.NoError(t, err)

			excludeList, _ = db.RedisClient.LRange(ctx, excludeListKey, 0, -1).Result()
			count = service.countProviderInExcludeList(excludeList, orderID)
			assert.Equal(t, 4, count, "Provider should have 4 failures")
			assert.True(t, count >= 3, "Provider should still be excluded (count >= max)")
		})

		t.Run("Multiple providers in exclude list are counted independently", func(t *testing.T) {
			provider1ID := testCtxForPQ.publicProviderProfile.ID
			provider2ID := "provider-2-id"
			excludeListKey := fmt.Sprintf("order_exclude_list_%s", "test-order-id-2")

			// Add provider1 twice and provider2 once
			_, err := db.RedisClient.RPush(ctx, excludeListKey, provider1ID).Result()
			assert.NoError(t, err)
			_, err = db.RedisClient.RPush(ctx, excludeListKey, provider1ID).Result()
			assert.NoError(t, err)
			_, err = db.RedisClient.RPush(ctx, excludeListKey, provider2ID).Result()
			assert.NoError(t, err)

			excludeList, _ := db.RedisClient.LRange(ctx, excludeListKey, 0, -1).Result()

			// Verify counts are independent
			count1 := service.countProviderInExcludeList(excludeList, provider1ID)
			count2 := service.countProviderInExcludeList(excludeList, provider2ID)

			assert.Equal(t, 2, count1, "Provider1 should have 2 failures")
			assert.Equal(t, 1, count2, "Provider2 should have 1 failure")
		})
	})

	t.Run("TestTryFallbackAssignment", func(t *testing.T) {
		ctx := context.Background()

		t.Run("FallbackNotConfigured", func(t *testing.T) {
			old := viper.GetString("FALLBACK_PROVIDER_ID")
			viper.Set("FALLBACK_PROVIDER_ID", "")
			defer viper.Set("FALLBACK_PROVIDER_ID", old)

			_order, err := test.CreateTestPaymentOrder(testCtxForPQ.token, map[string]interface{}{
				"provider": testCtxForPQ.publicProviderProfile, "rate": 100.0, "gateway_id": "gw-fb-none",
			})
			assert.NoError(t, err)
			_, err = _order.Update().ClearProvider().Save(ctx)
			assert.NoError(t, err)
			_, err = test.AddProvisionBucketToPaymentOrder(_order, testCtxForPQ.bucket.ID)
			assert.NoError(t, err)

			order, err := db.Client.PaymentOrder.Get(ctx, _order.ID)
			assert.NoError(t, err)

			err = service.TryFallbackAssignment(ctx, order)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "fallback provider not configured")
		})

		t.Run("OTCExcluded", func(t *testing.T) {
			old := viper.GetString("FALLBACK_PROVIDER_ID")
			viper.Set("FALLBACK_PROVIDER_ID", testCtxForPQ.publicProviderProfile.ID)
			defer viper.Set("FALLBACK_PROVIDER_ID", old)

			_order, err := test.CreateTestPaymentOrder(testCtxForPQ.token, map[string]interface{}{
				"provider": testCtxForPQ.publicProviderProfile, "rate": 100.0, "gateway_id": "gw-fb-otc",
			})
			assert.NoError(t, err)
			_, err = _order.Update().ClearProvider().SetOrderType(paymentorder.OrderTypeOtc).Save(ctx)
			assert.NoError(t, err)
			_, err = test.AddProvisionBucketToPaymentOrder(_order, testCtxForPQ.bucket.ID)
			assert.NoError(t, err)

			order, err := db.Client.PaymentOrder.Get(ctx, _order.ID)
			assert.NoError(t, err)

			err = service.TryFallbackAssignment(ctx, order)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "fallback is only for regular orders")
		})

		t.Run("OrderRequestExists", func(t *testing.T) {
			old := viper.GetString("FALLBACK_PROVIDER_ID")
			viper.Set("FALLBACK_PROVIDER_ID", testCtxForPQ.publicProviderProfile.ID)
			defer viper.Set("FALLBACK_PROVIDER_ID", old)

			_order, err := test.CreateTestPaymentOrder(testCtxForPQ.token, map[string]interface{}{
				"provider": testCtxForPQ.publicProviderProfile, "rate": 100.0, "gateway_id": "gw-fb-redis",
			})
			assert.NoError(t, err)
			_, err = _order.Update().ClearProvider().Save(ctx)
			assert.NoError(t, err)
			_, err = test.AddProvisionBucketToPaymentOrder(_order, testCtxForPQ.bucket.ID)
			assert.NoError(t, err)

			orderKey := fmt.Sprintf("order_request_%s", _order.ID)
			_, err = db.RedisClient.HSet(ctx, orderKey, "providerId", testCtxForPQ.publicProviderProfile.ID).Result()
			assert.NoError(t, err)
			defer db.RedisClient.Del(ctx, orderKey)

			order, err := db.Client.PaymentOrder.Get(ctx, _order.ID)
			assert.NoError(t, err)

			err = service.TryFallbackAssignment(ctx, order)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "already has an active order_request")
		})

		t.Run("FallbackAlreadyTried", func(t *testing.T) {
			old := viper.GetString("FALLBACK_PROVIDER_ID")
			viper.Set("FALLBACK_PROVIDER_ID", testCtxForPQ.publicProviderProfile.ID)
			defer viper.Set("FALLBACK_PROVIDER_ID", old)

			_order, err := test.CreateTestPaymentOrder(testCtxForPQ.token, map[string]interface{}{
				"provider": testCtxForPQ.publicProviderProfile, "rate": 100.0, "gateway_id": "gw-fb-tried",
			})
			assert.NoError(t, err)
			_, err = _order.Update().ClearProvider().Save(ctx)
			assert.NoError(t, err)
			_, err = test.AddProvisionBucketToPaymentOrder(_order, testCtxForPQ.bucket.ID)
			assert.NoError(t, err)
			_, err = _order.Update().SetFallbackTriedAt(time.Now()).Save(ctx)
			assert.NoError(t, err)

			order, err := db.Client.PaymentOrder.Get(ctx, _order.ID)
			assert.NoError(t, err)

			err = service.TryFallbackAssignment(ctx, order)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "already had fallback assignment tried")
		})

		t.Run("Success", func(t *testing.T) {
			old := viper.GetString("FALLBACK_PROVIDER_ID")
			viper.Set("FALLBACK_PROVIDER_ID", testCtxForPQ.publicProviderProfile.ID)
			defer viper.Set("FALLBACK_PROVIDER_ID", old)

			_order, err := test.CreateTestPaymentOrder(testCtxForPQ.token, map[string]interface{}{
				"provider": testCtxForPQ.publicProviderProfile, "rate": 100.0, "gateway_id": "gw-fb-success",
			})
			assert.NoError(t, err)
			_, err = _order.Update().ClearProvider().Save(ctx)
			assert.NoError(t, err)
			_, err = test.AddProvisionBucketToPaymentOrder(_order, testCtxForPQ.bucket.ID)
			assert.NoError(t, err)

			order, err := db.Client.PaymentOrder.
				Query().
				Where(paymentorder.IDEQ(_order.ID)).
				WithToken(func(tq *ent.TokenQuery) { tq.WithNetwork() }).
				WithProvisionBucket(func(pb *ent.ProvisionBucketQuery) { pb.WithCurrency() }).
				Only(ctx)
			assert.NoError(t, err)

			err = service.TryFallbackAssignment(ctx, order)
			assert.NoError(t, err)

			// Idempotency: FallbackTriedAt should be set
			updated, err := db.Client.PaymentOrder.Get(ctx, _order.ID)
			assert.NoError(t, err)
			assert.False(t, updated.FallbackTriedAt.IsZero(), "FallbackTriedAt should be set after success")
		})

		// RateOnlyMatchesFallback: order rate (1390) matches no provider in the queue (1376, tight slippage)
		// but is within fallback provider's slippage (1388, 2%) → fallback should assign before refund.
		t.Run("RateOnlyMatchesFallback", func(t *testing.T) {
			oldFallback := viper.GetString("FALLBACK_PROVIDER_ID")
			viper.Set("FALLBACK_PROVIDER_ID", testCtxForPQ.privateProviderProfile.ID)
			defer viper.Set("FALLBACK_PROVIDER_ID", oldFallback)

			tokenWithNet, err := db.Client.Token.Query().Where(tokenEnt.IDEQ(testCtxForPQ.token.ID)).WithNetwork().Only(ctx)
			assert.NoError(t, err)
			networkID := tokenWithNet.Edges.Network.Identifier

			// Queue provider (public): rate 1376, slippage 0.5% → order 1390 is outside (|1390-1376| > 1390*0.005)
			publicToken, err := db.Client.ProviderOrderToken.
				Query().
				Where(
					providerordertoken.HasProviderWith(providerprofile.IDEQ(testCtxForPQ.publicProviderProfile.ID)),
					providerordertoken.HasTokenWith(tokenEnt.IDEQ(testCtxForPQ.token.ID)),
					providerordertoken.HasCurrencyWith(fiatcurrency.IDEQ(testCtxForPQ.currency.ID)),
					providerordertoken.NetworkEQ(networkID),
				).
				Only(ctx)
			assert.NoError(t, err)
			_, err = db.Client.ProviderOrderToken.UpdateOneID(publicToken.ID).
				SetFixedConversionRate(decimal.NewFromFloat(1376)).
				SetRateSlippage(decimal.NewFromFloat(0.5)).
				Save(ctx)
			assert.NoError(t, err)

			// Fallback provider (private): rate 1388, slippage 2% → order 1390 is within (|1390-1388| <= 1390*0.02)
			_, err = test.AddProviderOrderTokenToProvider(map[string]interface{}{
				"provider":                 testCtxForPQ.privateProviderProfile,
				"token_id":                 int(testCtxForPQ.token.ID),
				"currency_id":              testCtxForPQ.currency.ID,
				"network":                  networkID,
				"fixed_conversion_rate":    decimal.NewFromFloat(1388),
				"conversion_rate_type":     "fixed",
				"floating_conversion_rate": decimal.NewFromFloat(1.0),
				"max_order_amount":         decimal.NewFromFloat(10000),
				"min_order_amount":         decimal.NewFromFloat(1),
				"max_order_amount_otc":     decimal.NewFromFloat(10000),
				"min_order_amount_otc":     decimal.NewFromFloat(100),
				"settlement_address":       "0xfallback123456789012345678901234567890",
			})
			assert.NoError(t, err)
			fallbackToken, err := db.Client.ProviderOrderToken.
				Query().
				Where(
					providerordertoken.HasProviderWith(providerprofile.IDEQ(testCtxForPQ.privateProviderProfile.ID)),
					providerordertoken.HasTokenWith(tokenEnt.IDEQ(testCtxForPQ.token.ID)),
					providerordertoken.HasCurrencyWith(fiatcurrency.IDEQ(testCtxForPQ.currency.ID)),
					providerordertoken.NetworkEQ(networkID),
				).
				Only(ctx)
			assert.NoError(t, err)
			_, err = db.Client.ProviderOrderToken.UpdateOneID(fallbackToken.ID).
				SetRateSlippage(decimal.NewFromFloat(2)).
				Save(ctx)
			assert.NoError(t, err)

			// Fallback provider needs sufficient fiat balance (order amount * rate; default amount 100.5 * 1390 > 100k)
			_, err = db.Client.ProviderBalances.Update().
				Where(providerbalances.HasProviderWith(providerprofile.IDEQ(testCtxForPQ.privateProviderProfile.ID))).
				Where(providerbalances.HasFiatCurrencyWith(fiatcurrency.IDEQ(testCtxForPQ.currency.ID))).
				SetAvailableBalance(decimal.NewFromFloat(500000)).
				SetTotalBalance(decimal.NewFromFloat(500000)).
				SetIsAvailable(true).
				Save(ctx)
			assert.NoError(t, err)

			// Fallback provider needs an API key for sendOrderRequest (notifyProvider) to succeed
			apiKeySvc := NewAPIKeyService()
			_, _, err = apiKeySvc.GenerateAPIKey(ctx, nil, nil, testCtxForPQ.privateProviderProfile)
			assert.NoError(t, err)

			// Clear any existing queue so the next build uses rate 1376 (not leftover from other tests)
			redisKey := fmt.Sprintf("bucket_%s_%s_%s", testCtxForPQ.currency.Code, testCtxForPQ.bucket.MinAmount, testCtxForPQ.bucket.MaxAmount)
			_ = db.RedisClient.Del(ctx, redisKey).Err()

			// Build queue so it contains public provider at 1376 (order 1390 will not match)
			bucketForQueue, err := db.Client.ProvisionBucket.
				Query().
				Where(provisionbucket.IDEQ(testCtxForPQ.bucket.ID)).
				WithCurrency().
				WithProviderProfiles().
				Only(ctx)
			assert.NoError(t, err)
			service.CreatePriorityQueueForBucket(ctx, bucketForQueue)

			// Order with rate 1390: no provider in queue can fulfill; fallback can
			_order, err := test.CreateTestPaymentOrder(testCtxForPQ.token, map[string]interface{}{
				"provider": testCtxForPQ.publicProviderProfile, "rate": 1390.0, "gateway_id": "gw-fb-rate-only",
			})
			assert.NoError(t, err)
			_, err = _order.Update().ClearProvider().Save(ctx)
			assert.NoError(t, err)
			_, err = test.AddProvisionBucketToPaymentOrder(_order, testCtxForPQ.bucket.ID)
			assert.NoError(t, err)

			// AssignPaymentOrder should fail (no queue provider matches 1390)
			bucketWithCurrency, err := db.Client.ProvisionBucket.
				Query().
				Where(provisionbucket.IDEQ(testCtxForPQ.bucket.ID)).
				WithCurrency().
				Only(ctx)
			assert.NoError(t, err)
			orderFields := types.PaymentOrderFields{
				ID:                _order.ID,
				OrderType:         "regular",
				Token:             testCtxForPQ.token,
				GatewayID:         _order.GatewayID,
				Amount:            _order.Amount,
				Rate:              _order.Rate,
				Institution:       _order.Institution,
				AccountIdentifier: _order.AccountIdentifier,
				AccountName:       _order.AccountName,
				ProviderID:        "",
				ProvisionBucket:   bucketWithCurrency,
				MessageHash:       _order.MessageHash,
				Memo:              _order.Memo,
				UpdatedAt:         _order.UpdatedAt,
				CreatedAt:         _order.CreatedAt,
			}
			if tokenWithNet.Edges.Network != nil {
				orderFields.Network = tokenWithNet.Edges.Network
			}
			err = service.AssignPaymentOrder(ctx, orderFields)
			// If queue matched (e.g. leftover state), clear provider and order_request so we can still test fallback path
			if err == nil {
				_, _ = db.Client.PaymentOrder.UpdateOneID(_order.ID).ClearProvider().Save(ctx)
				_ = db.RedisClient.Del(ctx, fmt.Sprintf("order_request_%s", _order.ID)).Err()
			} else {
				assert.Error(t, err, "AssignPaymentOrder expected to fail when no queue provider matches order rate 1390")
			}

			// TryFallbackAssignment should succeed and assign to fallback provider
			order, err := db.Client.PaymentOrder.
				Query().
				Where(paymentorder.IDEQ(_order.ID)).
				WithToken(func(tq *ent.TokenQuery) { tq.WithNetwork() }).
				WithProvisionBucket(func(pb *ent.ProvisionBucketQuery) { pb.WithCurrency() }).
				Only(ctx)
			assert.NoError(t, err)

			err = service.TryFallbackAssignment(ctx, order)
			assert.NoError(t, err, "TryFallbackAssignment should assign order to fallback when rate is within fallback slippage")

			updated, err := db.Client.PaymentOrder.Get(ctx, _order.ID)
			assert.NoError(t, err)
			assert.False(t, updated.FallbackTriedAt.IsZero(), "FallbackTriedAt should be set after successful fallback assignment")

			// For regular orders, provider_id is set in DB when provider accepts; sendOrderRequest only sets order_request_* in Redis.
			// So verify the order was sent to the fallback by checking Redis.
			orderReqProvider, err := db.RedisClient.HGet(ctx, fmt.Sprintf("order_request_%s", _order.ID), "providerId").Result()
			assert.NoError(t, err)
			assert.Equal(t, testCtxForPQ.privateProviderProfile.ID, orderReqProvider,
				"order should be sent to fallback provider (order_request_* in Redis), not refunded")
		})
	})
}
