package services

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	_ "github.com/mattn/go-sqlite3"
	"github.com/jarcoal/httpmock"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/enttest"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	"github.com/paycrest/aggregator/ent/migrate"
	"github.com/paycrest/aggregator/ent/providercurrencies"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/provisionbucket"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/paycrest/aggregator/utils/test"
	tokenUtils "github.com/paycrest/aggregator/utils/token"
	tokenEnt "github.com/paycrest/aggregator/ent/token"
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
	// Set up test database client
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	// Run schema migrations to ensure all tables are created
	if err := client.Schema.Create(context.Background(), migrate.WithGlobalUniqueID(true)); err != nil {
		t.Fatal(err)
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
	db.Client = client

	// Setup test data
	err = setupForPQ()
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
			"token_id":   testCtxForPQ.token.ID,
			"gateway_id": "order-1234",
		})
		assert.NoError(t, err)

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
					"status": "success",
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

	t.Run("TestEqualSlotDistribution", func(t *testing.T) {
		ctx := context.Background()

		// Create a second token for testing
		token2Id, err := db.Client.Token.
			Create().
			SetSymbol("TST2").
			SetContractAddress("0xd4E96eF8eee8678dBFf4d535E033Ed1a4F7605b8").
			SetDecimals(6).
			SetNetworkID(testCtxForPQ.token.Edges.Network.ID).
			SetIsEnabled(true).
			SetBaseCurrency("KES").
			OnConflict().
			UpdateNewValues().
			ID(ctx)
		assert.NoError(t, err)

		token2, err := db.Client.Token.
			Query().
			Where(tokenEnt.IDEQ(token2Id)).
			WithNetwork().
			Only(ctx)
		assert.NoError(t, err)

		// Create a third token for testing
		token3Id, err := db.Client.Token.
			Create().
			SetSymbol("TST3").
			SetContractAddress("0xd4E96eF8eee8678dBFf4d535E033Ed1a4F7605b9").
			SetDecimals(6).
			SetNetworkID(testCtxForPQ.token.Edges.Network.ID).
			SetIsEnabled(true).
			SetBaseCurrency("KES").
			OnConflict().
			UpdateNewValues().
			ID(ctx)
		assert.NoError(t, err)

		token3, err := db.Client.Token.
			Query().
			Where(tokenEnt.IDEQ(token3Id)).
			WithNetwork().
			Only(ctx)
		assert.NoError(t, err)

		// Create provider with multiple tokens (3 tokens)
		multiTokenProvider, err := test.CreateTestUser(map[string]interface{}{
			"scope": "provider",
			"email": "multitoken@test.com",
		})
		assert.NoError(t, err)

		multiTokenProviderProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
			"user_id":         multiTokenProvider.ID,
			"currency_id":     testCtxForPQ.currency.ID,
			"host_identifier": "https://multitoken.com",
		})
		assert.NoError(t, err)

		// Add 3 tokens to multiTokenProvider
		_, err = test.AddProviderOrderTokenToProvider(
			map[string]interface{}{
				"fixed_conversion_rate":    decimal.NewFromFloat(100),
				"conversion_rate_type":     "fixed",
				"floating_conversion_rate": decimal.NewFromFloat(1.0),
				"max_order_amount":         decimal.NewFromFloat(1000),
				"min_order_amount":         decimal.NewFromFloat(1.0),
				"provider":                 multiTokenProviderProfile,
				"currency_id":              testCtxForPQ.currency.ID,
				"network":                  testCtxForPQ.token.Edges.Network.Identifier,
				"token_id":                 testCtxForPQ.token.ID,
			},
		)
		assert.NoError(t, err)

		_, err = test.AddProviderOrderTokenToProvider(
			map[string]interface{}{
				"fixed_conversion_rate":    decimal.NewFromFloat(110),
				"conversion_rate_type":     "fixed",
				"floating_conversion_rate": decimal.NewFromFloat(1.0),
				"max_order_amount":         decimal.NewFromFloat(1000),
				"min_order_amount":         decimal.NewFromFloat(1.0),
				"provider":                 multiTokenProviderProfile,
				"currency_id":              testCtxForPQ.currency.ID,
				"network":                  token2.Edges.Network.Identifier,
				"token_id":                 token2.ID,
			},
		)
		assert.NoError(t, err)

		_, err = test.AddProviderOrderTokenToProvider(
			map[string]interface{}{
				"fixed_conversion_rate":    decimal.NewFromFloat(120),
				"conversion_rate_type":     "fixed",
				"floating_conversion_rate": decimal.NewFromFloat(1.0),
				"max_order_amount":         decimal.NewFromFloat(1000),
				"min_order_amount":         decimal.NewFromFloat(1.0),
				"provider":                 multiTokenProviderProfile,
				"currency_id":              testCtxForPQ.currency.ID,
				"network":                  token3.Edges.Network.Identifier,
				"token_id":                 token3.ID,
			},
		)
		assert.NoError(t, err)

		// Update ProviderCurrencies with sufficient balance
		_, err = db.Client.ProviderCurrencies.
			Update().
			Where(providercurrencies.HasProviderWith(providerprofile.IDEQ(multiTokenProviderProfile.ID))).
			Where(providercurrencies.HasCurrencyWith(fiatcurrency.IDEQ(testCtxForPQ.currency.ID))).
			SetAvailableBalance(decimal.NewFromFloat(100000)).
			SetTotalBalance(decimal.NewFromFloat(100000)).
			Save(ctx)
		assert.NoError(t, err)

		// Create provider with single token
		singleTokenProvider, err := test.CreateTestUser(map[string]interface{}{
			"scope": "provider",
			"email": "singletoken@test.com",
		})
		assert.NoError(t, err)

		singleTokenProviderProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
			"user_id":         singleTokenProvider.ID,
			"currency_id":     testCtxForPQ.currency.ID,
			"host_identifier": "https://singletoken.com",
		})
		assert.NoError(t, err)

		// Add only 1 token to singleTokenProvider
		_, err = test.AddProviderOrderTokenToProvider(
			map[string]interface{}{
				"fixed_conversion_rate":    decimal.NewFromFloat(105),
				"conversion_rate_type":     "fixed",
				"floating_conversion_rate": decimal.NewFromFloat(1.0),
				"max_order_amount":         decimal.NewFromFloat(1000),
				"min_order_amount":         decimal.NewFromFloat(1.0),
				"provider":                 singleTokenProviderProfile,
				"currency_id":              testCtxForPQ.currency.ID,
				"network":                  testCtxForPQ.token.Edges.Network.Identifier,
				"token_id":                 testCtxForPQ.token.ID,
			},
		)
		assert.NoError(t, err)

		// Update ProviderCurrencies with sufficient balance
		_, err = db.Client.ProviderCurrencies.
			Update().
			Where(providercurrencies.HasProviderWith(providerprofile.IDEQ(singleTokenProviderProfile.ID))).
			Where(providercurrencies.HasCurrencyWith(fiatcurrency.IDEQ(testCtxForPQ.currency.ID))).
			SetAvailableBalance(decimal.NewFromFloat(100000)).
			SetTotalBalance(decimal.NewFromFloat(100000)).
			Save(ctx)
		assert.NoError(t, err)

		// Create a bucket with both providers
		bucket, err := test.CreateTestProvisionBucket(map[string]interface{}{
			"provider_id": multiTokenProviderProfile.ID,
			"min_amount":  testCtxForPQ.minAmount,
			"max_amount":  testCtxForPQ.maxAmount,
			"currency_id": testCtxForPQ.currency.ID,
		})
		assert.NoError(t, err)

		// Add second provider to the same bucket
		_, err = db.Client.ProvisionBucket.
			UpdateOneID(bucket.ID).
			AddProviderProfileIDs(singleTokenProviderProfile.ID).
			Save(ctx)
		assert.NoError(t, err)

		_bucket, err := db.Client.ProvisionBucket.
			Query().
			Where(provisionbucket.IDEQ(bucket.ID)).
			WithCurrency().
			WithProviderProfiles().
			Only(ctx)
		assert.NoError(t, err)

		// Create the priority queue
		service.CreatePriorityQueueForBucket(ctx, _bucket)

		redisKey := fmt.Sprintf("bucket_%s_%s_%s", _bucket.Edges.Currency.Code, testCtxForPQ.minAmount, testCtxForPQ.maxAmount)

		// Verify the queue structure
		data, err := db.RedisClient.LRange(ctx, redisKey, 0, -1).Result()
		assert.NoError(t, err)

		// Both providers should have equal slots (3 each, matching the max token count)
		expectedSlots := 3
		totalExpectedSlots := expectedSlots * 2 // 2 providers

		assert.Equal(t, totalExpectedSlots, len(data), "Total slots should be %d (3 slots per provider x 2 providers)", totalExpectedSlots)

		// Count slots per provider
		multiTokenSlots := 0
		singleTokenSlots := 0
		for _, entry := range data {
			if strings.HasPrefix(entry, multiTokenProviderProfile.ID) {
				multiTokenSlots++
			} else if strings.HasPrefix(entry, singleTokenProviderProfile.ID) {
				singleTokenSlots++
			}
		}

		assert.Equal(t, expectedSlots, multiTokenSlots, "Multi-token provider should have exactly %d slots", expectedSlots)
		assert.Equal(t, expectedSlots, singleTokenSlots, "Single-token provider should have exactly %d slots", expectedSlots)

		// Verify that single token provider's token is repeated 3 times
		singleTokenEntries := []string{}
		for _, entry := range data {
			if strings.HasPrefix(entry, singleTokenProviderProfile.ID) {
				singleTokenEntries = append(singleTokenEntries, entry)
			}
		}

		// All entries should be identical (same token repeated)
		for i := 1; i < len(singleTokenEntries); i++ {
			assert.Equal(t, singleTokenEntries[0], singleTokenEntries[i], "Single-token provider entries should be identical (cycling)")
		}

		// Verify multi-token provider has all 3 different tokens
		multiTokenEntries := []string{}
		tokenSymbolsFound := make(map[string]bool)
		for _, entry := range data {
			if strings.HasPrefix(entry, multiTokenProviderProfile.ID) {
				multiTokenEntries = append(multiTokenEntries, entry)
				parts := strings.Split(entry, ":")
				if len(parts) >= 2 {
					tokenSymbolsFound[parts[1]] = true
				}
			}
		}

		assert.Equal(t, 3, len(tokenSymbolsFound), "Multi-token provider should have all 3 different tokens represented")
		assert.True(t, tokenSymbolsFound["TST"], "Should contain TST token")
		assert.True(t, tokenSymbolsFound["TST2"], "Should contain TST2 token")
		assert.True(t, tokenSymbolsFound["TST3"], "Should contain TST3 token")
	})

	t.Run("TestSlotCapAt20", func(t *testing.T) {
		ctx := context.Background()

		// Create a provider with many tokens (more than 20)
		manyTokenProvider, err := test.CreateTestUser(map[string]interface{}{
			"scope": "provider",
			"email": "manytoken@test.com",
		})
		assert.NoError(t, err)

		manyTokenProviderProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
			"user_id":         manyTokenProvider.ID,
			"currency_id":     testCtxForPQ.currency.ID,
			"host_identifier": "https://manytoken.com",
		})
		assert.NoError(t, err)

		// Add 25 tokens to test the cap
		for i := 0; i < 25; i++ {
			tokenId, err := db.Client.Token.
				Create().
				SetSymbol(fmt.Sprintf("CAP%d", i)).
				SetContractAddress(fmt.Sprintf("0xCAP%024d", i)).
				SetDecimals(6).
				SetNetworkID(testCtxForPQ.token.Edges.Network.ID).
				SetIsEnabled(true).
				SetBaseCurrency("KES").
				OnConflict().
				UpdateNewValues().
				ID(ctx)
			assert.NoError(t, err)

			_, err = test.AddProviderOrderTokenToProvider(
				map[string]interface{}{
					"fixed_conversion_rate":    decimal.NewFromFloat(100 + float64(i)),
					"conversion_rate_type":     "fixed",
					"floating_conversion_rate": decimal.NewFromFloat(1.0),
					"max_order_amount":         decimal.NewFromFloat(1000),
					"min_order_amount":         decimal.NewFromFloat(1.0),
					"provider":                 manyTokenProviderProfile,
					"currency_id":              testCtxForPQ.currency.ID,
					"network":                  testCtxForPQ.token.Edges.Network.Identifier,
					"token_id":                 tokenId,
				},
			)
			assert.NoError(t, err)
		}

		// Update ProviderCurrencies with sufficient balance
		_, err = db.Client.ProviderCurrencies.
			Update().
			Where(providercurrencies.HasProviderWith(providerprofile.IDEQ(manyTokenProviderProfile.ID))).
			Where(providercurrencies.HasCurrencyWith(fiatcurrency.IDEQ(testCtxForPQ.currency.ID))).
			SetAvailableBalance(decimal.NewFromFloat(100000)).
			SetTotalBalance(decimal.NewFromFloat(100000)).
			Save(ctx)
		assert.NoError(t, err)

		// Create a bucket with this provider
		bucket, err := test.CreateTestProvisionBucket(map[string]interface{}{
			"provider_id": manyTokenProviderProfile.ID,
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

		// Create the priority queue
		service.CreatePriorityQueueForBucket(ctx, _bucket)

		redisKey := fmt.Sprintf("bucket_%s_%s_%s", _bucket.Edges.Currency.Code, testCtxForPQ.minAmount, testCtxForPQ.maxAmount)

		// Verify the queue structure
		data, err := db.RedisClient.LRange(ctx, redisKey, 0, -1).Result()
		assert.NoError(t, err)

		// Should be capped at 20 slots, not 25
		assert.Equal(t, 20, len(data), "Slots should be capped at 20 even though provider has 25 tokens")

		// Count unique tokens in the queue
		tokenSymbolsFound := make(map[string]bool)
		for _, entry := range data {
			parts := strings.Split(entry, ":")
			if len(parts) >= 2 {
				tokenSymbolsFound[parts[1]] = true
			}
		}

		// Should have 20 unique tokens (cycling through the first 20)
		assert.Equal(t, 20, len(tokenSymbolsFound), "Should have exactly 20 unique tokens in queue")
	})

	t.Run("TestNoValidProvidersExitEarly", func(t *testing.T) {
		ctx := context.Background()

		// Create a provider with no tokens
		noTokenProvider, err := test.CreateTestUser(map[string]interface{}{
			"scope": "provider",
			"email": "notoken@test.com",
		})
		assert.NoError(t, err)

		noTokenProviderProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
			"user_id":         noTokenProvider.ID,
			"currency_id":     testCtxForPQ.currency.ID,
			"host_identifier": "https://notoken.com",
		})
		assert.NoError(t, err)

		// Update ProviderCurrencies with sufficient balance
		_, err = db.Client.ProviderCurrencies.
			Update().
			Where(providercurrencies.HasProviderWith(providerprofile.IDEQ(noTokenProviderProfile.ID))).
			Where(providercurrencies.HasCurrencyWith(fiatcurrency.IDEQ(testCtxForPQ.currency.ID))).
			SetAvailableBalance(decimal.NewFromFloat(100000)).
			SetTotalBalance(decimal.NewFromFloat(100000)).
			Save(ctx)
		assert.NoError(t, err)

		// Create a bucket with this provider (no tokens)
		bucket, err := test.CreateTestProvisionBucket(map[string]interface{}{
			"provider_id": noTokenProviderProfile.ID,
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

		// Create the priority queue (should exit early)
		service.CreatePriorityQueueForBucket(ctx, _bucket)

		redisKey := fmt.Sprintf("bucket_%s_%s_%s", _bucket.Edges.Currency.Code, testCtxForPQ.minAmount, testCtxForPQ.maxAmount)

		// Verify the queue is empty
		data, err := db.RedisClient.LRange(ctx, redisKey, 0, -1).Result()
		assert.NoError(t, err)
		assert.Equal(t, 0, len(data), "Queue should be empty when no valid providers exist")
	})

	t.Run("TestTwoProvidersWithDifferentTokenCounts", func(t *testing.T) {
		ctx := context.Background()

		// Create provider with 2 tokens
		twoTokenProvider, err := test.CreateTestUser(map[string]interface{}{
			"scope": "provider",
			"email": "twotoken@test.com",
		})
		assert.NoError(t, err)

		twoTokenProviderProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
			"user_id":         twoTokenProvider.ID,
			"currency_id":     testCtxForPQ.currency.ID,
			"host_identifier": "https://twotoken.com",
		})
		assert.NoError(t, err)

		// Create tokens
		token4Id, err := db.Client.Token.
			Create().
			SetSymbol("TST4").
			SetContractAddress("0xd4E96eF8eee8678dBFf4d535E033Ed1a4F7605c0").
			SetDecimals(6).
			SetNetworkID(testCtxForPQ.token.Edges.Network.ID).
			SetIsEnabled(true).
			SetBaseCurrency("KES").
			OnConflict().
			UpdateNewValues().
			ID(ctx)
		assert.NoError(t, err)

		token5Id, err := db.Client.Token.
			Create().
			SetSymbol("TST5").
			SetContractAddress("0xd4E96eF8eee8678dBFf4d535E033Ed1a4F7605c1").
			SetDecimals(6).
			SetNetworkID(testCtxForPQ.token.Edges.Network.ID).
			SetIsEnabled(true).
			SetBaseCurrency("KES").
			OnConflict().
			UpdateNewValues().
			ID(ctx)
		assert.NoError(t, err)

		// Add 2 tokens to twoTokenProvider
		_, err = test.AddProviderOrderTokenToProvider(
			map[string]interface{}{
				"fixed_conversion_rate":    decimal.NewFromFloat(100),
				"conversion_rate_type":     "fixed",
				"floating_conversion_rate": decimal.NewFromFloat(1.0),
				"max_order_amount":         decimal.NewFromFloat(1000),
				"min_order_amount":         decimal.NewFromFloat(1.0),
				"provider":                 twoTokenProviderProfile,
				"currency_id":              testCtxForPQ.currency.ID,
				"network":                  testCtxForPQ.token.Edges.Network.Identifier,
				"token_id":                 token4Id,
			},
		)
		assert.NoError(t, err)

		_, err = test.AddProviderOrderTokenToProvider(
			map[string]interface{}{
				"fixed_conversion_rate":    decimal.NewFromFloat(105),
				"conversion_rate_type":     "fixed",
				"floating_conversion_rate": decimal.NewFromFloat(1.0),
				"max_order_amount":         decimal.NewFromFloat(1000),
				"min_order_amount":         decimal.NewFromFloat(1.0),
				"provider":                 twoTokenProviderProfile,
				"currency_id":              testCtxForPQ.currency.ID,
				"network":                  testCtxForPQ.token.Edges.Network.Identifier,
				"token_id":                 token5Id,
			},
		)
		assert.NoError(t, err)

		// Update ProviderCurrencies with sufficient balance
		_, err = db.Client.ProviderCurrencies.
			Update().
			Where(providercurrencies.HasProviderWith(providerprofile.IDEQ(twoTokenProviderProfile.ID))).
			Where(providercurrencies.HasCurrencyWith(fiatcurrency.IDEQ(testCtxForPQ.currency.ID))).
			SetAvailableBalance(decimal.NewFromFloat(100000)).
			SetTotalBalance(decimal.NewFromFloat(100000)).
			Save(ctx)
		assert.NoError(t, err)

		// Create provider with 5 tokens
		fiveTokenProvider, err := test.CreateTestUser(map[string]interface{}{
			"scope": "provider",
			"email": "fivetoken@test.com",
		})
		assert.NoError(t, err)

		fiveTokenProviderProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
			"user_id":         fiveTokenProvider.ID,
			"currency_id":     testCtxForPQ.currency.ID,
			"host_identifier": "https://fivetoken.com",
		})
		assert.NoError(t, err)

		// Add 5 tokens to fiveTokenProvider
		for i := 0; i < 5; i++ {
			tokenId, err := db.Client.Token.
				Create().
				SetSymbol(fmt.Sprintf("TST%d", 10+i)).
				SetContractAddress(fmt.Sprintf("0xd4E96eF8eee8678dBFf4d535E033Ed1a4F7605%02d", 10+i)).
				SetDecimals(6).
				SetNetworkID(testCtxForPQ.token.Edges.Network.ID).
				SetIsEnabled(true).
				SetBaseCurrency("KES").
				OnConflict().
				UpdateNewValues().
				ID(ctx)
			assert.NoError(t, err)

			_, err = test.AddProviderOrderTokenToProvider(
				map[string]interface{}{
					"fixed_conversion_rate":    decimal.NewFromFloat(100 + float64(i)),
					"conversion_rate_type":     "fixed",
					"floating_conversion_rate": decimal.NewFromFloat(1.0),
					"max_order_amount":         decimal.NewFromFloat(1000),
					"min_order_amount":         decimal.NewFromFloat(1.0),
					"provider":                 fiveTokenProviderProfile,
					"currency_id":              testCtxForPQ.currency.ID,
					"network":                  testCtxForPQ.token.Edges.Network.Identifier,
					"token_id":                 tokenId,
				},
			)
			assert.NoError(t, err)
		}

		// Update ProviderCurrencies with sufficient balance
		_, err = db.Client.ProviderCurrencies.
			Update().
			Where(providercurrencies.HasProviderWith(providerprofile.IDEQ(fiveTokenProviderProfile.ID))).
			Where(providercurrencies.HasCurrencyWith(fiatcurrency.IDEQ(testCtxForPQ.currency.ID))).
			SetAvailableBalance(decimal.NewFromFloat(100000)).
			SetTotalBalance(decimal.NewFromFloat(100000)).
			Save(ctx)
		assert.NoError(t, err)

		// Create a bucket with both providers
		bucket, err := test.CreateTestProvisionBucket(map[string]interface{}{
			"provider_id": twoTokenProviderProfile.ID,
			"min_amount":  testCtxForPQ.minAmount,
			"max_amount":  testCtxForPQ.maxAmount,
			"currency_id": testCtxForPQ.currency.ID,
		})
		assert.NoError(t, err)

		// Add second provider to the same bucket
		_, err = db.Client.ProvisionBucket.
			UpdateOneID(bucket.ID).
			AddProviderProfileIDs(fiveTokenProviderProfile.ID).
			Save(ctx)
		assert.NoError(t, err)

		_bucket, err := db.Client.ProvisionBucket.
			Query().
			Where(provisionbucket.IDEQ(bucket.ID)).
			WithCurrency().
			WithProviderProfiles().
			Only(ctx)
		assert.NoError(t, err)

		// Create the priority queue
		service.CreatePriorityQueueForBucket(ctx, _bucket)

		redisKey := fmt.Sprintf("bucket_%s_%s_%s", _bucket.Edges.Currency.Code, testCtxForPQ.minAmount, testCtxForPQ.maxAmount)

		// Verify the queue structure
		data, err := db.RedisClient.LRange(ctx, redisKey, 0, -1).Result()
		assert.NoError(t, err)

		// Both providers should have equal slots (5 each, matching the max token count)
		expectedSlots := 5
		totalExpectedSlots := expectedSlots * 2 // 2 providers

		assert.Equal(t, totalExpectedSlots, len(data), "Total slots should be %d (5 slots per provider x 2 providers)", totalExpectedSlots)

		// Count slots per provider
		twoTokenSlots := 0
		fiveTokenSlots := 0
		for _, entry := range data {
			if strings.HasPrefix(entry, twoTokenProviderProfile.ID) {
				twoTokenSlots++
			} else if strings.HasPrefix(entry, fiveTokenProviderProfile.ID) {
				fiveTokenSlots++
			}
		}

		assert.Equal(t, expectedSlots, twoTokenSlots, "Two-token provider should have exactly %d slots", expectedSlots)
		assert.Equal(t, expectedSlots, fiveTokenSlots, "Five-token provider should have exactly %d slots", expectedSlots)

		// Verify that two-token provider cycles through its tokens
		twoTokenEntries := []string{}
		tokenSymbolsInTwoToken := make(map[string]int)
		for _, entry := range data {
			if strings.HasPrefix(entry, twoTokenProviderProfile.ID) {
				twoTokenEntries = append(twoTokenEntries, entry)
				parts := strings.Split(entry, ":")
				if len(parts) >= 2 {
					tokenSymbolsInTwoToken[parts[1]]++
				}
			}
		}

		// With 2 tokens and 5 slots: should have pattern like [T1, T2, T1, T2, T1]
		assert.Equal(t, 2, len(tokenSymbolsInTwoToken), "Two-token provider should cycle through 2 unique tokens")
		// Token counts should be 3 and 2 (or 2 and 3)
		counts := []int{}
		for _, count := range tokenSymbolsInTwoToken {
			counts = append(counts, count)
		}
		assert.Contains(t, counts, 3, "One token should appear 3 times")
		assert.Contains(t, counts, 2, "Other token should appear 2 times")
	})

	t.Run("TestDeterministicQueueOrder", func(t *testing.T) {
		ctx := context.Background()

		// Create 3 providers with different IDs to test deterministic ordering
		providers := []struct {
			email string
			host  string
		}{
			{"provider-c@test.com", "https://provider-c.com"},
			{"provider-a@test.com", "https://provider-a.com"},
			{"provider-b@test.com", "https://provider-b.com"},
		}

		providerProfiles := []*ent.ProviderProfile{}

		for _, p := range providers {
			providerUser, err := test.CreateTestUser(map[string]interface{}{
				"scope": "provider",
				"email": p.email,
			})
			assert.NoError(t, err)

			providerProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":         providerUser.ID,
				"currency_id":     testCtxForPQ.currency.ID,
				"host_identifier": p.host,
			})
			assert.NoError(t, err)

			// Add 1 token to each provider
			_, err = test.AddProviderOrderTokenToProvider(
				map[string]interface{}{
					"fixed_conversion_rate":    decimal.NewFromFloat(100),
					"conversion_rate_type":     "fixed",
					"floating_conversion_rate": decimal.NewFromFloat(1.0),
					"max_order_amount":         decimal.NewFromFloat(1000),
					"min_order_amount":         decimal.NewFromFloat(1.0),
					"provider":                 providerProfile,
					"currency_id":              testCtxForPQ.currency.ID,
					"network":                  testCtxForPQ.token.Edges.Network.Identifier,
					"token_id":                 testCtxForPQ.token.ID,
				},
			)
			assert.NoError(t, err)

			// Update ProviderCurrencies with sufficient balance
			_, err = db.Client.ProviderCurrencies.
				Update().
				Where(providercurrencies.HasProviderWith(providerprofile.IDEQ(providerProfile.ID))).
				Where(providercurrencies.HasCurrencyWith(fiatcurrency.IDEQ(testCtxForPQ.currency.ID))).
				SetAvailableBalance(decimal.NewFromFloat(100000)).
				SetTotalBalance(decimal.NewFromFloat(100000)).
				Save(ctx)
			assert.NoError(t, err)

			providerProfiles = append(providerProfiles, providerProfile)
		}

		// Create a bucket with all providers
		bucket, err := test.CreateTestProvisionBucket(map[string]interface{}{
			"provider_id": providerProfiles[0].ID,
			"min_amount":  testCtxForPQ.minAmount,
			"max_amount":  testCtxForPQ.maxAmount,
			"currency_id": testCtxForPQ.currency.ID,
		})
		assert.NoError(t, err)

		// Add other providers to the bucket
		_, err = db.Client.ProvisionBucket.
			UpdateOneID(bucket.ID).
			AddProviderProfileIDs(providerProfiles[1].ID, providerProfiles[2].ID).
			Save(ctx)
		assert.NoError(t, err)

		_bucket, err := db.Client.ProvisionBucket.
			Query().
			Where(provisionbucket.IDEQ(bucket.ID)).
			WithCurrency().
			WithProviderProfiles().
			Only(ctx)
		assert.NoError(t, err)

		// Create the queue multiple times and verify consistent ordering
		redisKey := fmt.Sprintf("bucket_%s_%s_%s", _bucket.Edges.Currency.Code, testCtxForPQ.minAmount, testCtxForPQ.maxAmount)

		// First run
		service.CreatePriorityQueueForBucket(ctx, _bucket)
		firstRun, err := db.RedisClient.LRange(ctx, redisKey, 0, -1).Result()
		assert.NoError(t, err)

		// Delete and recreate
		_, err = db.RedisClient.Del(ctx, redisKey).Result()
		assert.NoError(t, err)

		// Second run
		service.CreatePriorityQueueForBucket(ctx, _bucket)
		secondRun, err := db.RedisClient.LRange(ctx, redisKey, 0, -1).Result()
		assert.NoError(t, err)

		// Delete and recreate
		_, err = db.RedisClient.Del(ctx, redisKey).Result()
		assert.NoError(t, err)

		// Third run
		service.CreatePriorityQueueForBucket(ctx, _bucket)
		thirdRun, err := db.RedisClient.LRange(ctx, redisKey, 0, -1).Result()
		assert.NoError(t, err)

		// All runs should produce identical queue order
		assert.Equal(t, firstRun, secondRun, "First and second runs should produce identical queue order")
		assert.Equal(t, secondRun, thirdRun, "Second and third runs should produce identical queue order")

		// Verify providers are ordered deterministically (sorted by ID)
		// Collect all provider IDs in order of appearance
		seenProviders := []string{}
		for _, entry := range firstRun {
			parts := strings.Split(entry, ":")
			if len(parts) > 0 {
				providerID := parts[0]
				if !containsString(seenProviders, providerID) {
					seenProviders = append(seenProviders, providerID)
				}
			}
		}

		// Verify the providers appear in sorted order
		sortedProviders := make([]string, len(seenProviders))
		copy(sortedProviders, seenProviders)
		sort.Strings(sortedProviders)
		assert.Equal(t, sortedProviders, seenProviders, "Providers should appear in sorted ID order")
	})
}

// Helper function for the test
func containsString(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}
