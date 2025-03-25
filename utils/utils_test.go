package utils

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/go-redis/redismock/v9"
	_ "github.com/mattn/go-sqlite3"
	"github.com/paycrest/aggregator/ent/enttest"
	"github.com/paycrest/aggregator/storage"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
)

func TestUtils(t *testing.T) {

	t.Run("ToSubunit", func(t *testing.T) {
		testCases := []struct {
			amount    decimal.Decimal
			decimals  int8
			expectVal *big.Int
		}{
			{
				amount:    decimal.NewFromFloat(1.23),
				decimals:  2,
				expectVal: big.NewInt(123),
			},
			{
				amount:    decimal.NewFromFloat(0.001),
				decimals:  8,
				expectVal: big.NewInt(100000),
			},
			{
				amount:    decimal.NewFromFloat(0.005),
				decimals:  18,
				expectVal: big.NewInt(5000000000000000),
			},
		}

		for _, tc := range testCases {
			actualVal := ToSubunit(tc.amount, tc.decimals)
			assert.Equal(t, tc.expectVal, actualVal)
		}
	})

	t.Run("FromSubunit", func(t *testing.T) {
		testCases := []struct {
			amountInSubunit *big.Int
			decimals        int8
			expectVal       decimal.Decimal
		}{
			{
				amountInSubunit: big.NewInt(123),
				decimals:        2,
				expectVal:       decimal.NewFromFloat(1.23),
			},
			{
				amountInSubunit: big.NewInt(1),
				decimals:        8,
				expectVal:       decimal.NewFromFloat(0.00000001),
			},
			{
				amountInSubunit: big.NewInt(5000000000000000),
				decimals:        18,
				expectVal:       decimal.NewFromFloat(0.005),
			},
		}

		for _, tc := range testCases {
			actualVal := FromSubunit(tc.amountInSubunit, tc.decimals)
			assert.Equal(t, tc.expectVal, actualVal)
		}
	})

	t.Run("TestMedian", func(t *testing.T) {
		data := []decimal.Decimal{
			decimal.NewFromInt(9),
			decimal.NewFromInt(1),
			decimal.NewFromInt(5),
			decimal.NewFromInt(6),
			decimal.NewFromInt(2),
			decimal.NewFromInt(1),
			decimal.NewFromInt(3),
			decimal.NewFromInt(1),
			decimal.NewFromInt(1),
			decimal.NewFromInt(2),
		}

		median := Median(data)

		assert := assert.New(t)
		assert.True(median.Equal(decimal.NewFromInt(2)), "Median calculation is incorrect")
	})

	t.Run("UpdateRedisQueue", func(t *testing.T) {
		// Setup in-memory Ent client
		client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
		defer client.Close()
		storage.Client = client

		// Setup test data
		ctx := context.Background()
		user := client.User.Create().
			SetFirstName("Test").
			SetLastName("User").
			SetPassword("password123").
			SetScope("user").
			SetEmail("testuser@example.com").
			SaveX(ctx)

		// Create a FiatCurrency with all required fields
		currency := client.FiatCurrency.Create().
			SetCode("USD").
			SetShortName("USD").
			SetSymbol("$").
			SetName("US Dollar").
			SetMarketRate(decimal.NewFromFloat(1.0)).
			SetIsEnabled(true).
			SaveX(ctx)

		provider := client.ProviderProfile.Create().
			SetTradingName("TestProvider").
			SetUser(user).
			AddCurrencies(currency).
			SaveX(ctx)

		// Link the currency to ProvisionBucket
		_ = client.ProvisionBucket.Create().
			SetMinAmount(decimal.NewFromInt(100)).
			SetMaxAmount(decimal.NewFromInt(1000)).
			SetCurrency(currency). // Required edge
			AddProviderProfiles(provider).
			SaveX(ctx)

		redisKey := "bucket_USD_100_1000"                    // Matches format: bucket_<currency>_<minAmount>_<maxAmount>
		providerData := provider.ID + ":data:more:info:here" // Matches expected format with 5 parts

		t.Run("SuccessfulRemoval", func(t *testing.T) {
			redisClient, mock := redismock.NewClientMock()
			defer redisClient.Close()

			// Mock Redis list behavior for removal (isAvailable = false)
			mock.ExpectLIndex(redisKey, -1).SetVal(providerData)
			mock.ExpectWatch(redisKey)
			mock.ExpectLSet(redisKey, -1, "DELETED_PROVIDER").SetVal("OK")
			mock.ExpectLRem(redisKey, 0, "DELETED_PROVIDER").SetVal(1)

			err := UpdateRedisQueue(ctx, redisClient, provider, "USD", false)
			assert.NoError(t, err, "Should remove provider from queue without error")
			assert.NoError(t, mock.ExpectationsWereMet(), "Redis expectations should be met")
		})

		t.Run("SuccessfulAddition", func(t *testing.T) {
			redisClient, mock := redismock.NewClientMock()
			defer redisClient.Close()

			// Mock Redis list behavior for addition (isAvailable = true)
			mock.ExpectRPush(redisKey, providerData).SetVal(1)

			err := UpdateRedisQueue(ctx, redisClient, provider, "USD", true)
			assert.NoError(t, err, "Should add provider to queue without error")
			assert.NoError(t, mock.ExpectationsWereMet(), "Redis expectations should be met")
		})

		t.Run("NilRedisClient", func(t *testing.T) {
			err := UpdateRedisQueue(ctx, nil, provider, "USD", false)
			assert.Error(t, err, "Should return error when Redis client is nil")
			assert.Contains(t, err.Error(), "redis client is nil", "Error message should indicate nil client")
		})

		t.Run("NoProviderInQueue", func(t *testing.T) {
			redisClient, mock := redismock.NewClientMock()
			defer redisClient.Close()

			// Mock Redis list with no matching provider
			mock.ExpectLIndex(redisKey, -1).SetVal("otherID:data:more:info:here")
			mock.ExpectLIndex(redisKey, -2).RedisNil()

			err := UpdateRedisQueue(ctx, redisClient, provider, "USD", false)
			assert.NoError(t, err, "Should return no error when provider isn’t in queue")
			assert.NoError(t, mock.ExpectationsWereMet(), "Redis expectations should be met")
		})

		t.Run("RedisErrorOnRemoval", func(t *testing.T) {
			redisClient, mock := redismock.NewClientMock()
			defer redisClient.Close()

			// Mock Redis list with provider, but fail on LSet
			mock.ExpectLIndex(redisKey, -1).SetVal(providerData)
			mock.ExpectWatch(redisKey)
			mock.ExpectLSet(redisKey, -1, "DELETED_PROVIDER").SetErr(fmt.Errorf("redis error"))

			err := UpdateRedisQueue(ctx, redisClient, provider, "USD", false)
			assert.Error(t, err, "Should return error on Redis failure")
			assert.Contains(t, err.Error(), "redis error", "Error should reflect Redis failure")
			assert.NoError(t, mock.ExpectationsWereMet(), "Redis expectations should be met")
		})
	})
}
