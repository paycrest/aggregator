package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/enttest"

	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils/test"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
)

var testCtx = struct {
	rpcClient      types.RPCClient
	indexer        *IndexerService
	receiveAddress *ent.ReceiveAddress
	paymentOrder   *ent.PaymentOrder
}{}

func setup() error {
	// Set up test blockchain client
	client, err := test.SetUpTestBlockchain()
	if err != nil {
		return err
	}
	testCtx.rpcClient = client

	// Create a mock instance of the OrderService
	mockOrderService := &test.MockOrderService{}

	indexer := NewIndexerService(mockOrderService)
	testCtx.indexer = indexer.(*IndexerService)

	return nil
}

func TestAMLCompliance(t *testing.T) {
	// Test Blocked Transaction
	ok, err := testCtx.indexer.checkAMLCompliance("wss://ws-rpc.shield3.com?apiKey=gpqwyjnJ9y86bL1AfLQk1ZLu0vBev1F4aYaucJk9&networkId=sepolia", "0x352baede033033c359cbd2d404a6d980b29a6b993542fcae6536028b1823ac54")
	assert.False(t, ok)
	assert.NoError(t, err)

	// Test Allowed Transaction
	ok, err = testCtx.indexer.checkAMLCompliance("wss://ws-rpc.shield3.com?apiKey=gpqwyjnJ9y86bL1AfLQk1ZLu0vBev1F4aYaucJk9&networkId=sepolia", "0xad3f9245daaa4c814cc51b91bbcd32769064662ebf8063358806bbbc8bb9c124")
	assert.True(t, ok)
	assert.NoError(t, err)
}

func TestGetProvisionBucket(t *testing.T) {
	ctx := context.Background()

	// Set up test database client
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()
	db.Client = client

	// Setup test data (reusing your setup function where possible)
	err := setup()
	assert.NoError(t, err)

	// Create a test currency (USD) with a UUID and all required fields
	usdID := uuid.New()
	currencyUSD, err := db.Client.FiatCurrency.
		Create().
		SetID(usdID).
		SetCode("USD").
		SetShortName("Dollar").
		SetSymbol("$").
		SetName("US Dollar").
		SetMarketRate(decimal.Zero).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create USD currency: %v", err)
	}

	// Create a test currency (EUR) with a UUID and all required fields
	eurID := uuid.New()
	currencyEUR, err := db.Client.FiatCurrency.
		Create().
		SetID(eurID).
		SetCode("EUR").
		SetShortName("Euro").
		SetSymbol("€").
		SetName("Euro").
		SetMarketRate(decimal.Zero). // Required, set to zero if not used
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create EUR currency: %v", err)
	}

	// Create provision buckets for USD
	bucket10to100, err := db.Client.ProvisionBucket.
		Create().
		SetMinAmount(decimal.NewFromInt(10)).
		SetMaxAmount(decimal.NewFromInt(100)).
		SetCurrency(currencyUSD).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create bucket 10-100: %v", err)
	}

	bucket100to1000, err := db.Client.ProvisionBucket.
		Create().
		SetMinAmount(decimal.NewFromInt(100)).
		SetMaxAmount(decimal.NewFromInt(1000)).
		SetCurrency(currencyUSD).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create bucket 100-1000: %v", err)
	}

	indexer := testCtx.indexer

	tests := []struct {
		name            string
		amount          decimal.Decimal
		currency        *ent.FiatCurrency
		wantBucket      *ent.ProvisionBucket
		wantLessThanMin bool
		wantErr         bool
		errMsg          string
	}{
		{
			name:            "matching_bucket_found_10to100",
			amount:          decimal.NewFromInt(50),
			currency:        currencyUSD,
			wantBucket:      bucket10to100,
			wantLessThanMin: false,
			wantErr:         false,
		},
		{
			name:            "matching_bucket_found_100to1000",
			amount:          decimal.NewFromInt(500),
			currency:        currencyUSD,
			wantBucket:      bucket100to1000,
			wantLessThanMin: false,
			wantErr:         false,
		},
		{
			name:            "below_minimum_bucket",
			amount:          decimal.NewFromInt(5),
			currency:        currencyUSD,
			wantBucket:      nil,
			wantLessThanMin: true,
			wantErr:         false,
		},
		{
			name:            "above_maximum_bucket",
			amount:          decimal.NewFromInt(2000), // Fixed: > 1000
			currency:        currencyUSD,
			wantBucket:      nil,
			wantLessThanMin: false,
			wantErr:         true,
			errMsg:          "failed to fetch provision bucket: ent: provision_bucket not found",
		},
		{
			name:            "no_buckets_for_currency",
			amount:          decimal.NewFromInt(50),
			currency:        currencyEUR,
			wantBucket:      nil,
			wantLessThanMin: false,
			wantErr:         true,
			errMsg:          "failed to fetch minimum bucket: ent: provision_bucket not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket, isLessThanMin, err := indexer.getProvisionBucket(ctx, tt.amount, tt.currency)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, bucket)
				assert.Equal(t, tt.wantLessThanMin, isLessThanMin)
				return
			}

			assert.NoError(t, err)
			if tt.wantBucket != nil {
				assert.Equal(t, tt.wantBucket.ID, bucket.ID)
			} else {
				assert.Nil(t, bucket)
			}
			assert.Equal(t, tt.wantLessThanMin, isLessThanMin)
		})
	}
}
