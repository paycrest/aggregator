package services

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/enttest"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/receiveaddress"
	"github.com/paycrest/aggregator/ent/senderordertoken"
	"github.com/paycrest/aggregator/ent/senderprofile"
	tokenDB "github.com/paycrest/aggregator/ent/token"

	"github.com/paycrest/aggregator/services/contracts"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
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

	// Create a test token
	token, err := test.CreateERC20Token(
		client,
		map[string]interface{}{})
	if err != nil {
		return err
	}
	time.Sleep(time.Duration(time.Duration(rand.Intn(5)) * time.Second))

	// Create smart address
	address, salt, err := test.CreateSmartAddress(
		context.Background(), client)
	if err != nil {
		return fmt.Errorf("CreateSmartAddress.setup.indexer_test: %w", err)
	}

	// Create receive address
	receiveAddress, err := db.Client.ReceiveAddress.
		Create().
		SetAddress(address).
		SetSalt(salt).
		SetStatus(receiveaddress.StatusUnused).
		SetValidUntil(time.Now().Add(time.Millisecond * 5)).
		Save(context.Background())
	if err != nil {
		return fmt.Errorf("CreateReceiveAddress.setup.indexer_test: %w", err)
	}

	testCtx.receiveAddress = receiveAddress

	time.Sleep(time.Duration(time.Duration(rand.Intn(10)) * time.Second))

	// Create a test api key
	user, err := test.CreateTestUser(nil)
	if err != nil {
		return fmt.Errorf("CreateTestUser.setup.indexer_test: %w", err)
	}

	senderProfile, err := test.CreateTestSenderProfile(map[string]interface{}{
		"user_id": user.ID,
		"token":   token.Symbol,
	})
	if err != nil {
		return fmt.Errorf("CreateTestSenderProfile.setup.indexer_test: %w", err)
	}

	apiKeyService := NewAPIKeyService()
	_, _, err = apiKeyService.GenerateAPIKey(
		context.Background(),
		nil,
		senderProfile,
		nil,
	)
	if err != nil {
		return fmt.Errorf("GenerateAPIKey.setup.indexer_test: %w", err)
	}

	// find sender token
	senderToken, err := db.Client.SenderOrderToken.
		Query().
		Where(
			senderordertoken.HasSenderWith(senderprofile.IDEQ(senderProfile.ID)),
			senderordertoken.HasTokenWith(tokenDB.IDEQ(token.ID)),
		).
		Only(context.Background())

	if err != nil {
		return fmt.Errorf("Mine %w", err)
	}

	// Create a payment order
	amount := decimal.NewFromFloat(29.93)
	protocolFee := amount.Mul(decimal.NewFromFloat(0.001)) // 0.1% protocol fee

	paymentOrder, err := db.Client.PaymentOrder.
		Create().
		SetSenderProfile(senderProfile).
		SetAmount(amount).
		SetAmountPaid(decimal.NewFromInt(0)).
		SetAmountReturned(decimal.NewFromInt(0)).
		SetSenderFee(decimal.NewFromInt(0)).
		SetNetworkFee(token.Edges.Network.Fee).
		SetProtocolFee(protocolFee). // 0.1% protocol fee
		SetPercentSettled(decimal.NewFromInt(0)).
		SetRate(decimal.NewFromInt(750)).
		SetToken(token).
		SetReceiveAddress(receiveAddress).
		SetReceiveAddressText(receiveAddress.Address).
		SetFeePercent(senderToken.FeePercent).
		SetFeeAddress(senderToken.FeeAddress).
		Save(context.Background())
	if err != nil {
		return fmt.Errorf("setup,paymentOrder  %w", err)
	}
	testCtx.paymentOrder = paymentOrder

	// Create payment order recipient
	_, err = db.Client.PaymentOrderRecipient.
		Create().
		SetInstitution("ABNGNGLA").
		SetAccountIdentifier("1234567890").
		SetAccountName("John Doe").
		SetProviderID("").
		SetMemo("P#PShola Kehinde - rent for May 2021").
		SetPaymentOrder(paymentOrder).
		Save(context.Background())
	if err != nil {
		return fmt.Errorf("PaymentOrderRecipient.setup.indexer_test: %w", err)
	}

	// Fund receive address
	amountWithFees := amount.Add(paymentOrder.ProtocolFee).Add(paymentOrder.NetworkFee).Add(paymentOrder.SenderFee)
	err = test.FundAddressWithERC20Token(
		client,
		common.HexToAddress(token.ContractAddress),
		utils.ToSubunit(amountWithFees, token.Decimals),
		common.HexToAddress(receiveAddress.Address),
	)
	if err != nil {
		return fmt.Errorf("FundAddressWithERC20Token.setup.indexer_test: %w", err)
	}

	// Create a mock instance of the OrderService
	mockOrderService := &test.MockOrderService{}

	indexer := NewIndexerService(mockOrderService)
	testCtx.indexer = indexer.(*IndexerService)

	return nil
}

func TestIndexer(t *testing.T) {
	ctx := context.Background()

	// Set up test database client
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	db.Client = client

	// Setup test data
	err := setup()
	assert.NoError(t, err)

	// Index ERC20 transfers for the receive address
	err = IndexERC20Transfer(context.Background(), testCtx.rpcClient, testCtx.receiveAddress)
	assert.NoError(t, err)

	// Fetch receiveAddress from db
	receiveAddress, err := db.Client.ReceiveAddress.
		Query().
		Where(receiveaddress.AddressEQ(testCtx.receiveAddress.Address)).
		Only(ctx)
	assert.NoError(t, err)

	// Assert state changes after indexing
	assert.Equal(t, receiveaddress.StatusUsed, receiveAddress.Status)
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

// IndexERC20Transfer indexes ERC20 transfers for a receive address
func IndexERC20Transfer(ctx context.Context, client types.RPCClient, receiveAddress *ent.ReceiveAddress) error {
	var err error

	// Fetch payment order from db
	order, err := db.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.HasReceiveAddressWith(
				receiveaddress.AddressEQ(receiveAddress.Address),
			),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithRecipient().
		Only(ctx)
	if err != nil {
		return fmt.Errorf("IndexERC20Transfer.db: %w", err)
	}

	// Initialize contract filterer
	filterer, err := contracts.NewERC20TokenFilterer(common.HexToAddress(order.Edges.Token.ContractAddress), client)
	if err != nil {
		return fmt.Errorf("IndexERC20Transfer.NewERC20TokenFilterer: %w", err)
	}

	// Fetch current block header
	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		fmt.Println("IndexMissedBlocks.HeaderByNumber: %w", err)
	}
	toBlock := header.Number.Uint64()

	// Fetch logs
	var iter *contracts.ERC20TokenTransferIterator
	retryErr := utils.Retry(3, 8*time.Second, func() error {
		var err error
		iter, err = filterer.FilterTransfer(&bind.FilterOpts{
			Start: 1,
			End:   &toBlock,
		}, nil, []common.Address{common.HexToAddress(receiveAddress.Address)})
		return err
	})
	if retryErr != nil {
		return fmt.Errorf("IndexERC20Transfer.ERC20TokenTransferIterator: %v, start BlockNumber: %d, end BlockNumber: %d", retryErr, 1, toBlock)
	}

	// Iterate over logs
	for iter.Next() {
		transferEvent := &types.TokenTransferEvent{
			BlockNumber: iter.Event.Raw.BlockNumber,
			TxHash:      iter.Event.Raw.TxHash.Hex(),
			From:        iter.Event.From.Hex(),
			To:          iter.Event.To.Hex(),
			Value:       iter.Event.Value,
		}
		ok, err := testCtx.indexer.UpdateReceiveAddressStatus(ctx, client, receiveAddress, order, transferEvent)
		if err != nil {
			return fmt.Errorf("IndexERC20Transfer.UpdateReceiveAddressStatus: %w", err)
		}
		if ok {
			return nil
		}
	}

	return nil
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
