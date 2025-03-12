package services

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
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
