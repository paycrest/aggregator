package common

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/enttest"
	"github.com/paycrest/aggregator/ent/paymentorder"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
)

func setupTestDB(t *testing.T) (*ent.Client, func()) {
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}
	db.Client = client
	return client, func() { _ = client.Close() }
}

func createTestOrder(t *testing.T, client *ent.Client, amount float64, receiveAddress string) *ent.PaymentOrder {
	ctx := context.Background()

	network, err := client.Network.Create().
		SetIdentifier("polygon").
		SetChainID(137).
		SetRPCEndpoint("https://polygon-rpc.com").
		SetGatewayContractAddress("0xGateway").
		SetIsTestnet(false).
		SetBlockTime(decimal.NewFromFloat(2.0)).
		SetFee(decimal.NewFromFloat(0.1)).
		Save(ctx)
	assert.NoError(t, err)

	token, err := client.Token.Create().
		SetSymbol("USDT").
		SetContractAddress("0xTokenContract").
		SetDecimals(6).
		SetBaseCurrency("USD").
		SetIsEnabled(true).
		SetNetwork(network).
		Save(ctx)
	assert.NoError(t, err)

	order, err := client.PaymentOrder.Create().
		SetAmount(decimal.NewFromFloat(amount)).
		SetAmountInUsd(decimal.NewFromFloat(amount)).
		SetAmountPaid(decimal.Zero).
		SetAmountReturned(decimal.Zero).
		SetPercentSettled(decimal.Zero).
		SetNetworkFee(network.Fee).
		SetSenderFee(decimal.Zero).
		SetRate(decimal.NewFromFloat(1.0)).
		SetToken(token).
		SetReceiveAddress(receiveAddress).
		SetReceiveAddressSalt([]byte("salt")).
		SetReceiveAddressExpiry(time.Now().Add(time.Hour)).
		SetReturnAddress("0xReturnAddr").
		SetInstitution("ABNGNGLA").
		SetAccountIdentifier("1234567890").
		SetAccountName("Test Account").
		SetStatus(paymentorder.StatusInitiated).
		Save(ctx)
	assert.NoError(t, err)

	order, err = client.PaymentOrder.Query().
		Where(paymentorder.IDEQ(order.ID)).
		WithToken(func(tq *ent.TokenQuery) { tq.WithNetwork() }).
		Only(ctx)
	assert.NoError(t, err)

	return order
}

func noopCreateOrder(_ context.Context, _ uuid.UUID) error { return nil }
func noopGetProviderRate(_ context.Context, _ *ent.ProviderProfile, _ string, _ string) (decimal.Decimal, error) {
	return decimal.Zero, nil
}

func TestUpdateReceiveAddressStatus_DustTransferIgnored(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	order := createTestOrder(t, db.Client, 5.0, "0xReceiveAddr")

	dustEvent := &types.TokenTransferEvent{
		BlockNumber: 100,
		TxHash:      "0xDustTxHash",
		From:        "0xAttacker",
		To:          "0xReceiveAddr",
		Value:       decimal.NewFromFloat(0.005),
	}

	done, err := UpdateReceiveAddressStatus(
		context.Background(), order, dustEvent, noopCreateOrder, noopGetProviderRate,
	)
	assert.NoError(t, err)
	assert.False(t, done)

	// Order must still be initiated with original amount
	updated, err := db.Client.PaymentOrder.Get(context.Background(), order.ID)
	assert.NoError(t, err)
	assert.Equal(t, paymentorder.StatusInitiated, updated.Status)
	assert.True(t, updated.Amount.Equal(decimal.NewFromFloat(5.0)), "order amount should not be mutated by dust")
	assert.True(t, updated.AmountPaid.Equal(decimal.Zero), "amount paid should remain zero")
}

func TestUpdateReceiveAddressStatus_BoundaryDustIgnored(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	order := createTestOrder(t, db.Client, 5.0, "0xReceiveAddr2")

	boundaryEvent := &types.TokenTransferEvent{
		BlockNumber: 101,
		TxHash:      "0xBoundaryTxHash",
		From:        "0xAttacker",
		To:          "0xReceiveAddr2",
		Value:       decimal.NewFromFloat(0.1),
	}

	done, err := UpdateReceiveAddressStatus(
		context.Background(), order, boundaryEvent, noopCreateOrder, noopGetProviderRate,
	)
	assert.NoError(t, err)
	assert.False(t, done)

	updated, err := db.Client.PaymentOrder.Get(context.Background(), order.ID)
	assert.NoError(t, err)
	assert.Equal(t, paymentorder.StatusInitiated, updated.Status)
}

func TestUpdateReceiveAddressStatus_ValidTransferProcessed(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	order := createTestOrder(t, db.Client, 5.0, "0xReceiveAddr3")

	// order amount (5.0) + network fee (0.1) + sender fee (0) = 5.1
	validEvent := &types.TokenTransferEvent{
		BlockNumber: 102,
		TxHash:      "0xValidTxHash",
		From:        "0xSender",
		To:          "0xReceiveAddr3",
		Value:       decimal.NewFromFloat(5.1),
	}

	done, _ := UpdateReceiveAddressStatus(
		context.Background(), order, validEvent, noopCreateOrder, noopGetProviderRate,
	)
	// done==true confirms the transfer passed the dust check and was processed
	assert.True(t, done)

	updated, err := db.Client.PaymentOrder.Get(context.Background(), order.ID)
	assert.NoError(t, err)
	// Order should have moved past initiated (deposited or pending depending on tx driver)
	assert.NotEqual(t, paymentorder.StatusInitiated, updated.Status, "order should no longer be initiated")
	assert.True(t, updated.AmountPaid.GreaterThan(decimal.Zero), "amount paid should be updated")
}

func TestUpdateReceiveAddressStatus_WrongAddressIgnored(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	order := createTestOrder(t, db.Client, 5.0, "0xReceiveAddr4")

	wrongAddrEvent := &types.TokenTransferEvent{
		BlockNumber: 103,
		TxHash:      "0xWrongAddrTxHash",
		From:        "0xSender",
		To:          "0xSomeOtherAddress",
		Value:       decimal.NewFromFloat(5.1),
	}

	done, err := UpdateReceiveAddressStatus(
		context.Background(), order, wrongAddrEvent, noopCreateOrder, noopGetProviderRate,
	)
	assert.NoError(t, err)
	assert.False(t, done)

	updated, err := db.Client.PaymentOrder.Get(context.Background(), order.ID)
	assert.NoError(t, err)
	assert.Equal(t, paymentorder.StatusInitiated, updated.Status)
}

func TestUpdateReceiveAddressStatus_DuplicateTxHashIgnored(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	order := createTestOrder(t, db.Client, 5.0, "0xReceiveAddr5")

	// Pre-set a txHash on another order to simulate a duplicate
	_, err := db.Client.PaymentOrder.Create().
		SetAmount(decimal.NewFromFloat(1.0)).
		SetAmountInUsd(decimal.NewFromFloat(1.0)).
		SetAmountPaid(decimal.Zero).
		SetAmountReturned(decimal.Zero).
		SetPercentSettled(decimal.Zero).
		SetNetworkFee(decimal.Zero).
		SetSenderFee(decimal.Zero).
		SetRate(decimal.NewFromFloat(1.0)).
		SetToken(order.Edges.Token).
		SetInstitution("ABNGNGLA").
		SetAccountIdentifier("9999999999").
		SetAccountName("Dupe Account").
		SetStatus(paymentorder.StatusDeposited).
		SetTxHash("0xAlreadyIndexed").
		Save(ctx)
	assert.NoError(t, err)

	dupeEvent := &types.TokenTransferEvent{
		BlockNumber: 104,
		TxHash:      "0xAlreadyIndexed",
		From:        "0xSender",
		To:          "0xReceiveAddr5",
		Value:       decimal.NewFromFloat(5.1),
	}

	done, err := UpdateReceiveAddressStatus(
		context.Background(), order, dupeEvent, noopCreateOrder, noopGetProviderRate,
	)
	assert.NoError(t, err)
	assert.False(t, done)
}
