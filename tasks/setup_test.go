package tasks

import (
	"context"
	"fmt"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/enttest"
	"github.com/paycrest/aggregator/ent/paymentorder"
	tokenEnt "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/webhookretryattempt"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/test"
	"github.com/shopspring/decimal"
)

var testCtx = struct {
	sender  *ent.SenderProfile
	user    *ent.User
	webhook *ent.WebhookRetryAttempt
}{}

func setup() error {
	// Set up test data
	user, err := test.CreateTestUser(map[string]interface{}{})
	if err != nil {
		return err
	}

	testCtx.user = user

	// Create Network first (skip blockchain connection)
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
		return fmt.Errorf("CreateNetwork.tasks_test: %w", err)
	}

	// Create token directly without blockchain
	tokenId, err := db.Client.Token.
		Create().
		SetSymbol("TST").
		SetContractAddress("0xd4E96eF8eee8678dBFf4d535E033Ed1a4F7605b7").
		SetDecimals(6).
		SetNetworkID(networkId).
		SetIsEnabled(true).
		SetBaseCurrency("NGN").
		OnConflict().
		UpdateNewValues().
		ID(context.Background())
	if err != nil {
		return fmt.Errorf("CreateToken.tasks_test: %w", err)
	}

	token, err := db.Client.Token.
		Query().
		Where(tokenEnt.IDEQ(tokenId)).
		WithNetwork().
		Only(context.Background())
	if err != nil {
		return fmt.Errorf("GetToken.tasks_test: %w", err)
	}

	senderProfile, err := test.CreateTestSenderProfile(map[string]interface{}{
		"user_id":     user.ID,
		"fee_percent": "5",
	})

	if err != nil {
		return fmt.Errorf("CreateTestSenderProfile.tasks_test: %w", err)
	}
	testCtx.sender = senderProfile

	// Create payment order directly without blockchain dependency
	paymentOrder, err := db.Client.PaymentOrder.
		Create().
		SetSenderProfile(senderProfile).
		SetAmount(decimal.NewFromFloat(100.50)).
		SetAmountInUsd(decimal.NewFromFloat(100.50)).
		SetAmountPaid(decimal.Zero).
		SetAmountReturned(decimal.Zero).
		SetPercentSettled(decimal.Zero).
		SetNetworkFee(token.Edges.Network.Fee).
		SetSenderFee(decimal.NewFromFloat(5.0)).
		SetToken(token).
		SetRate(decimal.NewFromFloat(750.0)).
		SetReceiveAddress("0x1234567890123456789012345678901234567890").
		SetReceiveAddressSalt([]byte("test_salt")).
		SetReceiveAddressExpiry(time.Now().Add(time.Hour)).
		SetFeePercent(decimal.NewFromFloat(5.0)).
		SetFeeAddress("0x1234567890123456789012345678901234567890").
		SetReturnAddress("0x0987654321098765432109876543210987654321").
		SetInstitution("ABNGNGLA").
		SetAccountIdentifier("1234567890").
		SetAccountName("Test Account").
		SetMemo("Shola Kehinde - rent for May 2021").
		SetStatus(paymentorder.StatusPending).
		Save(context.Background())
	if err != nil {
		return fmt.Errorf("CreatePaymentOrder.tasks_test: %w", err)
	}
	if err != nil {
		return fmt.Errorf("CreatePaymentOrderRecipient.tasks_test: %w", err)
	}

	// Create the payload
	payloadStruct := types.PaymentOrderWebhookPayload{
		Event: "Test_events",
		Data: types.PaymentOrderWebhookData{
			ID:             paymentOrder.ID,
			Amount:         paymentOrder.Amount,
			AmountPaid:     paymentOrder.AmountPaid,
			AmountReturned: paymentOrder.AmountReturned,
			PercentSettled: paymentOrder.PercentSettled,
			SenderFee:      paymentOrder.SenderFee,
			NetworkFee:     paymentOrder.NetworkFee,
			Rate:           paymentOrder.Rate,
			Network:        token.Edges.Network.Identifier,
			GatewayID:      paymentOrder.GatewayID,
			SenderID:       senderProfile.ID,
			Recipient: types.PaymentOrderRecipient{
				Institution:       "",
				AccountIdentifier: "",
				AccountName:       "021",
				ProviderID:        "",
				Memo:              "",
			},
			FromAddress:   paymentOrder.FromAddress,
			ReturnAddress: paymentOrder.ReturnAddress,
			UpdatedAt:     paymentOrder.UpdatedAt,
			CreatedAt:     paymentOrder.CreatedAt,
			TxHash:        paymentOrder.TxHash,
			Status:        paymentOrder.Status,
		},
	}
	payload := utils.StructToMap(payloadStruct)
	hook, err := db.Client.WebhookRetryAttempt.
		Create().
		SetAttemptNumber(3).
		SetNextRetryTime(time.Now().Add(25 * time.Hour)).
		SetPayload(payload).
		SetSignature("").
		SetWebhookURL(senderProfile.WebhookURL).
		SetNextRetryTime(time.Now().Add(-10 * time.Minute)).
		SetCreatedAt(time.Now().Add(-25 * time.Hour)).
		SetStatus(webhookretryattempt.StatusFailed).
		Save(context.Background())

	testCtx.webhook = hook
	if err != nil {
		return fmt.Errorf("CreateTestSenderProfile.WebhookRetryAttempt: %w", err)
	}

	return nil
}

func setupTestDB(t *testing.T) func() {
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")

	// Run migrations to create all tables
	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatalf("Failed to create database schema: %v", err)
	}

	db.Client = client

	// Setup test data
	if err := setup(); err != nil {
		t.Fatalf("Failed to setup test data: %v", err)
	}

	return func() {
		_ = client.Close()
	}
}
