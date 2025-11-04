package tasks

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	_ "github.com/mattn/go-sqlite3"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/enttest"
	"github.com/paycrest/aggregator/ent/webhookretryattempt"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/test"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
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
		return fmt.Errorf("CreateERC20Token.tasks_test: %w", err)
	}

	senderProfile, err := test.CreateTestSenderProfile(map[string]interface{}{
		"user_id":     user.ID,
		"fee_percent": "5",
	})

	if err != nil {
		return fmt.Errorf("CreateTestSenderProfile.tasks_test: %w", err)
	}
	testCtx.sender = senderProfile

	paymentOrder, err := test.CreateTestPaymentOrder(backend, token, map[string]interface{}{
		"sender": senderProfile,
	})
	if err != nil {
		return fmt.Errorf("CreateTestSenderProfile.tasks_test: %w", err)
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

func TestTasks(t *testing.T) {

	// Set up test database client
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	db.Client = client

	// Setup test data
	err := setup()
	assert.NoError(t, err)

	t.Run("RetryFailedWebhookNotifications", func(t *testing.T) {
		httpmock.Activate()
		defer httpmock.Deactivate()

		// Register mock failure response for Webhook
		httpmock.RegisterResponder("POST", testCtx.sender.WebhookURL,
			func(r *http.Request) (*http.Response, error) {
				return httpmock.NewBytesResponse(400, []byte(`{"id": "01", "message": "Sent"}`)), nil
			},
		)

		// Register mock email response
		httpmock.RegisterResponder("POST", "https://api.sendgrid.com/v3/mail/send",
			func(r *http.Request) (*http.Response, error) {
				bytes, err := io.ReadAll(r.Body)
				if err != nil {
					log.Fatal(err)
				}

				// Assert email response contains userEmail and Name
				assert.Contains(t, string(bytes), testCtx.user.Email)
				assert.Contains(t, string(bytes), testCtx.user.FirstName)

				resp := httpmock.NewBytesResponse(202, nil)
				return resp, nil
			},
		)
		err := RetryFailedWebhookNotifications()
		assert.NoError(t, err)
		hook, err := db.Client.WebhookRetryAttempt.
			Query().
			Where(webhookretryattempt.IDEQ(testCtx.webhook.ID)).
			Only(context.Background())
		assert.NoError(t, err)

		assert.Equal(t, hook.Status, webhookretryattempt.StatusExpired)
	})

	t.Run("fetchExternalRate", func(t *testing.T) {
		httpmock.Activate()
		defer httpmock.Deactivate()

		// Test unsupported currency
		t.Run("UnsupportedCurrency", func(t *testing.T) {
			value, err := fetchExternalRate("KSH")
			assert.Error(t, err)
			assert.Equal(t, value, decimal.Zero)
			assert.Contains(t, err.Error(), "currency not supported")
		})

		// Test successful API response
		t.Run("SuccessfulResponse", func(t *testing.T) {
			// Mock successful response
			httpmock.RegisterResponder("GET", "https://api.rates.noblocks.xyz/rates/usdt/ngn",
				httpmock.NewStringResponder(200, `[
					{
						"stablecoin": "USDT",
						"fiat": "NGN",
						"sources": ["quidax"],
						"buyRate": 1444.36,
						"sellRate": 1451.61,
						"timestamp": "2025-11-03T13:12:50.290Z"
					}
				]`))

			value, err := fetchExternalRate("NGN")
			assert.NoError(t, err)
			expectedRate := decimal.NewFromFloat((1444.36 + 1451.61) / 2) // Average of buy and sell
			assert.True(t, value.Equal(expectedRate))
		})

		// Test API error
		t.Run("APIError", func(t *testing.T) {
			httpmock.RegisterResponder("GET", "https://api.rates.noblocks.xyz/rates/usdt/kes",
				httpmock.NewStringResponder(500, `{"error": "Internal server error"}`))

			value, err := fetchExternalRate("KES")
			assert.Error(t, err)
			assert.Equal(t, value, decimal.Zero)
			assert.Contains(t, err.Error(), "ComputeMarketRate")
		})

		// Test empty response
		t.Run("EmptyResponse", func(t *testing.T) {
			httpmock.RegisterResponder("GET", "https://api.rates.noblocks.xyz/rates/usdt/ghs",
				httpmock.NewStringResponder(200, `[]`))

			value, err := fetchExternalRate("GHS")
			assert.Error(t, err)
			assert.Equal(t, value, decimal.Zero)
			assert.Contains(t, err.Error(), "No data in the response")
		})

		// Test invalid JSON response
		t.Run("InvalidJSONResponse", func(t *testing.T) {
			httpmock.RegisterResponder("GET", "https://api.rates.noblocks.xyz/rates/usdt/mwk",
				httpmock.NewStringResponder(200, `invalid json`))

			value, err := fetchExternalRate("MWK")
			assert.Error(t, err)
			assert.Equal(t, value, decimal.Zero)
		})

		// Test malformed rate data
		t.Run("MalformedRateData", func(t *testing.T) {
			httpmock.RegisterResponder("GET", "https://api.rates.noblocks.xyz/rates/usdt/tzs",
				httpmock.NewStringResponder(200, `[
					{
						"stablecoin": "USDT",
						"fiat": "TZS",
						"sources": ["quidax"],
						"buyRate": "invalid",
						"sellRate": 1451.61,
						"timestamp": "2025-11-03T13:12:50.290Z"
					}
				]`))

			value, err := fetchExternalRate("TZS")
			assert.Error(t, err)
			assert.Equal(t, value, decimal.Zero)
			assert.Contains(t, err.Error(), "Invalid buyRate format")
		})

		// Reset httpmock after each test
		httpmock.Reset()
	})
}
