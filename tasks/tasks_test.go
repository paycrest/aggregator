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
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/webhookretryattempt"
	"github.com/paycrest/aggregator/services"
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

// Helper function to create test provider with specific balance
func createTestProviderWithBalance(t *testing.T, currencyCode string, availableBalance decimal.Decimal) (*ent.ProviderProfile, *ent.FiatCurrency) {
	// Create test currency
	currency, err := db.Client.FiatCurrency.
		Create().
		SetCode(currencyCode).
		SetName(fmt.Sprintf("Test %s", currencyCode)).
		SetMinimumAvailableBalance(decimal.NewFromFloat(100.0)).
		SetAlertThreshold(decimal.NewFromFloat(500.0)).
		SetCriticalThreshold(decimal.NewFromFloat(200.0)).
		Save(context.Background())
	assert.NoError(t, err)

	// Create test provider
	provider, err := db.Client.ProviderProfile.
		Create().
		SetTradingName(fmt.Sprintf("Test Provider %s", currencyCode)).
		SetIsActive(true).
		SetVisibilityMode(providerprofile.VisibilityModePublic).
		SetUser(testCtx.user).
		Save(context.Background())
	assert.NoError(t, err)

	// Create provider currency
	_, err = db.Client.ProviderCurrencies.
		Create().
		SetProvider(provider).
		SetCurrency(currency).
		SetAvailableBalance(availableBalance).
		SetReservedBalance(decimal.NewFromFloat(100.0)).
		SetTotalBalance(availableBalance.Add(decimal.NewFromFloat(100.0))).
		SetIsAvailable(true).
		Save(context.Background())
	assert.NoError(t, err)

	return provider, currency
}

// Helper function to test balance health validation
func testBalanceHealthValidation(t *testing.T, providerID, currencyCode string, expectedHealthy bool) {
	balanceService := services.NewBalanceManagementService()
	isHealthy, err := balanceService.IsProviderHealthyForCurrency(context.Background(), providerID, currencyCode)
	assert.NoError(t, err)
	assert.Equal(t, expectedHealthy, isHealthy, fmt.Sprintf("Provider health should be %v", expectedHealthy))
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
		value, err := fetchExternalRate("KSH")
		assert.Error(t, err)
		assert.Equal(t, value, decimal.Zero)
	})

	// Balance Health Check Tests
	t.Run("TestBalanceHealthChecks", func(t *testing.T) {
		// Test 1: Provider with healthy balance
		t.Run("ProviderWithHealthyBalance", func(t *testing.T) {
			t.Log("🧪 Starting ProviderWithHealthyBalance test")

			user, err := test.CreateTestUser(map[string]interface{}{
				"email": fmt.Sprintf("test-user-%d@example.com", time.Now().UnixNano()),
				"scope": "provider",
			})
			assert.NoError(t, err)
			t.Logf("✅ Created test user: %s", user.Email)

			// Create test currency with thresholds
			currency, err := db.Client.FiatCurrency.
				Create().
				SetCode("USD").
				SetName("US Dollar").
				SetShortName("USD").
				SetSymbol("$").
				SetDecimals(2).
				SetMarketRate(decimal.NewFromFloat(1.0)).
				SetMinimumAvailableBalance(decimal.NewFromFloat(100.0)).
				SetAlertThreshold(decimal.NewFromFloat(500.0)).
				SetCriticalThreshold(decimal.NewFromFloat(200.0)).
				Save(context.Background())
			assert.NoError(t, err)
			t.Logf("✅ Created test currency: %s (Code: %s, Min: %s, Alert: %s, Critical: %s)",
				currency.Name, currency.Code,
				currency.MinimumAvailableBalance.String(),
				currency.AlertThreshold.String(),
				currency.CriticalThreshold.String())

			// Create test provider
			provider, err := db.Client.ProviderProfile.
				Create().
				SetTradingName("Test Provider").
				SetIsActive(true).
				SetVisibilityMode(providerprofile.VisibilityModePublic).
				SetUser(user).
				Save(context.Background())
			assert.NoError(t, err)
			t.Logf("✅ Created test provider: %s (ID: %s)", provider.TradingName, provider.ID)

			// Create provider currency with healthy balance
			providerCurrency, err := db.Client.ProviderCurrencies.
				Create().
				SetProvider(provider).
				SetCurrency(currency).
				SetAvailableBalance(decimal.NewFromFloat(1000.0)).
				SetReservedBalance(decimal.NewFromFloat(100.0)).
				SetTotalBalance(decimal.NewFromFloat(1100.0)).
				SetIsAvailable(true).
				Save(context.Background())
			assert.NoError(t, err)
			t.Logf("✅ Created provider currency: Available=%s, Reserved=%s, Total=%s",
				providerCurrency.AvailableBalance.String(),
				providerCurrency.ReservedBalance.String(),
				providerCurrency.TotalBalance.String())

			// Test health check
			t.Log("🔍 Testing balance health check...")
			balanceService := services.NewBalanceManagementService()
			isHealthy, err := balanceService.IsProviderHealthyForCurrency(context.Background(), provider.ID, "USD")
			assert.NoError(t, err)
			assert.True(t, isHealthy, "Provider with healthy balance should be considered healthy")
			if isHealthy {
				t.Log("✅ Provider is HEALTHY - balance above all thresholds")
			} else {
				t.Log("❌ Provider is UNHEALTHY - balance below thresholds")
			}

			assert.True(t, isHealthy, "Provider with healthy balance should be considered healthy")
			t.Log("🎉 ProviderWithHealthyBalance test completed successfully")
		})

		// Test 2: Provider with critical balance
		t.Run("ProviderWithCriticalBalance", func(t *testing.T) {
			t.Log("🧪 Starting ProviderWithCriticalBalance test")

			user, err := test.CreateTestUser(map[string]interface{}{
				"email": fmt.Sprintf("test-user-%d@example.com", time.Now().UnixNano()),
				"scope": "provider",
			})
			assert.NoError(t, err)
			t.Logf("✅ Created test user: %s", user.Email)

			// Create test currency
			currency, err := db.Client.FiatCurrency.
				Create().
				SetCode("EUR").
				SetName("Euro").
				SetShortName("EUR").
				SetSymbol("€").
				SetDecimals(2).
				SetMarketRate(decimal.NewFromFloat(1.0)).
				SetMinimumAvailableBalance(decimal.NewFromFloat(50.0)).
				SetAlertThreshold(decimal.NewFromFloat(300.0)).
				SetCriticalThreshold(decimal.NewFromFloat(150.0)).
				Save(context.Background())
			assert.NoError(t, err)
			t.Logf("✅ Created test currency: %s (Code: %s, Min: %s, Alert: %s, Critical: %s)",
				currency.Name, currency.Code,
				currency.MinimumAvailableBalance.String(),
				currency.AlertThreshold.String(),
				currency.CriticalThreshold.String())

			// Create test provider
			provider, err := db.Client.ProviderProfile.
				Create().
				SetTradingName("Critical Provider").
				SetIsActive(true).
				SetVisibilityMode(providerprofile.VisibilityModePublic).
				SetUser(user).
				Save(context.Background())
			assert.NoError(t, err)
			t.Logf("✅ Created test provider: %s (ID: %s)", provider.TradingName, provider.ID)

			t.Log("🔍 Testing balance health check...")
			// Create provider currency with critical balance
			providerCurrency, err := db.Client.ProviderCurrencies.
				Create().
				SetProvider(provider).
				SetCurrency(currency).
				SetAvailableBalance(decimal.NewFromFloat(100.0)). // Below critical threshold
				SetReservedBalance(decimal.NewFromFloat(50.0)).
				SetTotalBalance(decimal.NewFromFloat(150.0)).
				SetIsAvailable(true).
				Save(context.Background())
			assert.NoError(t, err)
			t.Logf("✅ Created provider currency: Available=%s, Reserved=%s, Total=%s",
				providerCurrency.AvailableBalance.String(),
				providerCurrency.ReservedBalance.String(),
				providerCurrency.TotalBalance.String())

			// Test health check
			balanceService := services.NewBalanceManagementService()
			isHealthy, err := balanceService.IsProviderHealthyForCurrency(context.Background(), provider.ID, "EUR")
			assert.NoError(t, err)
			assert.False(t, isHealthy, "Provider with critical balance should not be considered healthy")
			if isHealthy {
				t.Log("✅ Provider is HEALTHY - balance above all thresholds")
			} else {
				t.Log("❌ Provider is UNHEALTHY - balance below thresholds")
			}
			t.Log("🎉 ProviderWithCriticalBalance test completed successfully")
		})

		// Test 3: Provider with alert threshold balance
		t.Run("ProviderWithAlertThresholdBalance", func(t *testing.T) {
			t.Log("🧪 Starting ProviderWithAlertThresholdBalance test")

			user, err := test.CreateTestUser(map[string]interface{}{
				"email": fmt.Sprintf("test-user-%d@example.com", time.Now().UnixNano()),
				"scope": "provider",
			})
			assert.NoError(t, err)
			t.Logf("✅ Created test user: %s", user.Email)

			// Create test currency
			currency, err := db.Client.FiatCurrency.
				Create().
				SetCode("GBP").
				SetName("British Pound").
				SetShortName("GBP").
				SetSymbol("£").
				SetDecimals(2).
				SetMarketRate(decimal.NewFromFloat(1.0)).
				SetMinimumAvailableBalance(decimal.NewFromFloat(75.0)).
				SetAlertThreshold(decimal.NewFromFloat(400.0)).
				SetCriticalThreshold(decimal.NewFromFloat(200.0)).
				Save(context.Background())
			assert.NoError(t, err)
			t.Logf("✅ Created test currency: %s (Code: %s, Min: %s, Alert: %s, Critical: %s)",
				currency.Name, currency.Code,
				currency.MinimumAvailableBalance.String(),
				currency.AlertThreshold.String(),
				currency.CriticalThreshold.String())

			// Create test provider
			provider, err := db.Client.ProviderProfile.
				Create().
				SetTradingName("Alert Provider").
				SetIsActive(true).
				SetVisibilityMode(providerprofile.VisibilityModePublic).
				SetUser(user).
				Save(context.Background())
			assert.NoError(t, err)
			t.Logf("✅ Created test provider: %s (ID: %s)", provider.TradingName, provider.ID)

			t.Log("🔍 Testing balance health check...")
			// Create provider currency with alert threshold balance
			providerCurrency, err := db.Client.ProviderCurrencies.
				Create().
				SetProvider(provider).
				SetCurrency(currency).
				SetAvailableBalance(decimal.NewFromFloat(350.0)). // Below alert threshold
				SetReservedBalance(decimal.NewFromFloat(50.0)).
				SetTotalBalance(decimal.NewFromFloat(400.0)).
				SetIsAvailable(true).
				Save(context.Background())
			assert.NoError(t, err)
			t.Logf("✅ Created provider currency: Available=%s, Reserved=%s, Total=%s",
				providerCurrency.AvailableBalance.String(),
				providerCurrency.ReservedBalance.String(),
				providerCurrency.TotalBalance.String())

			// Test health check
			balanceService := services.NewBalanceManagementService()
			isHealthy, err := balanceService.IsProviderHealthyForCurrency(context.Background(), provider.ID, "GBP")
			assert.NoError(t, err)
			assert.False(t, isHealthy, "Provider with alert threshold balance should not be considered healthy")
			if isHealthy {
				t.Log("✅ Provider is HEALTHY - balance above all thresholds")
			} else {
				t.Log("❌ Provider is UNHEALTHY - balance below thresholds")
			}
			t.Log("🎉 ProviderWithAlertThresholdBalance test completed successfully")
		})

		// Test 4: Provider with insufficient balance for order
		t.Run("ProviderWithInsufficientBalanceForOrder", func(t *testing.T) {
			t.Log("🧪 Starting ProviderWithInsufficientBalanceForOrder test")

			user, err := test.CreateTestUser(map[string]interface{}{
				"email": fmt.Sprintf("test-user-%d@example.com", time.Now().UnixNano()),
				"scope": "provider",
			})
			assert.NoError(t, err)
			t.Logf("✅ Created test user: %s", user.Email)

			// Create test currency
			currency, err := db.Client.FiatCurrency.
				Create().
				SetCode("CAD").
				SetName("Canadian Dollar").
				SetShortName("CAD").
				SetSymbol("CA$").
				SetDecimals(2).
				SetMarketRate(decimal.NewFromFloat(1.0)).
				SetMinimumAvailableBalance(decimal.NewFromFloat(100.0)).
				SetAlertThreshold(decimal.NewFromFloat(500.0)).
				SetCriticalThreshold(decimal.NewFromFloat(250.0)).
				Save(context.Background())
			assert.NoError(t, err)
			t.Logf("✅ Created test currency: %s (Code: %s, Min: %s, Alert: %s, Critical: %s)",
				currency.Name, currency.Code,
				currency.MinimumAvailableBalance.String(),
				currency.AlertThreshold.String(),
				currency.CriticalThreshold.String())

			// Create test provider
			provider, err := db.Client.ProviderProfile.
				Create().
				SetTradingName("Insufficient Provider").
				SetIsActive(true).
				SetVisibilityMode(providerprofile.VisibilityModePublic).
				SetUser(user).
				Save(context.Background())
			assert.NoError(t, err)
			t.Logf("✅ Created test provider: %s (ID: %s)", provider.TradingName, provider.ID)

			t.Log("🔍 Testing balance sufficiency for large order...")
			// Create provider currency with insufficient balance
			providerCurrency, err := db.Client.ProviderCurrencies.
				Create().
				SetProvider(provider).
				SetCurrency(currency).
				SetAvailableBalance(decimal.NewFromFloat(300.0)). // Above thresholds but insufficient for large order
				SetReservedBalance(decimal.NewFromFloat(50.0)).
				SetTotalBalance(decimal.NewFromFloat(350.0)).
				SetIsAvailable(true).
				Save(context.Background())
			assert.NoError(t, err)
			t.Logf("✅ Created provider currency: Available=%s, Reserved=%s, Total=%s",
				providerCurrency.AvailableBalance.String(),
				providerCurrency.ReservedBalance.String(),
				providerCurrency.TotalBalance.String())

			// Test balance sufficiency for large order
			balanceService := services.NewBalanceManagementService()
			hasBalance, err := balanceService.HasSufficientBalance(context.Background(), provider.ID, "CAD", decimal.NewFromFloat(250.0))
			assert.NoError(t, err)
			assert.False(t, hasBalance, "Provider should not have sufficient balance for order that would leave them below minimum threshold")
			if hasBalance {
				t.Log("✅ Provider has sufficient balance for order")
			} else {
				t.Log("❌ Provider does not have sufficient balance for order")
			}
			t.Log("🎉 ProviderWithInsufficientBalanceForOrder test completed successfully")
		})

		// Test 5: Get healthy providers for currency
		t.Run("GetHealthyProvidersForCurrency", func(t *testing.T) {
			t.Log("🧪 Starting GetHealthyProvidersForCurrency test")

			// Create unique users for this test with unique emails and add a small delay
			healthyUser, err := test.CreateTestUser(map[string]interface{}{
				"email": fmt.Sprintf("healthy-user-%d@example.com", time.Now().UnixNano()),
			})
			assert.NoError(t, err)
			t.Logf("✅ Created test user: %s", healthyUser.Email)
			// Add a small delay to ensure unique timestamps
			time.Sleep(1 * time.Millisecond)

			unhealthyUser, err := test.CreateTestUser(map[string]interface{}{
				"email": fmt.Sprintf("unhealthy-user-%d@example.com", time.Now().UnixNano()),
			})
			assert.NoError(t, err)

			t.Logf("✅ Created test user: %s", unhealthyUser.Email)
			// Create test currency
			currency, err := db.Client.FiatCurrency.
				Create().
				SetCode("JPY").
				SetName("Japanese Yen").
				SetShortName("JPY").
				SetSymbol("¥").
				SetDecimals(0).
				SetMarketRate(decimal.NewFromFloat(110.0)).
				SetIsEnabled(true).
				SetMinimumAvailableBalance(decimal.NewFromFloat(1000.0)).
				SetAlertThreshold(decimal.NewFromFloat(5000.0)).
				SetCriticalThreshold(decimal.NewFromFloat(2000.0)).
				Save(context.Background())
			assert.NoError(t, err)

			t.Logf("✅ Created test currency: %s (Code: %s, Min: %s, Alert: %s, Critical: %s)",
				currency.Name, currency.Code,
				currency.MinimumAvailableBalance.String(),
				currency.AlertThreshold.String(),
				currency.CriticalThreshold.String())
			// Create healthy provider
			healthyProvider, err := db.Client.ProviderProfile.
				Create().
				SetTradingName("Healthy Provider").
				SetIsActive(true).
				SetVisibilityMode(providerprofile.VisibilityModePublic).
				SetUser(healthyUser).
				Save(context.Background())
			assert.NoError(t, err)

			t.Logf("✅ Created healthy provider: %s (ID: %s)", healthyProvider.TradingName, healthyProvider.ID)
			// Create provider currency for healthy provider
			providerCurrency, err := db.Client.ProviderCurrencies.
				Create().
				SetProvider(healthyProvider).
				SetCurrency(currency).
				SetAvailableBalance(decimal.NewFromFloat(10000.0)).
				SetReservedBalance(decimal.NewFromFloat(1000.0)).
				SetTotalBalance(decimal.NewFromFloat(11000.0)).
				SetIsAvailable(true).
				Save(context.Background())
			assert.NoError(t, err)

			t.Logf("✅ Created provider currency: Available=%s, Reserved=%s, Total=%s",
				providerCurrency.AvailableBalance.String(),
				providerCurrency.ReservedBalance.String(),
				providerCurrency.TotalBalance.String())
			// Create unhealthy provider
			unhealthyProvider, err := db.Client.ProviderProfile.
				Create().
				SetTradingName("Unhealthy Provider").
				SetIsActive(true).
				SetVisibilityMode(providerprofile.VisibilityModePublic).
				SetUser(unhealthyUser).
				Save(context.Background())
			assert.NoError(t, err)

			t.Logf("✅ Created unhealthy provider: %s (ID: %s)", unhealthyProvider.TradingName, unhealthyProvider.ID)
			// Create provider currency for unhealthy provider
			providerCurrency, err = db.Client.ProviderCurrencies.
				Create().
				SetProvider(unhealthyProvider).
				SetCurrency(currency).
				SetAvailableBalance(decimal.NewFromFloat(1000.0)). // Below critical threshold
				SetReservedBalance(decimal.NewFromFloat(500.0)).
				SetTotalBalance(decimal.NewFromFloat(1500.0)).
				SetIsAvailable(true).
				Save(context.Background())
			assert.NoError(t, err)

			t.Logf("✅ Created provider currency: Available=%s, Reserved=%s, Total=%s",
				providerCurrency.AvailableBalance.String(),
				providerCurrency.ReservedBalance.String(),
				providerCurrency.TotalBalance.String())
			// Test getting healthy providers
			balanceService := services.NewBalanceManagementService()
			healthyProviders, err := balanceService.GetHealthyProvidersForCurrency(context.Background(), "JPY")
			assert.NoError(t, err)
			assert.Len(t, healthyProviders, 1, "Should return only healthy providers")
			assert.Equal(t, healthyProvider.ID, healthyProviders[0].ID, "Should return the healthy provider")
			if len(healthyProviders) == 1 {
				t.Log("✅ Should return only healthy provider")
			} else {
				t.Log("❌ Should return only healthy provider")
			}
			t.Log("🎉 GetHealthyProvidersForCurrency test completed successfully")
		})
	})
}
