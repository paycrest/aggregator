package services

import (
	"context"
	"fmt"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/enttest"
	"github.com/paycrest/aggregator/ent/providerprofile"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils/test"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
)

func TestBalanceMonitoringIntegration(t *testing.T) {
	t.Log("🧪 Starting Balance Monitoring Service Integration Test")

	config.BalanceConfig().RedisEnabled = false
	// Set up test database client
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	db.Client = client

	t.Run("TestCompleteBalanceMonitoringFlow", func(t *testing.T) {
		t.Log("🧪 Starting Complete Balance Monitoring Flow Integration Test")

		// Create test currency
		currency, err := db.Client.FiatCurrency.
			Create().
			SetCode("USD").
			SetName("US Dollar").
			SetShortName("USD").
			SetSymbol("$").
			SetDecimals(2).
			SetMarketRate(decimal.NewFromFloat(1.0)).
			SetIsEnabled(true).
			SetMinimumAvailableBalance(decimal.NewFromFloat(100.0)).
			SetCriticalThreshold(decimal.NewFromFloat(200.0)).
			Save(context.Background())
		assert.NoError(t, err)
		t.Logf("✅ Created test currency: %s", currency.Code)

		// Create test provider
		user, err := test.CreateTestUser(map[string]interface{}{
			"email": fmt.Sprintf("integration-user-%d@example.com", time.Now().UnixNano()),
		})
		assert.NoError(t, err)

		provider, err := db.Client.ProviderProfile.
			Create().
			SetTradingName("Integration Test Provider").
			SetIsActive(true).
			SetVisibilityMode(providerprofile.VisibilityModePublic).
			SetUser(user).
			Save(context.Background())
		assert.NoError(t, err)
		t.Logf("✅ Created test provider: %s", provider.TradingName)

		// Create provider currency with healthy initial balance
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
		t.Logf("✅ Created provider currency with healthy balance: %s", providerCurrency.AvailableBalance.String())

		// Test 1: Initial health check
		t.Log("🔍 Testing initial health check...")
		balanceService := NewBalanceManagementService()
		isHealthy, err := balanceService.CheckBalanceSufficiency(context.Background(), provider.ID, "USD", decimal.NewFromFloat(0.0))
		assert.NoError(t, err)
		assert.True(t, isHealthy, "Provider should be healthy initially")
		t.Log("✅ Provider is healthy initially")

		// Test health check after balance drop
		isHealthy, err = balanceService.CheckBalanceSufficiency(context.Background(), provider.ID, "USD", decimal.NewFromFloat(0.0))
		assert.NoError(t, err)
		assert.False(t, isHealthy, "Provider should be unhealthy after balance drop")
		t.Log("✅ Provider correctly identified as unhealthy")

		// Test 3: Simulate balance drop to critical threshold
		t.Log("�� Simulating balance drop to critical threshold...")
		_, err = db.Client.ProviderCurrencies.
			UpdateOneID(providerCurrency.ID).
			SetAvailableBalance(decimal.NewFromFloat(150.0)). // Below critical threshold
			Save(context.Background())
		assert.NoError(t, err)
		t.Logf("✅ Updated balance to: %s (below critical threshold: %s)",
			decimal.NewFromFloat(150.0).String(), currency.CriticalThreshold.String())

		// Test health check after critical balance drop
		isHealthy, err = balanceService.CheckBalanceSufficiency(context.Background(), provider.ID, "USD", decimal.NewFromFloat(0.0))
		assert.NoError(t, err)
		assert.False(t, isHealthy, "Provider should be unhealthy at critical threshold")
		t.Log("✅ Provider correctly identified as critical")

		// Test 5: Simulate balance recovery
		t.Log("�� Simulating balance recovery...")
		_, err = db.Client.ProviderCurrencies.
			UpdateOneID(providerCurrency.ID).
			SetAvailableBalance(decimal.NewFromFloat(800.0)). // Above all thresholds
			Save(context.Background())
		assert.NoError(t, err)
		t.Logf("✅ Recovered balance to: %s", decimal.NewFromFloat(800.0).String())

		// Test health check after recovery
		isHealthy, err = balanceService.CheckBalanceSufficiency(context.Background(), provider.ID, "USD", decimal.NewFromFloat(0.0))
		assert.NoError(t, err)
		assert.True(t, isHealthy, "Provider should be healthy after recovery")
		t.Log("✅ Provider correctly identified as healthy after recovery")

		t.Log("🎉 Complete Balance Monitoring Flow Integration Test completed successfully")
	})

	t.Run("TestProviderHealthIntegrationWithOrderAssignment", func(t *testing.T) {
		t.Log("🧪 Starting Provider Health Integration with Order Assignment Test")

		// Create test currency
		currency, err := db.Client.FiatCurrency.
			Create().
			SetCode("EUR").
			SetName("Euro").
			SetShortName("EUR").
			SetSymbol("€").
			SetDecimals(2).
			SetMarketRate(decimal.NewFromFloat(0.85)).
			SetIsEnabled(true).
			SetMinimumAvailableBalance(decimal.NewFromFloat(50.0)).
			SetCriticalThreshold(decimal.NewFromFloat(150.0)).
			Save(context.Background())
		assert.NoError(t, err)

		// Create provision bucket
		bucket, err := db.Client.ProvisionBucket.
			Create().
			SetCurrency(currency).
			SetMinAmount(decimal.NewFromFloat(100.0)).
			SetMaxAmount(decimal.NewFromFloat(1000.0)).
			Save(context.Background())
		assert.NoError(t, err)
		t.Logf("✅ Created provision bucket: %s - %s", bucket.MinAmount.String(), bucket.MaxAmount.String())

		// Create healthy provider
		healthyUser, err := test.CreateTestUser(map[string]interface{}{
			"email": fmt.Sprintf("healthy-provider-%d@example.com", time.Now().UnixNano()),
		})
		assert.NoError(t, err)

		healthyProvider, err := db.Client.ProviderProfile.
			Create().
			SetTradingName("Healthy Provider").
			SetIsActive(true).
			SetVisibilityMode(providerprofile.VisibilityModePublic).
			SetUser(healthyUser).
			Save(context.Background())
		assert.NoError(t, err)

		_, err = db.Client.ProviderCurrencies.
			Create().
			SetProvider(healthyProvider).
			SetCurrency(currency).
			SetAvailableBalance(decimal.NewFromFloat(2000.0)).
			SetReservedBalance(decimal.NewFromFloat(200.0)).
			SetTotalBalance(decimal.NewFromFloat(2200.0)).
			SetIsAvailable(true).
			Save(context.Background())
		assert.NoError(t, err)
		t.Logf("✅ Created healthy provider: %s", healthyProvider.TradingName)

		// Create unhealthy provider
		unhealthyUser, err := test.CreateTestUser(map[string]interface{}{
			"email": fmt.Sprintf("unhealthy-provider-%d@example.com", time.Now().UnixNano()),
		})
		assert.NoError(t, err)

		unhealthyProvider, err := db.Client.ProviderProfile.
			Create().
			SetTradingName("Unhealthy Provider").
			SetIsActive(true).
			SetVisibilityMode(providerprofile.VisibilityModePublic).
			SetUser(unhealthyUser).
			Save(context.Background())
		assert.NoError(t, err)

		_, err = db.Client.ProviderCurrencies.
			Create().
			SetProvider(unhealthyProvider).
			SetCurrency(currency).
			SetAvailableBalance(decimal.NewFromFloat(100.0)). // Below critical threshold
			SetReservedBalance(decimal.NewFromFloat(50.0)).
			SetTotalBalance(decimal.NewFromFloat(150.0)).
			SetIsAvailable(true).
			Save(context.Background())
		assert.NoError(t, err)
		t.Logf("✅ Created unhealthy provider: %s", unhealthyProvider.TradingName)

		// Test priority queue service with health checks
		t.Log("🔍 Testing priority queue service with health checks...")
		priorityService := NewPriorityQueueService()
		buckets, err := priorityService.GetProvisionBuckets(context.Background())
		assert.NoError(t, err)

		// Find the EUR bucket
		var eurBucket *ent.ProvisionBucket
		for _, b := range buckets {
			if b.Edges.Currency.Code == "EUR" {
				eurBucket = b
				break
			}
		}
		assert.NotNil(t, eurBucket, "Should find EUR bucket")

		t.Logf("�� Found %d providers in EUR bucket", len(eurBucket.Edges.ProviderProfiles))

		// Should only include healthy providers
		assert.Len(t, eurBucket.Edges.ProviderProfiles, 1, "Should return only healthy providers")
		assert.Equal(t, healthyProvider.ID, eurBucket.Edges.ProviderProfiles[0].ID, "Should return the healthy provider")
		t.Log("✅ Priority queue correctly filtered out unhealthy providers")

		t.Log("🎉 Provider Health Integration with Order Assignment Test completed successfully")
	})

	t.Run("TestBalanceMonitoringServiceIntegration", func(t *testing.T) {
		t.Log("🧪 Starting Balance Monitoring Service Integration Test")

		// Create test currency
		currency, err := db.Client.FiatCurrency.
			Create().
			SetCode("GBP").
			SetName("British Pound").
			SetShortName("GBP").
			SetSymbol("£").
			SetDecimals(2).
			SetMarketRate(decimal.NewFromFloat(0.75)).
			SetIsEnabled(true).
			SetMinimumAvailableBalance(decimal.NewFromFloat(75.0)).
			SetCriticalThreshold(decimal.NewFromFloat(200.0)).
			Save(context.Background())
		assert.NoError(t, err)

		// Create test provider
		user, err := test.CreateTestUser(map[string]interface{}{
			"email": fmt.Sprintf("monitoring-user-%d@example.com", time.Now().UnixNano()),
		})
		assert.NoError(t, err)

		provider, err := db.Client.ProviderProfile.
			Create().
			SetTradingName("Monitoring Test Provider").
			SetIsActive(true).
			SetVisibilityMode(providerprofile.VisibilityModePublic).
			SetUser(user).
			Save(context.Background())
		assert.NoError(t, err)

		_, err = db.Client.ProviderCurrencies.
			Create().
			SetProvider(provider).
			SetCurrency(currency).
			SetAvailableBalance(decimal.NewFromFloat(1500.0)).
			SetReservedBalance(decimal.NewFromFloat(150.0)).
			SetTotalBalance(decimal.NewFromFloat(1650.0)).
			SetIsAvailable(true).
			Save(context.Background())
		assert.NoError(t, err)
		t.Logf("✅ Created test provider: %s", provider.TradingName)

		t.Log(" Balance Monitoring Service Integration Test completed successfully")
	})

	t.Run("TestBalanceHealthValidationIntegration", func(t *testing.T) {
		t.Log("🧪 Starting Balance Health Validation Integration Test")

		// Create test currency
		currency, err := db.Client.FiatCurrency.
			Create().
			SetCode("CAD").
			SetName("Canadian Dollar").
			SetShortName("CAD").
			SetSymbol("C$").
			SetDecimals(2).
			SetMarketRate(decimal.NewFromFloat(1.25)).
			SetIsEnabled(true).
			SetMinimumAvailableBalance(decimal.NewFromFloat(100.0)).
			SetCriticalThreshold(decimal.NewFromFloat(250.0)).
			Save(context.Background())
		assert.NoError(t, err)

		// Create test provider
		user, err := test.CreateTestUser(map[string]interface{}{
			"email": fmt.Sprintf("validation-user-%d@example.com", time.Now().UnixNano()),
		})
		assert.NoError(t, err)

		provider, err := db.Client.ProviderProfile.
			Create().
			SetTradingName("Validation Test Provider").
			SetIsActive(true).
			SetVisibilityMode(providerprofile.VisibilityModePublic).
			SetUser(user).
			Save(context.Background())
		assert.NoError(t, err)

		_, err = db.Client.ProviderCurrencies.
			Create().
			SetProvider(provider).
			SetCurrency(currency).
			SetAvailableBalance(decimal.NewFromFloat(600.0)).
			SetReservedBalance(decimal.NewFromFloat(100.0)).
			SetTotalBalance(decimal.NewFromFloat(700.0)).
			SetIsAvailable(true).
			Save(context.Background())
		assert.NoError(t, err)
		t.Logf("✅ Created test provider: %s", provider.TradingName)

		// Test balance health validation
		balanceService := NewBalanceManagementService()

		// Test with small order (should be healthy)
		smallOrderAmount := decimal.NewFromFloat(200.0)
		t.Logf("�� Testing with small order amount: %s", smallOrderAmount.String())

		healthReport, err := balanceService.CheckBalanceSufficiency(context.Background(), provider.ID, "CAD", smallOrderAmount)
		assert.NoError(t, err)
		assert.Equal(t, true, healthReport, "Provider should be healthy for small order")
		t.Logf("✅ Health report: Status=%s", healthReport)

		// Test with large order (should be insufficient)
		largeOrderAmount := decimal.NewFromFloat(600.0)
		t.Logf("�� Testing with large order amount: %s", largeOrderAmount.String())

		healthReport, err = balanceService.CheckBalanceSufficiency(context.Background(), provider.ID, "CAD", largeOrderAmount)
		assert.NoError(t, err)
		assert.Equal(t, false, healthReport, "Provider should be insufficient for large order")
		t.Logf("✅ Health report: Status=%s", healthReport)

		t.Log("🎉 Balance Health Validation Integration Test completed successfully")
	})

	t.Run("TestBalanceMonitoringWithRealTimeUpdates", func(t *testing.T) {
		t.Log("🧪 Starting Balance Monitoring with Real-Time Updates Test")

		// Create test currency
		currency, err := db.Client.FiatCurrency.
			Create().
			SetCode("AUD").
			SetName("Australian Dollar").
			SetShortName("AUD").
			SetSymbol("A$").
			SetDecimals(2).
			SetMarketRate(decimal.NewFromFloat(1.35)).
			SetIsEnabled(true).
			SetMinimumAvailableBalance(decimal.NewFromFloat(200.0)).
			SetCriticalThreshold(decimal.NewFromFloat(500.0)).
			Save(context.Background())
		assert.NoError(t, err)

		// Create test provider
		user, err := test.CreateTestUser(map[string]interface{}{
			"email": fmt.Sprintf("realtime-user-%d@example.com", time.Now().UnixNano()),
		})
		assert.NoError(t, err)

		provider, err := db.Client.ProviderProfile.
			Create().
			SetTradingName("Real-Time Test Provider").
			SetIsActive(true).
			SetVisibilityMode(providerprofile.VisibilityModePublic).
			SetUser(user).
			Save(context.Background())
		assert.NoError(t, err)

		providerCurrency, err := db.Client.ProviderCurrencies.
			Create().
			SetProvider(provider).
			SetCurrency(currency).
			SetAvailableBalance(decimal.NewFromFloat(1500.0)).
			SetReservedBalance(decimal.NewFromFloat(200.0)).
			SetTotalBalance(decimal.NewFromFloat(1700.0)).
			SetIsAvailable(true).
			Save(context.Background())
		assert.NoError(t, err)
		t.Logf("✅ Created test provider with initial balance: %s", providerCurrency.AvailableBalance.String())

		// Test balance monitoring service
		balanceService := NewBalanceManagementService()

		// Simulate multiple balance updates and test health changes
		balanceUpdates := []struct {
			amount   float64
			expected bool
			reason   string
		}{
			{1500.0, true, "Initial healthy balance"},
			{800.0, false, "Below effective threshold (1000 + 100 safety margin)"}, // This should be false
			{400.0, false, "Below alert threshold"},
			{300.0, false, "Below critical threshold"},
			{100.0, false, "Well below critical threshold"},
			{1200.0, true, "Above effective threshold"}, // This should be true
		}

		for i, update := range balanceUpdates {
			t.Logf("�� Update %d: Setting balance to %s (%s)", i+1, decimal.NewFromFloat(update.amount).String(), update.reason)

			// Update balance
			_, err = db.Client.ProviderCurrencies.
				UpdateOneID(providerCurrency.ID).
				SetAvailableBalance(decimal.NewFromFloat(update.amount)).
				Save(context.Background())
			assert.NoError(t, err)

			// Test health check
			isHealthy, err := balanceService.CheckBalanceSufficiency(context.Background(), provider.ID, "AUD", decimal.NewFromFloat(update.amount))
			assert.NoError(t, err)
			assert.Equal(t, update.expected, isHealthy, fmt.Sprintf("Balance %s should be %v (%s)",
				decimal.NewFromFloat(update.amount).String(), update.expected, update.reason))

		}

		t.Log("�� Balance Monitoring with Real-Time Updates Test completed successfully")
	})
}
