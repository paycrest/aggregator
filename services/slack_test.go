package services

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jarcoal/httpmock"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/utils"
	"github.com/stretchr/testify/assert"
)

var (
	testUserID       = uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	SlackEmail       = "user@example.com"
	FirstName        = "John"
	LastName         = "Doe"
	ProviderCurrency = "USD"
	conf             *config.ServerConfiguration

	// Declare mockUser globally
	mockUser = &ent.User{
		ID:        testUserID,
		Email:     SlackEmail,
		FirstName: FirstName,
		LastName:  LastName,
		CreatedAt: time.Now(),
	}
)

func init() {
	// Load server configuration
	conf = config.ServerConfig()
}

func TestSlackService(t *testing.T) {
	// Activate httpmock
	httpmock.Activate()
	defer httpmock.Deactivate()

	webhookURL := conf.SlackWebhookURL
	if webhookURL == "" {
		t.Fatal("SLACK_WEBHOOK_URL is not configured in serverConfig")
	}

	// Register mock response using the actual serverConfig URL
	httpmock.RegisterResponder("POST", webhookURL,
		func(r *http.Request) (*http.Response, error) {
			return httpmock.NewBytesResponse(200, []byte(`{"ok": true}`)), nil
		},
	)

	t.Run("Slack", func(t *testing.T) {

		t.Run("SendUserSignupNotification should work properly and return no error when user is a provider", func(t *testing.T) {
			// Test with provider role and currency
			slackService := NewSlackService(webhookURL)
			providerCurrencies := []string{"GHS", "KES"}
			err := slackService.SendUserSignupNotification(mockUser, []string{"provider"}, providerCurrencies)
			assert.NoError(t, err, "unexpected error")
		})

		t.Run("SendUserSignupNotification should work properly and return no error when user is a sender", func(t *testing.T) {
			// Test with sender role (no currency)
			slackService := NewSlackService(webhookURL)
			providerCurrencies := []string{}
			err := slackService.SendUserSignupNotification(mockUser, []string{"sender"}, providerCurrencies)
			assert.NoError(t, err, "unexpected error")
		})

		t.Run("SendUserSignupNotification should fail silently if webhook URL is not configured", func(t *testing.T) {
			// Remove the SlackWebhookURL from serverConfig for this test
			originalWebhookURL := conf.SlackWebhookURL
			conf.SlackWebhookURL = "" // Clear for this test

			slackService := NewSlackService("")
			providerCurrencies := []string{"GHS", "KES"}
			err := slackService.SendUserSignupNotification(mockUser, []string{"provider"}, providerCurrencies)

			assert.NoError(t, err, "expected no error")

			// Restore the SlackWebhookURL for subsequent tests
			conf.SlackWebhookURL = originalWebhookURL
		})

		t.Run("SendUserSignupNotification should not send notification in non-production environment", func(t *testing.T) {
			// Set environment variable to non-production (development) for this test
			originalEnv := os.Getenv("ENVIRONMENT")
			os.Setenv("ENVIRONMENT", "development")
			defer os.Setenv("ENVIRONMENT", originalEnv) // Restore original environment variable

			slackService := NewSlackService(webhookURL)
			providerCurrencies := []string{"GHS", "KES"}
			err := slackService.SendUserSignupNotification(mockUser, []string{"provider"}, providerCurrencies)

			assert.NoError(t, err, "unexpected error")
		})

		t.Run("FormatTimestampToGMT1 should work with any timezone configuration", func(t *testing.T) {
			testTime := time.Date(2023, 5, 15, 14, 30, 0, 0, time.UTC)

			formattedTime, err := utils.FormatTimestampToGMT1(testTime)

			assert.NoError(t, err, "formatting timestamp should not produce an error")
			assert.NotEmpty(t, formattedTime, "formatted time should not be empty")
			assert.Contains(t, formattedTime, "May 15, 2023")
			assert.Contains(t, formattedTime, "3:30 PM")
		})

		t.Run("FormatTimestampToGMT1 should work with current time", func(t *testing.T) {
			// Get current time
			now := time.Now().UTC()

			formattedTime, err := utils.FormatTimestampToGMT1(now)

			assert.NoError(t, err, "formatting current timestamp should not produce an error")
			assert.NotEmpty(t, formattedTime, "formatted time should not be empty")
			assert.Contains(t, formattedTime, now.In(time.FixedZone("GMT+1", 3600)).Format("2006"))
		})

		t.Run("SendStuckOrderNotification should skip initial notifications", func(t *testing.T) {
			// Create Slack service
			slackService := NewSlackService(webhookURL)

			// Test data
			providerName := "Test Provider"
			providerEmail := "provider@example.com"
			orders := []map[string]interface{}{
				{
					"order_id":      "123e4567-e89b-12d3-a456-426614174000",
					"tx_id":         "0x1234567890abcdef",
					"amount":        "100.50",
					"currency":      "USD",
					"time_stuck":    "5 minutes",
					"institution":   "Test Bank",
					"account_name":  "Test Account",
					"dashboard_url": "https://example.com/dashboard/orders/123e4567-e89b-12d3-a456-426614174000",
				},
			}

			// Test initial notification - should be skipped
			templateType := "initial"
			err := slackService.SendStuckOrderNotification(providerName, providerEmail, orders, templateType)
			assert.NoError(t, err, "unexpected error")

			// Verify NO request was made (initial notifications are skipped)
			info := httpmock.GetCallCountInfo()
			assert.Equal(t, 3, info["POST "+webhookURL])
		})

		t.Run("SendStuckOrderNotification should work properly for follow-up notification", func(t *testing.T) {
			// Create Slack service
			slackService := NewSlackService(webhookURL)

			// Test data
			providerName := "Test Provider"
			providerEmail := "provider@example.com"
			orders := []map[string]interface{}{
				{
					"order_id":      "123e4567-e89b-12d3-a456-426614174000",
					"tx_id":         "0x1234567890abcdef",
					"amount":        "100.50",
					"currency":      "USD",
					"time_stuck":    "10 minutes",
					"institution":   "Test Bank",
					"account_name":  "Test Account",
					"dashboard_url": "https://example.com/dashboard/orders/123e4567-e89b-12d3-a456-426614174000",
				},
			}

			// Test follow-up notification (should trigger HIGH priority)
			templateType := "follow_up"
			err := slackService.SendStuckOrderNotification(providerName, providerEmail, orders, templateType)
			assert.NoError(t, err, "unexpected error")

			// Verify the request was made
			info := httpmock.GetCallCountInfo()
			assert.Equal(t, 4, info["POST "+webhookURL])
		})

		t.Run("SendStuckOrderNotification should work properly for escalation notification", func(t *testing.T) {
			// Create Slack service
			slackService := NewSlackService(webhookURL)

			// Test data
			providerName := "Test Provider"
			providerEmail := "provider@example.com"
			orders := []map[string]interface{}{
				{
					"order_id":      "123e4567-e89b-12d3-a456-426614174000",
					"tx_id":         "0x1234567890abcdef",
					"amount":        "100.50",
					"currency":      "USD",
					"time_stuck":    "30 minutes",
					"institution":   "Test Bank",
					"account_name":  "Test Account",
					"dashboard_url": "https://example.com/dashboard/orders/123e4567-e89b-12d3-a456-426614174000",
				},
			}

			// Test escalation notification (should trigger CRITICAL priority)
			templateType := "escalation"
			err := slackService.SendStuckOrderNotification(providerName, providerEmail, orders, templateType)
			assert.NoError(t, err, "unexpected error")

			// Verify the request was made
			info := httpmock.GetCallCountInfo()
			assert.Equal(t, 5, info["POST "+webhookURL])
		})
		t.Run("SendStuckOrderNotification should return error when HTTP request fails", func(t *testing.T) {
			// Create Slack service
			slackService := NewSlackService(webhookURL)

			// Register mock response with error status
			httpmock.RegisterResponder("POST", webhookURL,
				httpmock.NewStringResponder(500, `{"error": "Internal Server Error"}`))

			// Test data
			providerName := "Test Provider"
			providerEmail := "provider@example.com"
			orders := []map[string]interface{}{
				{
					"order_id":      "123e4567-e89b-12d3-a456-426614174000",
					"tx_id":         "0x1234567890abcdef",
					"amount":        "100.50",
					"currency":      "USD",
					"time_stuck":    "5 minutes",
					"institution":   "Test Bank",
					"account_name":  "Test Account",
					"dashboard_url": "https://example.com/dashboard/orders/123e4567-e89b-12d3-a456-426614174000",
				},
			}

			// Test that error is returned when HTTP request fails
			templateType := "initial"
			err := slackService.SendStuckOrderNotification(providerName, providerEmail, orders, templateType)
			assert.Error(t, err, "expected error")
			assert.Contains(t, err.Error(), "notification failed with status: 500")
		})
	})
}
