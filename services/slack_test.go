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

		t.Run("SendUserSignupNotification should return error if webhook URL is not configured", func(t *testing.T) {
			// Remove the SlackWebhookURL from serverConfig for this test
			originalWebhookURL := conf.SlackWebhookURL
			conf.SlackWebhookURL = "" // Clear for this test

			slackService := NewSlackService("")
			providerCurrencies := []string{"GHS", "KES"}
			err := slackService.SendUserSignupNotification(mockUser, []string{"provider"}, providerCurrencies)

			assert.Error(t, err, "expected error")

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
	})
}
