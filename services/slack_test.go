package services

import (
	"encoding/json"
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

	// Use a test webhook URL for unit testing (self-contained, doesn't require external config)
	testWebhookURL := "https://hooks.slack.com/services/test/webhook/url"

	// If config has a webhook URL, use it; otherwise use the test URL
	webhookURL := conf.SlackWebhookURL
	if webhookURL == "" {
		webhookURL = testWebhookURL
	}

	// Register mock response using the webhook URL
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

		t.Run("PostKYBSubmissionMessage", func(t *testing.T) {
			slackAPI := "https://slack.com/api/chat.postMessage"
			slackService := NewSlackService("")

			t.Run("returns ts on success", func(t *testing.T) {
				httpmock.RegisterResponder("POST", slackAPI,
					func(r *http.Request) (*http.Response, error) {
						var body map[string]interface{}
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							t.Fatalf("decode body: %v", err)
						}
						assert.Equal(t, "C01234", body["channel"], "channel must be set")
						blocks, ok := body["blocks"].([]interface{})
						assert.True(t, ok, "blocks must be present")
						var hasReviewButton bool
						for _, b := range blocks {
							blk, _ := b.(map[string]interface{})
							if blk["type"] == "actions" {
								elements, _ := blk["elements"].([]interface{})
								for _, e := range elements {
									el, _ := e.(map[string]interface{})
									if el["action_id"] == "review_kyb" && el["value"] == "sub-123" {
										hasReviewButton = true
										break
									}
								}
								break
							}
						}
						assert.True(t, hasReviewButton, "payload must include review_kyb button with value sub-123")
						return httpmock.NewBytesResponse(200, []byte(`{"ok": true, "ts": "1234567890.123456"}`)), nil
					},
				)
				ts, err := slackService.PostKYBSubmissionMessage("xoxb-token", "C01234", "Jane", "jane@example.com", "sub-123")
				assert.NoError(t, err)
				assert.Equal(t, "1234567890.123456", ts)
			})

			t.Run("returns error when bot token is empty", func(t *testing.T) {
				ts, err := slackService.PostKYBSubmissionMessage("", "C01234", "Jane", "jane@example.com", "sub-123")
				assert.Error(t, err)
				assert.Empty(t, ts)
				assert.Contains(t, err.Error(), "bot token and channel ID are required")
			})

			t.Run("returns error when channel ID is empty", func(t *testing.T) {
				ts, err := slackService.PostKYBSubmissionMessage("xoxb-token", "", "Jane", "jane@example.com", "sub-123")
				assert.Error(t, err)
				assert.Empty(t, ts)
			})

			t.Run("returns error when Slack API returns ok:false", func(t *testing.T) {
				httpmock.RegisterResponder("POST", slackAPI,
					httpmock.NewBytesResponder(200, []byte(`{"ok": false, "error": "channel_not_found"}`)),
				)
				ts, err := slackService.PostKYBSubmissionMessage("xoxb-token", "C01234", "Jane", "jane@example.com", "sub-123")
				assert.Error(t, err)
				assert.Empty(t, ts)
				assert.Contains(t, err.Error(), "channel_not_found")
			})
		})

		t.Run("UpdateKYBSubmissionMessage", func(t *testing.T) {
			slackAPI := "https://slack.com/api/chat.update"
			slackService := NewSlackService("")

			t.Run("returns nil on success", func(t *testing.T) {
				httpmock.RegisterResponder("POST", slackAPI,
					func(r *http.Request) (*http.Response, error) {
						var body map[string]interface{}
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							t.Fatalf("decode body: %v", err)
						}
						assert.Equal(t, "C01234", body["channel"], "channel must be set")
						assert.Equal(t, "1234567890.123456", body["ts"], "ts must be set")
						blocks, ok := body["blocks"].([]interface{})
						assert.True(t, ok, "blocks must be present")
						for _, b := range blocks {
							blk, _ := b.(map[string]interface{})
							assert.NotEqualf(t, "actions", blk["type"], "chat.update must not contain actions block (buttons removed)")
						}
						return httpmock.NewBytesResponse(200, []byte(`{"ok": true}`)), nil
					},
				)
				err := slackService.UpdateKYBSubmissionMessage("xoxb-token", "C01234", "1234567890.123456", "Acme Ltd", "Approved", "KYB submission approved successfully")
				assert.NoError(t, err)
			})

			t.Run("returns error when bot token is empty", func(t *testing.T) {
				err := slackService.UpdateKYBSubmissionMessage("", "C01234", "123.456", "Acme Ltd", "Rejected", "Incomplete documents")
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "bot token, channel ID and message ts are required")
			})

			t.Run("returns error when message ts is empty", func(t *testing.T) {
				err := slackService.UpdateKYBSubmissionMessage("xoxb-token", "C01234", "", "Acme Ltd", "Rejected", "Incomplete documents")
				assert.Error(t, err)
			})

			t.Run("returns error when Slack API returns ok:false", func(t *testing.T) {
				httpmock.RegisterResponder("POST", slackAPI,
					httpmock.NewBytesResponder(200, []byte(`{"ok": false, "error": "message_not_found"}`)),
				)
				err := slackService.UpdateKYBSubmissionMessage("xoxb-token", "C01234", "123.456", "Acme Ltd", "Rejected", "Incomplete documents")
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "message_not_found")
			})
		})
	})
}
