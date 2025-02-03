package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/utils/logger"
)

type SlackService struct{}

func NewSlackService() *SlackService {
	return &SlackService{}
}

func (s *SlackService) SendUserSignupNotification(user *ent.User, scopes []string, providerCurrency string) error {
	// Only send in production

	conf := config.ServerConfig()
	if conf.Environment != "production" {
		return nil
	}
	webhookURL := conf.SlackWebhookURL
	if webhookURL == "" {
		return fmt.Errorf("slack webhook URL not configured")
	}

	// Prepare Slack message
	message := map[string]interface{}{
		"blocks": []map[string]interface{}{
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": "*New User Signup*",
				},
			},
			{
				"type": "section",
				"fields": []map[string]interface{}{
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*User ID:* %s", user.ID),
					},
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Email:* %s", user.Email),
					},
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Name:* %s %s", user.FirstName, user.LastName),
					},
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Scopes:* %v", scopes),
					},
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Timestamp:* %s", user.CreatedAt.Format(time.RFC3339)),
					},
				},
			},
		},
	}

	// Add provider details if applicable
	if providerCurrency != "" {
		message["blocks"] = append(message["blocks"].([]map[string]interface{}),
			map[string]interface{}{
				"type": "section",
				"fields": []map[string]interface{}{
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("*Provider Currency:* %s", providerCurrency),
					},
				},
			},
		)
	}

	// Send notification
	jsonPayload, err := json.Marshal(message)
	if err != nil {
		return err
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		logger.Errorf("Failed to send Slack notification: %v", err)
		return err
	}
	defer resp.Body.Close()

	// Log error if notification failed, but don't interrupt registration
	if resp.StatusCode != http.StatusOK {
		logger.Errorf("Slack notification failed with status: %d", resp.StatusCode)
	}

	return nil
}
