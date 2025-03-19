package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

type SlackService struct {
	SlackWebhookURL string
}

func NewSlackService(webhookURL string) *SlackService {
	return &SlackService{
		SlackWebhookURL: webhookURL,
	}
}

func (s *SlackService) SendUserSignupNotification(user *ent.User, scopes []string, providerCurrencies []string) error {
	if s.SlackWebhookURL == "" {
		return fmt.Errorf("slack webhook URL not configured")
	}

	// Format the timestamp using the utility function
	formattedTime, err := utils.FormatTimestampToGMT1(user.CreatedAt)
	if err != nil {
		return fmt.Errorf("error formatting timestamp: %v", err)
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
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*User ID:* %s", user.ID),
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Email:* %s", user.Email),
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Name:* %s %s", user.FirstName, user.LastName),
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Scopes:* %v", scopes),
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Timestamp:* %s", formattedTime),
				},
			},
		},
	}

	// Add provider details if applicable
	if utils.ContainsString(scopes, "provider") && len(providerCurrencies) > 0 {
		// Join the currencies with comma for display
		currenciesString := strings.Join(providerCurrencies, ", ")
		message["blocks"] = append(message["blocks"].([]map[string]interface{}),
			map[string]interface{}{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Provider Currencies:* %s", currenciesString)},
			},
		)
	}

	// Send notification
	jsonPayload, err := json.Marshal(message)
	if err != nil {
		return err
	}

	resp, err := http.Post(s.SlackWebhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		logger.Errorf("Failed to send Slack notification: %v", err)
		return err
	}
	defer resp.Body.Close()

	// Return error if notification fails, allowing caller to handle it
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack notification failed with status: %d", resp.StatusCode)
	}

	return nil
}
