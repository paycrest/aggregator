package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

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

// SendUserSignupNotification sends a Slack notification when a new user signs up
func (s *SlackService) SendUserSignupNotification(user *ent.User, scopes []string, providerCurrencies []string) error {
	if s.SlackWebhookURL == "" {
		return nil
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

	// Send notification with timeout to prevent hanging on stalled Slack endpoint
	jsonPayload, err := json.Marshal(message)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.SlackWebhookURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := utils.GetHTTPClient().Do(req)
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

// SendActionFeedbackNotification sends a Slack notification for an action taken on a KYB submission
func (s *SlackService) SendActionFeedbackNotification(firstName, email, submissionID, actionType, reasonForDecline string) error {
	if s.SlackWebhookURL == "" {
		logger.Warnf("Slack webhook URL not set, skipping feedback notification")
		return nil
	}

	var actionText string
	switch actionType {
	case "approve":
		actionText = "Approved"
	case "reject":
		actionText = "Declined"
	default:
		return fmt.Errorf("invalid action type: %s", actionType)
	}

	var reasonText string
	if reasonForDecline != "" {
		reasonText = fmt.Sprintf("\nReason: %s", reasonForDecline)
	}

	message := map[string]interface{}{
		"blocks": []map[string]interface{}{
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*KYB Action Taken*\nUser: %s\nEmail: %s\nSubmission ID: %s\nAction: %s%s", firstName, email, submissionID, actionText, reasonText),
				},
			},
		},
	}

	jsonPayload, err := json.Marshal(message)
	if err != nil {
		logger.Errorf("Failed to marshal Slack feedback notification: %v", err)
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Send notification with timeout to prevent hanging on stalled Slack endpoint
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.SlackWebhookURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		logger.Errorf("Failed to create Slack request: %v", err)
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := utils.GetHTTPClient().Do(req)
	if err != nil {
		logger.Errorf("Failed to send Slack feedback notification: %v", err)
		return fmt.Errorf("failed to send notification: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Errorf("Slack feedback notification failed with status: %d", resp.StatusCode)
		return fmt.Errorf("notification failed with status: %d", resp.StatusCode)
	}
	return nil
}

// SendSubmissionNotification sends a Slack notification for a new KYB submission
func (s *SlackService) SendSubmissionNotification(firstName, email, submissionID string) error {
	if s.SlackWebhookURL == "" {
		logger.Warnf("Slack webhook URL not set, skipping notification")
		return nil
	}

	message := map[string]interface{}{
		"blocks": []map[string]interface{}{
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": "*New KYB Submission*",
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("First Name: %s", firstName),
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("Email: %s", email),
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("Submission ID: %s", submissionID),
				},
			},
			{
				"type": "actions",
				"elements": []map[string]interface{}{
					{
						"type": "button",
						"text": map[string]interface{}{
							"type": "plain_text",
							"text": "Review",
						},
						"action_id": "review_kyb",
						"style":     "primary",
						"value":     submissionID,
					},
					{
						"type": "button",
						"text": map[string]interface{}{
							"type": "plain_text",
							"text": "Reject",
						},
						"action_id": "reject_kyb_" + submissionID,
						"style":     "danger",
						"value":     submissionID,
					},
				},
			},
		},
	}

	jsonPayload, err := json.Marshal(message)
	if err != nil {
		logger.Errorf("Failed to marshal Slack notification: %v", err)
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Send notification with timeout to prevent hanging on stalled Slack endpoint
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.SlackWebhookURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		logger.Errorf("Failed to create Slack request: %v", err)
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := utils.GetHTTPClient().Do(req)
	if err != nil {
		logger.Errorf("Failed to send Slack notification: %v", err)
		return fmt.Errorf("failed to send Slack notification: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Errorf("Slack notification failed with status: %d", resp.StatusCode)
		return fmt.Errorf("slack notification failed with status: %d", resp.StatusCode)
	}
	return nil
}
