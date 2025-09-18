package services

import (
	"bytes"
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

	resp, err := http.Post(s.SlackWebhookURL, "application/json", bytes.NewBuffer(jsonPayload))
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
							"text": "Approve",
						},
						"action_id": "approve_" + submissionID,
						"style":     "primary",
						"value":     fmt.Sprintf(`{"submission_id":"%s","email":"%s","action":"approve"}`, submissionID, email),
					},
					{
						"type": "button",
						"text": map[string]interface{}{
							"type": "plain_text",
							"text": "Reject",
						},
						"action_id": "reject_" + submissionID,
						"style":     "danger",
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

	resp, err := http.Post(s.SlackWebhookURL, "application/json", bytes.NewBuffer(jsonPayload))
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

// SendStuckOrderNotification sends a Slack notification for stuck lock orders
func (s *SlackService) SendStuckOrderNotification(providerName, providerEmail string, orders []map[string]interface{}, templateType string) error {
	if s.SlackWebhookURL == "" {
		logger.Warnf("Slack webhook URL not set, skipping stuck order notification")
		return nil
	}

	// Skip initial notifications - only send follow_up and escalation to Slack
	if templateType == "initial" {
		logger.Infof("Skipping initial notification for Slack - only sending follow_up and escalation")
		return nil
	}

	// Determine urgency based on template type
	var urgencyEmoji, urgencyText string
	switch templateType {
	case "escalation":
		urgencyEmoji = "🚨"
		urgencyText = "CRITICAL"
	case "follow_up":
		urgencyEmoji = "⚠️"
		urgencyText = "HIGH"
	default:
		urgencyEmoji = "📧"
		urgencyText = "MEDIUM"
	}

	// Build order details text
	var orderDetails strings.Builder
	for i, order := range orders {
		if i > 0 {
			orderDetails.WriteString("\n\n")
		}
		orderDetails.WriteString(fmt.Sprintf("OrderID: %s\nAmount: %s %s\nStuck: %s",
			order["order_id"], order["amount"], order["currency"], order["time_stuck"]))
	}

	formattedTime, err := utils.FormatTimestampToGMT1(time.Now())
	if err != nil {
		logger.Errorf("Failed to format timestamp: %v", err)
		return fmt.Errorf("failed to format timestamp: %v", err)
	}

	message := map[string]interface{}{
		"blocks": []map[string]interface{}{
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("%s *Stuck Lock Order Alert* - %s Priority", urgencyEmoji, urgencyText),
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Provider:* %s\n*Email:* %s\n*Orders Count:* %d",
						providerName, providerEmail, len(orders)),
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Order Details:*\n%s", orderDetails.String()),
				},
			},
			{
				"type": "context",
				"elements": []map[string]interface{}{
					{
						"type": "mrkdwn",
						"text": fmt.Sprintf("Template Type: %s\nTimestamp: %s", templateType, formattedTime),
					},
				},
			},
		},
	}

	jsonPayload, err := json.Marshal(message)
	if err != nil {
		logger.Errorf("Failed to marshal Slack stuck order notification: %v", err)
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	resp, err := http.Post(s.SlackWebhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		logger.Errorf("Failed to send Slack stuck order notification: %v", err)
		return fmt.Errorf("failed to send notification: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Errorf("Slack stuck order notification failed with status: %d", resp.StatusCode)
		return fmt.Errorf("notification failed with status: %d", resp.StatusCode)
	}
	return nil
}
