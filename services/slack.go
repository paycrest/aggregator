package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// postSlackJSON sends a POST request to the exact Slack webhook URL using the shared HTTP client.
// Uses net/http directly so the full URL (including path) is used; some client libs strip the path when given as base URL.
// Uses a 10s per-request timeout to prevent indefinite hangs.
// Drains and closes the response body before returning so the request context can be cancelled without
// forcing the underlying connection to be discarded; the connection is returned to the shared pool.
func (s *SlackService) postSlackJSON(payload []byte) (statusCode int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.SlackWebhookURL, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := utils.GetHTTPClient().Do(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	return resp.StatusCode, nil
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

	statusCode, err := s.postSlackJSON(jsonPayload)
	if err != nil {
		logger.Errorf("Failed to send Slack notification: %v", err)
		return err
	}
	if statusCode != http.StatusOK {
		return fmt.Errorf("slack notification failed with status: %d", statusCode)
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

	statusCode, err := s.postSlackJSON(jsonPayload)
	if err != nil {
		logger.Errorf("Failed to send Slack feedback notification: %v", err)
		return fmt.Errorf("failed to send notification: %v", err)
	}
	if statusCode != http.StatusOK {
		logger.Errorf("Slack feedback notification failed with status: %d", statusCode)
		return fmt.Errorf("notification failed with status: %d", statusCode)
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

	statusCode, err := s.postSlackJSON(jsonPayload)
	if err != nil {
		logger.Errorf("Failed to send Slack notification: %v", err)
		return fmt.Errorf("failed to send Slack notification: %v", err)
	}
	if statusCode != http.StatusOK {
		logger.Errorf("Slack notification failed with status: %d", statusCode)
		return fmt.Errorf("slack notification failed with status: %d", statusCode)
	}
	return nil
}

// PostKYBSubmissionMessage sends a KYB submission notification via chat.postMessage (Bot Token)
// and returns the message ts so the message can be updated later after approve/reject.
func (s *SlackService) PostKYBSubmissionMessage(botToken, channelID, firstName, email, submissionID string) (msgTs string, err error) {
	if botToken == "" || channelID == "" {
		return "", fmt.Errorf("bot token and channel ID are required")
	}

	blocks := []map[string]interface{}{
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
	}

	payload := map[string]interface{}{
		"channel": channelID,
		"blocks":  blocks,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://slack.com/api/chat.postMessage", bytes.NewReader(jsonPayload))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+botToken)

	resp, err := utils.GetHTTPClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to post message: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		TS    string `json:"ts"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}
	if !result.OK {
		return "", fmt.Errorf("chat.postMessage failed: %s", result.Error)
	}
	return result.TS, nil
}

// UpdateKYBSubmissionMessage updates the original KYB submission message in Slack to remove
// Review/Reject buttons and show the decision status. Requires Slack Bot Token (chat:write).
func (s *SlackService) UpdateKYBSubmissionMessage(botToken, channelID, messageTs, firstName, email, submissionID, statusLabel string) error {
	if botToken == "" || channelID == "" || messageTs == "" {
		return fmt.Errorf("bot token, channel ID and message ts are required to update KYB message")
	}

	blocks := []map[string]interface{}{
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
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Status:* %s", statusLabel),
			},
		},
	}

	payload := map[string]interface{}{
		"channel": channelID,
		"ts":      messageTs,
		"blocks":  blocks,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal chat.update payload: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://slack.com/api/chat.update", bytes.NewReader(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create chat.update request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+botToken)
	resp, err := utils.GetHTTPClient().Do(req)
	if err != nil {
		logger.Errorf("Failed to call Slack chat.update: %v", err)
		return fmt.Errorf("failed to call Slack chat.update: %w", err)
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &result)
	if !result.OK {
		logger.Errorf("Slack chat.update failed: %s", result.Error)
		return fmt.Errorf("slack chat.update failed: %s", result.Error)
	}
	return nil
}
