package email

import (
	"context"
	"fmt"
	"strconv"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils/logger"
)

// BrevoProvider implements EmailProvider for Brevo
type BrevoProvider struct {
	config *config.NotificationConfiguration
}

// NewBrevoProvider creates a new Brevo provider
func NewBrevoProvider(config *config.NotificationConfiguration) *BrevoProvider {
	if config == nil || config.EmailAPIKey == "" {
		logger.Errorf("Brevo provider requires EmailAPIKey")
		return nil
	}
	return &BrevoProvider{
		config: config,
	}
}

// SendEmail sends an email via Brevo
func (b *BrevoProvider) SendEmail(ctx context.Context, payload types.SendEmailPayload) (types.SendEmailResponse, error) {
	reqBody := map[string]interface{}{
		"sender": map[string]string{
			"email": payload.FromAddress,
			"name":  "Paycrest",
		},
		"to": []map[string]string{
			{
				"email": payload.ToAddress,
			},
		},
		"subject":     payload.Subject,
		"htmlContent": payload.HTMLBody,
		"textContent": payload.Body,
	}

	return b.sendBrevoRequest(ctx, reqBody)
}

// SendTemplateEmail sends a template email via Brevo
func (b *BrevoProvider) SendTemplateEmail(ctx context.Context, payload types.SendEmailPayload, templateID string) (types.SendEmailResponse, error) {
	// Parse and validate template ID before building request
	templateIDInt, err := strconv.Atoi(templateID)
	if err != nil {
		logger.Errorf("Invalid template ID '%s' for Brevo: %v", templateID, err)
		return types.SendEmailResponse{}, fmt.Errorf("invalid template ID '%s': %w", templateID, err)
	}

	reqBody := map[string]interface{}{
		"templateId": templateIDInt,
		"sender": map[string]string{
			"email": payload.FromAddress,
			"name":  "Paycrest",
		},
		"to": []map[string]string{
			{
				"email": payload.ToAddress,
			},
		},
		"params": payload.DynamicData,
	}

	return b.sendBrevoRequest(ctx, reqBody)
}

// sendBrevoRequest sends a request to Brevo API
func (b *BrevoProvider) sendBrevoRequest(ctx context.Context, reqBody map[string]interface{}) (types.SendEmailResponse, error) {
	res, err := fastshot.NewClient(fmt.Sprintf("https://%s", b.config.EmailDomain)).
		Config().SetTimeout(30*time.Second).
		Header().Add("Content-Type", "application/json").
		Header().Add("api-key", b.config.EmailAPIKey).
		Build().POST("/v3/smtp/email").
		Body().AsJSON(reqBody).
		Send()
	if err != nil {
		logger.Errorf("Failed to send Brevo request: %v", err)
		return types.SendEmailResponse{}, fmt.Errorf("brevo request error: %w", err)
	}

	// Check for HTTP errors
	if res.Status().IsError() {
		body, _ := res.Body().AsString()
		logger.Errorf("Brevo API error: %d - %s", res.Status().Code(), body)
		return types.SendEmailResponse{}, fmt.Errorf("brevo API error: %d", res.Status().Code(), body)
	}

	// Parse response body to extract message ID
	var responseBody map[string]interface{}
	err = res.Body().AsJSON(&responseBody)
	if err != nil {
		logger.Errorf("Failed to decode Brevo response: %v", err)
		return types.SendEmailResponse{}, fmt.Errorf("brevo response parse error: %w", err)
	}

	// Extract message ID from response body
	var messageID string
	if id, exists := responseBody["messageId"]; exists {
		if idStr, ok := id.(string); ok {
			messageID = idStr
		}
	}

	// Fallback if message ID not found in response body
	if messageID == "" {
		logger.Warnf("Message ID not found in Brevo response, using fallback")
		messageID = fmt.Sprintf("brevo-%d", time.Now().UnixNano())
	}

	return types.SendEmailResponse{
		Id:       messageID,
		Response: messageID,
	}, nil
}

// GetName returns the provider name
func (b *BrevoProvider) GetName() string {
	return "brevo"
}
