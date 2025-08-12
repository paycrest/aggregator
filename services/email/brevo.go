package email

import (
	"context"
	"fmt"
	"strconv"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

// BrevoProvider implements EmailProvider for Brevo
type BrevoProvider struct {
	config *config.NotificationConfiguration
}

// NewBrevoProvider creates a new Brevo provider
func NewBrevoProvider(config *config.NotificationConfiguration) *BrevoProvider {
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
	reqBody := map[string]interface{}{
		"templateId": func() int { id, _ := strconv.Atoi(templateID); return id }(),
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
	res, err := fastshot.NewClient("https://api.brevo.com").
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

	if res.RawResponse.StatusCode >= 400 {
		logger.Errorf("Brevo API error: %d", res.RawResponse.StatusCode)
		return types.SendEmailResponse{}, fmt.Errorf("brevo API error: %d", res.RawResponse.StatusCode)
	}

	_, err = utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		logger.Errorf("Failed to decode Brevo response: %v", err)
		return types.SendEmailResponse{}, fmt.Errorf("brevo response parse error: %w", err)
	}

	// Extract message ID from response headers
	messageID := res.RawResponse.Header.Get("X-Message-Id")
	if messageID == "" {
		messageID = "brevo-message-id" // Fallback
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
