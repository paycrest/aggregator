package email

import (
	"context"
	"fmt"

	mailgunv3 "github.com/mailgun/mailgun-go/v3"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils/logger"
)

// MailgunProvider implements EmailProvider for Mailgun
type MailgunProvider struct {
	config *config.NotificationConfiguration
	client mailgunv3.Mailgun
}

// NewMailgunProvider creates a new Mailgun provider
func NewMailgunProvider(config *config.NotificationConfiguration) *MailgunProvider {
	if config == nil {
		logger.Errorf("Mailgun provider configuration is nil")
		return nil
	}
	if config.EmailDomain == "" || config.EmailAPIKey == "" {
		logger.Errorf("Mailgun provider requires EmailDomain and EmailAPIKey")
		return nil
	}
	client := mailgunv3.NewMailgun(config.EmailDomain, config.EmailAPIKey)
	return &MailgunProvider{
		config: config,
		client: client,
	}
}

// SendEmail sends an email via Mailgun
func (m *MailgunProvider) SendEmail(ctx context.Context, payload types.SendEmailPayload) (types.SendEmailResponse, error) {
	message := m.client.NewMessage(
		payload.FromAddress,
		payload.Subject,
		payload.Body,
		payload.ToAddress,
	)

	response, id, err := m.client.Send(ctx, message)
	if err != nil {
		logger.Errorf("Failed to send email via Mailgun: %v", err)
		return types.SendEmailResponse{}, fmt.Errorf("mailgun send error: %w", err)
	}

	return types.SendEmailResponse{
		Id:       id,
		Response: response,
	}, nil
}

// SendTemplateEmail sends a template email via Mailgun
func (m *MailgunProvider) SendTemplateEmail(ctx context.Context, payload types.SendEmailPayload, templateID string) (types.SendEmailResponse, error) {
	// Mailgun doesn't have built-in template support like SendGrid
	// We'll implement a simple template rendering here
	// For now, we'll use the regular SendEmail method
	return m.SendEmail(ctx, payload)
}

// GetName returns the provider name
func (m *MailgunProvider) GetName() string {
	return "mailgun"
}
