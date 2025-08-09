package email

import (
	"context"
	"fmt"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/types"
)

// EmailProvider defines the interface for email providers
type EmailProvider interface {
	SendEmail(ctx context.Context, payload types.SendEmailPayload) (types.SendEmailResponse, error)
	SendTemplateEmail(ctx context.Context, payload types.SendEmailPayload, templateID string) (types.SendEmailResponse, error)
	GetName() string
}

// ProviderFactory creates email providers based on configuration
type ProviderFactory struct {
	config *config.NotificationConfiguration
}

// NewProviderFactory creates a new provider factory
func NewProviderFactory(config *config.NotificationConfiguration) *ProviderFactory {
	return &ProviderFactory{config: config}
}

// CreateProvider creates an email provider based on the provider name
func (pf *ProviderFactory) CreateProvider(providerName string) (EmailProvider, error) {
	switch providerName {
	case "mailgun":
		return NewMailgunProvider(pf.config), nil
	case "sendgrid":
		return NewSendGridProvider(pf.config), nil
	case "brevo":
		return NewBrevoProvider(pf.config), nil
	default:
		return nil, fmt.Errorf("unsupported email provider: %s", providerName)
	}
}

// GetDefaultProvider returns the default provider based on configuration
func (pf *ProviderFactory) GetDefaultProvider() (EmailProvider, error) {
	providerName := pf.config.EmailProvider
	if providerName == "" {
		providerName = "sendgrid" // Default fallback
	}
	return pf.CreateProvider(providerName)
}
