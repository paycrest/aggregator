package email

import (
	"context"

	"github.com/paycrest/aggregator/types"
)

// EmailServiceInterface provides the interface for the email service
type EmailServiceInterface interface {
	SendEmail(ctx context.Context, payload types.SendEmailPayload) (types.SendEmailResponse, error)
	SendTemplateEmail(ctx context.Context, payload types.SendEmailPayload, templateID string) (types.SendEmailResponse, error)
	SendVerificationEmail(ctx context.Context, token, email, firstName string) (types.SendEmailResponse, error)
	SendPasswordResetEmail(ctx context.Context, token, email, firstName string) (types.SendEmailResponse, error)
	SendWelcomeEmail(ctx context.Context, email, firstName string, scopes []string) (types.SendEmailResponse, error)
	SendKYBApprovalEmail(ctx context.Context, email, firstName string) (types.SendEmailResponse, error)
	SendKYBRejectionEmail(ctx context.Context, email, firstName, reasonForDecline string) (types.SendEmailResponse, error)
	SendWebhookFailureEmail(ctx context.Context, email, firstName string) (types.SendEmailResponse, error)
}

// NewEmailServiceWithProviders creates a new email service with dynamic provider selection
func NewEmailServiceWithProviders() EmailServiceInterface {
	return NewEmailService()
}
