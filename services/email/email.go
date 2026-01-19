package email

import (
	"context"
	"fmt"
	"strings"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils/logger"
)

// EmailService provides functionality for sending emails with provider abstraction and fallback support
type EmailService struct {
	primaryProvider  EmailProvider
	fallbackProvider EmailProvider
	providerFactory  *ProviderFactory
	notificationConf *config.NotificationConfiguration
}

// NewEmailService creates a new EmailService with dynamic provider selection
func NewEmailService() *EmailService {
	notificationConf := config.NotificationConfig()
	factory := NewProviderFactory(notificationConf)

	// Get primary provider
	primaryProvider, err := factory.GetDefaultProvider()
	if err != nil {
		logger.Errorf("Failed to create primary email provider: %v", err)
		// Fallback to SendGrid if primary provider fails
		primaryProvider, _ = factory.CreateProvider("sendgrid")
	}

	// Get fallback provider (different from primary)
	var fallbackProvider EmailProvider
	if primaryProvider.GetName() == "sendgrid" {
		fallbackProvider, err = factory.CreateProvider("mailgun")
	} else {
		fallbackProvider, err = factory.CreateProvider("sendgrid")
	}
	if err != nil {
		logger.Errorf("Failed to create fallback email provider: %v", err)
		return nil
	}

	return &EmailService{
		primaryProvider:  primaryProvider,
		fallbackProvider: fallbackProvider,
		providerFactory:  factory,
		notificationConf: notificationConf,
	}
}

// SendEmail sends an email with fallback support
func (e *EmailService) SendEmail(ctx context.Context, payload types.SendEmailPayload) (types.SendEmailResponse, error) {
	// Try primary provider first
	response, err := e.primaryProvider.SendEmail(ctx, payload)
	if err != nil {
		logger.WithFields(logger.Fields{
			"primary_provider": e.primaryProvider.GetName(),
			"error":            err.Error(),
		}).Warnf("Primary email provider failed, trying fallback")

		// Try fallback provider
		if e.fallbackProvider == nil {
			return types.SendEmailResponse{}, fmt.Errorf("no fallback provider available: %w", err)
		}
		response, err = e.fallbackProvider.SendEmail(ctx, payload)
		if err != nil {
			logger.WithFields(logger.Fields{
				"fallback_provider": e.fallbackProvider.GetName(),
				"error":             err.Error(),
			}).Errorf("Fallback email provider also failed")
			return types.SendEmailResponse{}, fmt.Errorf("all email providers failed: %w", err)
		}

		logger.WithFields(logger.Fields{
			"fallback_provider": e.fallbackProvider.GetName(),
		}).Infof("Email sent successfully via fallback provider")
	}

	return response, nil
}

// SendTemplateEmail sends a template email with fallback support
func (e *EmailService) SendTemplateEmail(ctx context.Context, payload types.SendEmailPayload, templateID string) (types.SendEmailResponse, error) {
	// Try primary provider first
	response, err := e.primaryProvider.SendTemplateEmail(ctx, payload, templateID)
	if err != nil {
		logger.WithFields(logger.Fields{
			"primary_provider": e.primaryProvider.GetName(),
			"template_id":      templateID,
			"error":            err.Error(),
		}).Warnf("Primary email provider failed for template, trying fallback")

		// Check if fallback provider exists
		if e.fallbackProvider == nil {
			logger.WithFields(logger.Fields{
				"primary_provider": e.primaryProvider.GetName(),
				"template_id":      templateID,
			}).Errorf("No fallback provider available for template")
			return types.SendEmailResponse{}, fmt.Errorf("no fallback provider available for template: %w", err)
		}

		// Try fallback provider
		response, err = e.fallbackProvider.SendTemplateEmail(ctx, payload, templateID)
		if err != nil {
			logger.WithFields(logger.Fields{
				"fallback_provider": e.fallbackProvider.GetName(),
				"template_id":       templateID,
				"error":             err.Error(),
			}).Errorf("Fallback email provider also failed for template")
			return types.SendEmailResponse{}, fmt.Errorf("all email providers failed for template: %w", err)
		}

		logger.WithFields(logger.Fields{
			"fallback_provider": e.fallbackProvider.GetName(),
			"template_id":       templateID,
		}).Infof("Template email sent successfully via fallback provider")
	}

	return response, nil
}

// SendVerificationEmail sends a verification email
func (e *EmailService) SendVerificationEmail(ctx context.Context, token, email, firstName string) (types.SendEmailResponse, error) {
	payload := types.SendEmailPayload{
		FromAddress: e.notificationConf.EmailFromAddress,
		ToAddress:   email,
		DynamicData: map[string]interface{}{
			"first_name": firstName,
			"token":      token,
		},
	}

	templateID := getTemplateID("verification", e.primaryProvider.GetName())
	return e.SendTemplateEmail(ctx, payload, templateID)
}

// SendPasswordResetEmail sends a password reset email
func (e *EmailService) SendPasswordResetEmail(ctx context.Context, token, email, firstName string) (types.SendEmailResponse, error) {
	payload := types.SendEmailPayload{
		FromAddress: e.notificationConf.EmailFromAddress,
		ToAddress:   email,
		DynamicData: map[string]interface{}{
			"first_name": firstName,
			"token":      token,
		},
	}

	templateID := getTemplateID("password_reset", e.primaryProvider.GetName())
	return e.SendTemplateEmail(ctx, payload, templateID)
}

// SendWelcomeEmail sends a welcome email
func (e *EmailService) SendWelcomeEmail(ctx context.Context, email, firstName string, scopes []string) (types.SendEmailResponse, error) {
	payload := types.SendEmailPayload{
		FromAddress: e.notificationConf.EmailFromAddress,
		ToAddress:   email,
		DynamicData: map[string]interface{}{
			"first_name": firstName,
			"email":      email,
			"scopes":     strings.Join(scopes, ", "),
		},
	}

	templateID := getTemplateID("welcome", e.primaryProvider.GetName())
	return e.SendTemplateEmail(ctx, payload, templateID)
}

// SendKYBApprovalEmail sends a KYB approval email
func (e *EmailService) SendKYBApprovalEmail(ctx context.Context, email, firstName string) (types.SendEmailResponse, error) {
	payload := types.SendEmailPayload{
		FromAddress: e.notificationConf.EmailFromAddress,
		ToAddress:   email,
		DynamicData: map[string]interface{}{
			"first_name": firstName,
		},
	}

	templateID := getTemplateID("kyb_approval", e.primaryProvider.GetName())
	return e.SendTemplateEmail(ctx, payload, templateID)
}

// SendKYBRejectionEmail sends a KYB rejection email
func (e *EmailService) SendKYBRejectionEmail(ctx context.Context, email, firstName, reasonForDecline string, additionalData map[string]interface{}) (types.SendEmailResponse, error) {
	payload := types.SendEmailPayload{
		FromAddress: e.notificationConf.EmailFromAddress,
		ToAddress:   email,
		DynamicData: map[string]interface{}{
			"first_name":         firstName,
			"reason_for_decline": reasonForDecline,
		},
	}

	// Merge additional dynamic data if provided
	if additionalData != nil {
		for k, v := range additionalData {
			payload.DynamicData[k] = v
		}
	}

	templateID := getTemplateID("kyb_rejection", e.primaryProvider.GetName())
	return e.SendTemplateEmail(ctx, payload, templateID)
}

// SendWebhookFailureEmail sends a webhook failure notification email
func (e *EmailService) SendWebhookFailureEmail(ctx context.Context, email, firstName string) (types.SendEmailResponse, error) {
	payload := types.SendEmailPayload{
		FromAddress: e.notificationConf.EmailFromAddress,
		ToAddress:   email,
		DynamicData: map[string]interface{}{
			"first_name": firstName,
		},
	}

	templateID := getTemplateID("webhook_failure", e.primaryProvider.GetName())
	return e.SendTemplateEmail(ctx, payload, templateID)
}

// SendPartnerOnboardingSuccessEmail sends a partner onboarding success email.
func (e *EmailService) SendPartnerOnboardingSuccessEmail(ctx context.Context, email, firstName, apiKey string) (types.SendEmailResponse, error) {
	payload := types.SendEmailPayload{
		FromAddress: e.notificationConf.EmailFromAddress,
		ToAddress:   email,
		DynamicData: map[string]interface{}{
			"first_name": firstName,
			"api_key":    apiKey,
			"email":      email,
		},
	}

	templateID := getTemplateID("partner_onboarding_success", e.primaryProvider.GetName())
	return e.SendTemplateEmail(ctx, payload, templateID)
}

// getTemplateID returns the appropriate template ID based on email type and provider
func getTemplateID(emailType, provider string) string {
	// Template ID mapping based on provider and email type
	templates := map[string]map[string]string{
		"sendgrid": {
			"verification":               "d-f26d853bbb884c0c856f0bbda894032c",
			"password_reset":             "d-8b689801cd9947748775ccd1c4cc932e",
			"welcome":                    "d-b425f024e6554c5ba2b4d03ab0a8b25d",
			"kyb_approval":               "d-5ebb862274214ba79eae226c09300aa7",
			"kyb_rejection":              "d-6917f9c32105467b8dd806a5a3dd32dc",
			"webhook_failure":            "d-da75eee4966544ad92dcd060421d4e12",
			"partner_onboarding_success": "d-da75eee4966544ad92dcd060421d4a13",
		},
		"brevo": {
			"verification":               "5",
			"password_reset":             "6",
			"welcome":                    "4",
			"kyb_approval":               "7",
			"kyb_rejection":              "8",
			"webhook_failure":            "9",
			"partner_onboarding_success": "57",
		},
		"mailgun": {
			"verification":               "mailgun-verification-template-id",               // TODO: Add actual template ID
			"password_reset":             "mailgun-password-reset-template-id",             // TODO: Add actual template ID
			"welcome":                    "mailgun-welcome-template-id",                    // TODO: Add actual template ID
			"kyb_approval":               "mailgun-kyb-approval-template-id",               // TODO: Add actual template ID
			"kyb_rejection":              "mailgun-kyb-rejection-template-id",              // TODO: Add actual template ID
			"webhook_failure":            "mailgun-webhook-failure-template-id",            // TODO: Add actual template ID
			"partner_onboarding_success": "mailgun-partner-onboarding-success-template-id", // TODO: Add actual template ID
		},
	}

	if providerTemplates, exists := templates[provider]; exists {
		if templateID, exists := providerTemplates[emailType]; exists {
			return templateID
		}
	}

	// Fallback to SendGrid templates if provider-specific template not found
	if provider != "sendgrid" {
		return getTemplateID(emailType, "sendgrid")
	}

	// Final fallback
	return ""
}
