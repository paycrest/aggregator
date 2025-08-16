package email

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/types"
	"github.com/stretchr/testify/assert"
)

type mockProvider struct {
	name              string
	sendErr           error
	sendTemplateErr   error
	lastTemplateID    string
	responseToReturn  types.SendEmailResponse
	callCount         int64
	templateCallCount int64
	lastPayload       types.SendEmailPayload
	mu                sync.RWMutex
}

func (m *mockProvider) GetName() string {
	return m.name
}

func (m *mockProvider) SendEmail(ctx context.Context, payload types.SendEmailPayload) (types.SendEmailResponse, error) {
	atomic.AddInt64(&m.callCount, 1)
	m.mu.Lock()
	m.lastPayload = payload
	m.mu.Unlock()
	return m.responseToReturn, m.sendErr
}

func (m *mockProvider) SendTemplateEmail(ctx context.Context, payload types.SendEmailPayload, templateID string) (types.SendEmailResponse, error) {
	atomic.AddInt64(&m.templateCallCount, 1)
	m.mu.Lock()
	m.lastTemplateID = templateID
	m.lastPayload = payload
	m.mu.Unlock()
	return m.responseToReturn, m.sendTemplateErr
}

// GetCallCount returns the current call count safely
func (m *mockProvider) GetCallCount() int64 {
	return atomic.LoadInt64(&m.callCount)
}

// GetTemplateCallCount returns the current template call count safely
func (m *mockProvider) GetTemplateCallCount() int64 {
	return atomic.LoadInt64(&m.templateCallCount)
}

// GetLastTemplateID returns the last template ID safely
func (m *mockProvider) GetLastTemplateID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastTemplateID
}

// GetLastPayload returns the last payload safely
func (m *mockProvider) GetLastPayload() types.SendEmailPayload {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastPayload
}

func TestSendEmail_PrimarySuccess(t *testing.T) {
	primary := &mockProvider{name: "sendgrid", responseToReturn: types.SendEmailResponse{Id: "123"}}
	fallback := &mockProvider{name: "mailgun"}
	service := &EmailService{
		primaryProvider:  primary,
		fallbackProvider: fallback,
		notificationConf: &config.NotificationConfiguration{},
	}

	resp, err := service.SendEmail(context.Background(), types.SendEmailPayload{})
	assert.NoError(t, err)
	assert.Equal(t, "123", resp.Id)
	assert.Equal(t, int64(1), primary.GetCallCount())
	assert.Equal(t, int64(0), fallback.GetCallCount())
}

func TestSendEmail_FallbackSuccess(t *testing.T) {
	primary := &mockProvider{name: "sendgrid", sendErr: errors.New("primary failed")}
	fallback := &mockProvider{name: "mailgun", responseToReturn: types.SendEmailResponse{Id: "456"}}
	service := &EmailService{
		primaryProvider:  primary,
		fallbackProvider: fallback,
		notificationConf: &config.NotificationConfiguration{},
	}

	resp, err := service.SendEmail(context.Background(), types.SendEmailPayload{})
	assert.NoError(t, err)
	assert.Equal(t, "456", resp.Id)
	assert.Equal(t, int64(1), primary.GetCallCount())
	assert.Equal(t, int64(1), fallback.GetCallCount())
}

func TestSendEmail_AllFail(t *testing.T) {
	primary := &mockProvider{name: "sendgrid", sendErr: errors.New("primary failed")}
	fallback := &mockProvider{name: "mailgun", sendErr: errors.New("fallback failed")}
	service := &EmailService{
		primaryProvider:  primary,
		fallbackProvider: fallback,
		notificationConf: &config.NotificationConfiguration{},
	}

	_, err := service.SendEmail(context.Background(), types.SendEmailPayload{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "all email providers failed")
	assert.Equal(t, int64(1), primary.GetCallCount())
	assert.Equal(t, int64(1), fallback.GetCallCount())
}

func TestSendEmail_PayloadPropagation(t *testing.T) {
	payload := types.SendEmailPayload{
		FromAddress: "from@test.com",
		ToAddress:   "to@test.com",
		Subject:     "Test Subject",
		DynamicData: map[string]interface{}{"key": "value"},
	}

	primary := &mockProvider{name: "sendgrid", responseToReturn: types.SendEmailResponse{Id: "123"}}
	service := &EmailService{
		primaryProvider:  primary,
		fallbackProvider: &mockProvider{name: "mailgun"},
		notificationConf: &config.NotificationConfiguration{},
	}

	_, err := service.SendEmail(context.Background(), payload)
	assert.NoError(t, err)
	lastPayload := primary.GetLastPayload()
	assert.Equal(t, payload.FromAddress, lastPayload.FromAddress)
	assert.Equal(t, payload.ToAddress, lastPayload.ToAddress)
	assert.Equal(t, payload.Subject, lastPayload.Subject)
	assert.Equal(t, payload.DynamicData, lastPayload.DynamicData)
}

func TestSendTemplateEmail_PrimarySuccess(t *testing.T) {
	primary := &mockProvider{name: "sendgrid", responseToReturn: types.SendEmailResponse{Id: "templ-123"}}
	fallback := &mockProvider{name: "mailgun"}
	service := &EmailService{
		primaryProvider:  primary,
		fallbackProvider: fallback,
		notificationConf: &config.NotificationConfiguration{},
	}

	resp, err := service.SendTemplateEmail(context.Background(), types.SendEmailPayload{}, "template-id")
	assert.NoError(t, err)
	assert.Equal(t, "templ-123", resp.Id)
	assert.Equal(t, int64(1), primary.GetTemplateCallCount())
	assert.Equal(t, int64(0), fallback.GetTemplateCallCount())
	assert.Equal(t, "template-id", primary.GetLastTemplateID())
}

func TestSendTemplateEmail_FallbackSuccess(t *testing.T) {
	primary := &mockProvider{name: "sendgrid", sendTemplateErr: errors.New("primary template failed")}
	fallback := &mockProvider{name: "mailgun", responseToReturn: types.SendEmailResponse{Id: "fallback-456"}}
	service := &EmailService{
		primaryProvider:  primary,
		fallbackProvider: fallback,
		notificationConf: &config.NotificationConfiguration{},
	}

	resp, err := service.SendTemplateEmail(context.Background(), types.SendEmailPayload{}, "template-id")
	assert.NoError(t, err)
	assert.Equal(t, "fallback-456", resp.Id)
	assert.Equal(t, int64(1), primary.GetTemplateCallCount())
	assert.Equal(t, int64(1), fallback.GetTemplateCallCount())
	assert.Equal(t, "template-id", fallback.GetLastTemplateID())
}

func TestSendTemplateEmail_NoFallbackProvider(t *testing.T) {
	primary := &mockProvider{name: "sendgrid", sendTemplateErr: errors.New("primary failed")}
	service := &EmailService{
		primaryProvider:  primary,
		fallbackProvider: nil,
		notificationConf: &config.NotificationConfiguration{},
	}

	_, err := service.SendTemplateEmail(context.Background(), types.SendEmailPayload{}, "template-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no fallback provider available for template")
}

func TestSendTemplateEmail_AllProvidersFail(t *testing.T) {
	primary := &mockProvider{name: "sendgrid", sendTemplateErr: errors.New("primary failed")}
	fallback := &mockProvider{name: "mailgun", sendTemplateErr: errors.New("fallback failed")}
	service := &EmailService{
		primaryProvider:  primary,
		fallbackProvider: fallback,
		notificationConf: &config.NotificationConfiguration{},
	}

	_, err := service.SendTemplateEmail(context.Background(), types.SendEmailPayload{}, "template-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "all email providers failed for template")
}

func TestSendVerificationEmail(t *testing.T) {
	primary := &mockProvider{name: "sendgrid", responseToReturn: types.SendEmailResponse{Id: "verify-123"}}
	service := &EmailService{
		primaryProvider:  primary,
		fallbackProvider: &mockProvider{name: "mailgun"},
		notificationConf: &config.NotificationConfiguration{EmailFromAddress: "noreply@paycrest.io"},
	}

	resp, err := service.SendVerificationEmail(context.Background(), "token123", "user@test.com", "John")
	assert.NoError(t, err)
	assert.Equal(t, "verify-123", resp.Id)
	assert.Equal(t, "d-f26d853bbb884c0c856f0bbda894032c", primary.GetLastTemplateID())
	lastPayload := primary.GetLastPayload()
	assert.Equal(t, "noreply@paycrest.io", lastPayload.FromAddress)
	assert.Equal(t, "user@test.com", lastPayload.ToAddress)
	assert.Equal(t, "John", lastPayload.DynamicData["first_name"])
	assert.Equal(t, "token123", lastPayload.DynamicData["token"])
}

func TestSendPasswordResetEmail(t *testing.T) {
	primary := &mockProvider{name: "brevo", responseToReturn: types.SendEmailResponse{Id: "reset-456"}}
	service := &EmailService{
		primaryProvider:  primary,
		fallbackProvider: &mockProvider{name: "sendgrid"},
		notificationConf: &config.NotificationConfiguration{EmailFromAddress: "support@paycrest.io"},
	}

	resp, err := service.SendPasswordResetEmail(context.Background(), "resetToken", "user@example.com", "Jane")
	assert.NoError(t, err)
	assert.Equal(t, "reset-456", resp.Id)
	assert.Equal(t, "6", primary.GetLastTemplateID()) // Brevo password reset template ID
	lastPayload := primary.GetLastPayload()
	assert.Equal(t, "support@paycrest.io", lastPayload.FromAddress)
	assert.Equal(t, "user@example.com", lastPayload.ToAddress)
	assert.Equal(t, "Jane", lastPayload.DynamicData["first_name"])
	assert.Equal(t, "resetToken", lastPayload.DynamicData["token"])
}

func TestSendWelcomeEmail(t *testing.T) {
	primary := &mockProvider{name: "mailgun", responseToReturn: types.SendEmailResponse{Id: "welcome-789"}}
	service := &EmailService{
		primaryProvider:  primary,
		fallbackProvider: &mockProvider{name: "sendgrid"},
		notificationConf: &config.NotificationConfiguration{EmailFromAddress: "welcome@paycrest.io"},
	}

	scopes := []string{"read", "write", "admin"}
	resp, err := service.SendWelcomeEmail(context.Background(), "new@user.com", "Alice", scopes)
	assert.NoError(t, err)
	assert.Equal(t, "welcome-789", resp.Id)
	assert.Equal(t, "mailgun-welcome-template-id", primary.GetLastTemplateID())
	lastPayload := primary.GetLastPayload()
	assert.Equal(t, "welcome@paycrest.io", lastPayload.FromAddress)
	assert.Equal(t, "new@user.com", lastPayload.ToAddress)
	assert.Equal(t, "Alice", lastPayload.DynamicData["first_name"])
	assert.Equal(t, "new@user.com", lastPayload.DynamicData["email"])
	assert.Equal(t, "read, write, admin", lastPayload.DynamicData["scopes"])
}

func TestSendKYBApprovalEmail(t *testing.T) {
	primary := &mockProvider{name: "sendgrid", responseToReturn: types.SendEmailResponse{Id: "kyb-approve-123"}}
	service := &EmailService{
		primaryProvider:  primary,
		fallbackProvider: &mockProvider{name: "brevo"},
		notificationConf: &config.NotificationConfiguration{EmailFromAddress: "kyb@paycrest.io"},
	}

	resp, err := service.SendKYBApprovalEmail(context.Background(), "business@company.com", "Robert")
	assert.NoError(t, err)
	assert.Equal(t, "kyb-approve-123", resp.Id)
	assert.Equal(t, "d-5ebb862274214ba79eae226c09300aa7", primary.GetLastTemplateID())
	lastPayload := primary.GetLastPayload()
	assert.Equal(t, "kyb@paycrest.io", lastPayload.FromAddress)
	assert.Equal(t, "business@company.com", lastPayload.ToAddress)
	assert.Equal(t, "Robert", lastPayload.DynamicData["first_name"])
}

func TestSendKYBRejectionEmail(t *testing.T) {
	primary := &mockProvider{name: "brevo", responseToReturn: types.SendEmailResponse{Id: "kyb-reject-456"}}
	service := &EmailService{
		primaryProvider:  primary,
		fallbackProvider: &mockProvider{name: "mailgun"},
		notificationConf: &config.NotificationConfiguration{EmailFromAddress: "kyb@paycrest.io"},
	}

	reason := "Incomplete documentation provided"
	resp, err := service.SendKYBRejectionEmail(context.Background(), "business@fail.com", "Sarah", reason)
	assert.NoError(t, err)
	assert.Equal(t, "kyb-reject-456", resp.Id)
	assert.Equal(t, "8", primary.GetLastTemplateID()) // Brevo KYB rejection template ID
	lastPayload := primary.GetLastPayload()
	assert.Equal(t, "kyb@paycrest.io", lastPayload.FromAddress)
	assert.Equal(t, "business@fail.com", lastPayload.ToAddress)
	assert.Equal(t, "Sarah", lastPayload.DynamicData["first_name"])
	assert.Equal(t, reason, lastPayload.DynamicData["reason_for_decline"])
}

func TestGetTemplateID_SendgridTemplates(t *testing.T) {
	tests := []struct {
		emailType string
		expected  string
	}{
		{"verification", "d-f26d853bbb884c0c856f0bbda894032c"},
		{"password_reset", "d-8b689801cd9947748775ccd1c4cc932e"},
		{"welcome", "d-b425f024e6554c5ba2b4d03ab0a8b25d"},
		{"kyb_approval", "d-5ebb862274214ba79eae226c09300aa7"},
		{"kyb_rejection", "d-6917f9c32105467b8dd806a5a3dd32dc"},
	}

	for _, tt := range tests {
		t.Run("sendgrid_"+tt.emailType, func(t *testing.T) {
			id := getTemplateID(tt.emailType, "sendgrid")
			assert.Equal(t, tt.expected, id)
		})
	}
}

func TestGetTemplateID_BrevoTemplates(t *testing.T) {
	tests := []struct {
		emailType string
		expected  string
	}{
		{"verification", "5"},
		{"password_reset", "6"},
		{"welcome", "4"},
		{"kyb_approval", "7"},
		{"kyb_rejection", "8"},
	}

	for _, tt := range tests {
		t.Run("brevo_"+tt.emailType, func(t *testing.T) {
			id := getTemplateID(tt.emailType, "brevo")
			assert.Equal(t, tt.expected, id)
		})
	}
}

func TestGetTemplateID_MailgunTemplates(t *testing.T) {
	tests := []struct {
		emailType string
		expected  string
	}{
		{"verification", "mailgun-verification-template-id"},
		{"password_reset", "mailgun-password-reset-template-id"},
		{"welcome", "mailgun-welcome-template-id"},
		{"kyb_approval", "mailgun-kyb-approval-template-id"},
		{"kyb_rejection", "mailgun-kyb-rejection-template-id"},
	}

	for _, tt := range tests {
		t.Run("mailgun_"+tt.emailType, func(t *testing.T) {
			id := getTemplateID(tt.emailType, "mailgun")
			assert.Equal(t, tt.expected, id)
		})
	}
}

func TestGetTemplateID_FallbackLogic(t *testing.T) {
	// Test unknown provider falls back to SendGrid
	id := getTemplateID("verification", "unknown-provider")
	assert.Equal(t, "d-f26d853bbb884c0c856f0bbda894032c", id)

	// Test unknown email type for known provider
	id = getTemplateID("unknown-email-type", "sendgrid")
	assert.Equal(t, "", id)

	// Test unknown email type for unknown provider (double fallback)
	id = getTemplateID("unknown-email-type", "unknown-provider")
	assert.Equal(t, "", id)
}

func TestGetTemplateID_EmptyInputs(t *testing.T) {
	// Test empty email type
	id := getTemplateID("", "sendgrid")
	assert.Equal(t, "", id)

	// Test empty provider
	id = getTemplateID("verification", "")
	assert.Equal(t, "d-f26d853bbb884c0c856f0bbda894032c", id)

	// Test both empty
	id = getTemplateID("", "")
	assert.Equal(t, "", id)
}

func TestEmailService_ConcurrentRequests(t *testing.T) {
	primary := &mockProvider{name: "sendgrid", responseToReturn: types.SendEmailResponse{Id: "concurrent-test"}}
	service := &EmailService{
		primaryProvider:  primary,
		fallbackProvider: &mockProvider{name: "mailgun"},
		notificationConf: &config.NotificationConfiguration{EmailFromAddress: "test@paycrest.io"},
	}

	// Test concurrent email sends
	done := make(chan bool, 3)
	for i := 0; i < 3; i++ {
		go func() {
			defer func() { done <- true }()
			_, err := service.SendVerificationEmail(context.Background(), "token", "test@example.com", "Test")
			assert.NoError(t, err)
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 3; i++ {
		<-done
	}

	assert.Equal(t, int64(3), primary.GetTemplateCallCount())
}

func TestEmailService_SpecializedEmailMethods_WithFallback(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(*EmailService) error
	}{
		{
			"verification_with_fallback",
			func(s *EmailService) error {
				_, err := s.SendVerificationEmail(context.Background(), "token", "user@test.com", "User")
				return err
			},
		},
		{
			"password_reset_with_fallback",
			func(s *EmailService) error {
				_, err := s.SendPasswordResetEmail(context.Background(), "reset", "user@test.com", "User")
				return err
			},
		},
		{
			"welcome_with_fallback",
			func(s *EmailService) error {
				_, err := s.SendWelcomeEmail(context.Background(), "user@test.com", "User", []string{"scope1"})
				return err
			},
		},
		{
			"kyb_approval_with_fallback",
			func(s *EmailService) error {
				_, err := s.SendKYBApprovalEmail(context.Background(), "user@test.com", "User")
				return err
			},
		},
		{
			"kyb_rejection_with_fallback",
			func(s *EmailService) error {
				_, err := s.SendKYBRejectionEmail(context.Background(), "user@test.com", "User", "Reason")
				return err
			},
		},
		{
			"webhook_failure_with_fallback",
			func(s *EmailService) error {
				_, err := s.SendWebhookFailureEmail(context.Background(), "user@test.com", "User")
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := &mockProvider{name: "sendgrid", sendTemplateErr: errors.New("primary failed")}
			fallback := &mockProvider{name: "mailgun", responseToReturn: types.SendEmailResponse{Id: "fallback-success"}}
			service := &EmailService{
				primaryProvider:  primary,
				fallbackProvider: fallback,
				notificationConf: &config.NotificationConfiguration{EmailFromAddress: "test@paycrest.io"},
			}

			err := tt.testFunc(service)
			assert.NoError(t, err)
			assert.Equal(t, int64(1), primary.GetTemplateCallCount())
			assert.Equal(t, int64(1), fallback.GetTemplateCallCount())
		})
	}
}

func TestSendWebhookFailureEmail_Success(t *testing.T) {
	primary := &mockProvider{name: "sendgrid", responseToReturn: types.SendEmailResponse{Id: "webhook-failure-123"}}
	service := &EmailService{
		primaryProvider:  primary,
		fallbackProvider: nil,
		notificationConf: &config.NotificationConfiguration{EmailFromAddress: "test@paycrest.io"},
	}

	resp, err := service.SendWebhookFailureEmail(context.Background(), "user@test.com", "TestUser")
	assert.NoError(t, err)
	assert.Equal(t, "webhook-failure-123", resp.Id)
	assert.Equal(t, int64(1), primary.GetTemplateCallCount())
	assert.Equal(t, "d-da75eee4966544ad92dcd060421d4e12", primary.GetLastTemplateID())

	// Verify the payload
	payload := primary.GetLastPayload()
	assert.Equal(t, "test@paycrest.io", payload.FromAddress)
	assert.Equal(t, "user@test.com", payload.ToAddress)
	assert.Equal(t, "TestUser", payload.DynamicData["first_name"])
}

func TestSendWebhookFailureEmail_WithFallback(t *testing.T) {
	primary := &mockProvider{name: "sendgrid", sendTemplateErr: errors.New("primary failed")}
	fallback := &mockProvider{name: "mailgun", responseToReturn: types.SendEmailResponse{Id: "fallback-webhook-failure"}}
	service := &EmailService{
		primaryProvider:  primary,
		fallbackProvider: fallback,
		notificationConf: &config.NotificationConfiguration{EmailFromAddress: "test@paycrest.io"},
	}

	resp, err := service.SendWebhookFailureEmail(context.Background(), "user@test.com", "TestUser")
	assert.NoError(t, err)
	assert.Equal(t, "fallback-webhook-failure", resp.Id)
	assert.Equal(t, int64(1), primary.GetTemplateCallCount())
	assert.Equal(t, int64(1), fallback.GetTemplateCallCount())
}
