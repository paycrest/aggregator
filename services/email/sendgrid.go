package email

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// SendGridProvider implements EmailProvider for SendGrid
type SendGridProvider struct {
	config *config.NotificationConfiguration
}

// NewSendGridProvider creates a new SendGrid provider
func NewSendGridProvider(config *config.NotificationConfiguration) *SendGridProvider {
	return &SendGridProvider{
		config: config,
	}
}

// SendEmail sends an email via SendGrid
func (s *SendGridProvider) SendEmail(ctx context.Context, payload types.SendEmailPayload) (types.SendEmailResponse, error) {
	from := mail.NewEmail("Paycrest", payload.FromAddress)
	to := mail.NewEmail("", payload.ToAddress)
	body := mail.NewContent("text/plain", payload.Body)
	htmlBody := mail.NewContent("text/html", payload.HTMLBody)

	m := mail.NewV3Mail()
	m.Subject = payload.Subject
	m.SetFrom(from)
	m.AddContent(body)
	m.AddContent(htmlBody)

	p := mail.NewPersonalization()
	p.AddTos(to)
	m.AddPersonalizations(p)

	request := sendgrid.GetRequest(s.config.EmailAPIKey, "/v3/mail/send", fmt.Sprintf("https://%s", s.config.EmailDomain))
	request.Method = "POST"
	request.Body = mail.GetRequestBody(m)
	response, err := sendgrid.API(request)
	if err != nil || response.StatusCode >= 400 {
		logger.Errorf("Failed to send email via SendGrid: %v", err)
		return types.SendEmailResponse{}, fmt.Errorf("sendgrid send error: %w", err)
	}

	return types.SendEmailResponse{
		Id:       response.Headers["X-Message-Id"][0],
		Response: response.Headers["X-Message-Id"][0],
	}, nil
}

// SendTemplateEmail sends a template email via SendGrid
func (s *SendGridProvider) SendTemplateEmail(ctx context.Context, payload types.SendEmailPayload, templateID string) (types.SendEmailResponse, error) {
	reqBody := map[string]interface{}{
		"from": map[string]string{
			"email": payload.FromAddress,
		},
		"personalizations": []map[string]interface{}{
			{
				"to": []map[string]string{
					{
						"email": payload.ToAddress,
					},
				},
				"dynamic_template_data": payload.DynamicData,
			},
		},
		"template_id": templateID,
	}

	res, err := fastshot.NewClient(fmt.Sprintf("https://%s", s.config.EmailDomain)).
		Config().SetTimeout(30*time.Second).
		Auth().BearerToken(s.config.EmailAPIKey).
		Header().Add("Content-Type", "application/json").
		Build().POST("/v3/mail/send").
		Body().AsJSON(reqBody).
		Send()
	if err != nil {
		logger.Errorf("Failed to send template email via SendGrid: %v", err)
		return types.SendEmailResponse{}, fmt.Errorf("sendgrid template send error: %w", err)
	}

	// Check for HTTP errors first (preserving original logic)
	if res.StatusCode() >= 500 { // Return on server errors
		logger.Errorf("HTTP server error from SendGrid: %d", res.StatusCode())
		return types.SendEmailResponse{}, fmt.Errorf("sendgrid server error: %d", res.StatusCode())
	}
	if res.StatusCode() >= 400 { // Return on client errors
		logger.Errorf("HTTP client error from SendGrid: %d", res.StatusCode())
		return types.SendEmailResponse{}, fmt.Errorf("sendgrid client error: %d", res.StatusCode())
	}

	// Parse JSON response using fastshot's RawBody method
	bodyReader := res.RawBody()
	defer bodyReader.Close()

	body, err := io.ReadAll(bodyReader)
	if err != nil {
		logger.Errorf("Failed to read response body from SendGrid: %v", err)
		return types.SendEmailResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		logger.Errorf("Failed to decode SendGrid response: %v", err)
		return types.SendEmailResponse{}, fmt.Errorf("sendgrid response parse error: %w", err)
	}

	return types.SendEmailResponse{
		Response: res.RawResponse.Header.Get("X-Message-Id"),
		Id:       res.RawResponse.Header.Get("X-Message-Id"),
	}, nil
}

// GetName returns the provider name
func (s *SendGridProvider) GetName() string {
	return "sendgrid"
}
