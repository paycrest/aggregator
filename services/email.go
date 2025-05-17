package services

import (
	"context"
	"fmt"
	"time"

	mailgunv3 "github.com/mailgun/mailgun-go/v3"
	fastshot "github.com/opus-domini/fast-shot"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

var (
	notificationConf = config.NotificationConfig()

	mailgunClient       mailgunv3.Mailgun
	_DefaultFromAddress = notificationConf.EmailFromAddress
)

type MailProvider string

const (
	MAILGUN_MAIL_PROVIDER  MailProvider = "MAILGUN"
	SENDGRID_MAIL_PROVIDER MailProvider = "SENDGRID"
)

// EmailService provides functionality to sending emails via a mailer provider
type EmailService struct {
	MailProvider MailProvider
}

// NewEmailService creates a new instance of EmailService with a given MailProvider.
func NewEmailService(mailProvider MailProvider) *EmailService {
	return &EmailService{MailProvider: mailProvider}
}

// NewMailgun initialize mailgunv3.Mailgun and can be used to initialize a mocked Mailgun interface.
func NewMailgun(m mailgunv3.Mailgun) {
	if m != nil {
		mailgunClient = m
		return
	}

	mailgunClient = mailgunv3.NewMailgun(notificationConf.EmailDomain, notificationConf.EmailAPIKey)
}

// SendEmail performs the action for sending an email.
func (m *EmailService) SendEmail(ctx context.Context, payload types.SendEmailPayload) (types.SendEmailResponse, error) {
	switch m.MailProvider {
	case MAILGUN_MAIL_PROVIDER:
		return sendEmailViaMailgun(ctx, payload)
	case SENDGRID_MAIL_PROVIDER:
		return sendEmailViaSendGrid(ctx, payload)
	default:
		return types.SendEmailResponse{}, fmt.Errorf("unsupported mail provider")
	}
}

// SendVerificationEmail performs the actions for sending a verification token to the user email.
func (m *EmailService) SendVerificationEmail(ctx context.Context, token, email, firstName string) (types.SendEmailResponse, error) {
	payload := types.SendEmailPayload{
		FromAddress: _DefaultFromAddress,
		ToAddress:   email,
		DynamicData: map[string]interface{}{
			"first_name": firstName,
			"token":      token,
		},
	}
	return SendTemplateEmail(payload, "d-f26d853bbb884c0c856f0bbda894032c")

}

// SendPasswordResetEmail performs the actions for sending a password reset token to the user email.
func (m *EmailService) SendPasswordResetEmail(ctx context.Context, token, email, firstName string) (types.SendEmailResponse, error) {

	payload := types.SendEmailPayload{
		FromAddress: _DefaultFromAddress,
		ToAddress:   email,
		DynamicData: map[string]interface{}{
			"first_name": firstName,
			"token":      token,
		},
	}
	return SendTemplateEmail(payload, "d-8b689801cd9947748775ccd1c4cc932e")
}

// sendEmailViaMailgun performs the actions for sending an email.
func sendEmailViaMailgun(ctx context.Context, content types.SendEmailPayload) (types.SendEmailResponse, error) {
	// initialize
	NewMailgun(mailgunClient)

	message := mailgunClient.NewMessage(
		content.FromAddress,
		content.Subject,
		content.Body,
		content.ToAddress,
	)

	response, id, err := mailgunClient.Send(ctx, message)

	return types.SendEmailResponse{Id: id, Response: response}, err
}

// sendEmailViaSendGrid performs the actions for sending an email.
func sendEmailViaSendGrid(ctx context.Context, content types.SendEmailPayload) (types.SendEmailResponse, error) {
	_ = ctx
	from := mail.NewEmail("Paycrest", "<no-reply@paycrest.io>")
	to := mail.NewEmail("", content.ToAddress)
	body := mail.NewContent("text/plain", content.Body)
	htmlBody := mail.NewContent("text/html", content.HTMLBody)

	m := mail.NewV3Mail()
	m.Subject = content.Subject
	m.SetFrom(from)
	m.AddContent(body)
	m.AddContent(htmlBody)

	p := mail.NewPersonalization()
	p.AddTos(to)
	m.AddPersonalizations(p)

	request := sendgrid.GetRequest(notificationConf.EmailAPIKey, "/v3/mail/send", fmt.Sprintf("https://%s", notificationConf.EmailDomain))
	request.Method = "POST"
	request.Body = mail.GetRequestBody(m)
	response, err := sendgrid.API(request)
	if err != nil || response.StatusCode >= 400 {
		return types.SendEmailResponse{}, err
	}

	return types.SendEmailResponse{Id: response.Headers["X-Message-Id"][0]}, nil
}

// SendTemplateEmail sends an email using SendGrid's dynamic template.
func SendTemplateEmail(content types.SendEmailPayload, templateId string) (types.SendEmailResponse, error) {
	reqBody := map[string]interface{}{
		"from": map[string]string{
			"email": content.FromAddress,
		},
		"personalizations": []map[string]interface{}{
			{
				"to": []map[string]string{
					{
						"email": content.ToAddress,
						"name":  "Paycrest",
					},
				},
				"dynamic_template_data": content.DynamicData,
			},
		},
		"template_id": templateId,
	}

	res, err := fastshot.NewClient(fmt.Sprintf("https://%s", notificationConf.EmailDomain)).
		Config().SetTimeout(30*time.Second).
		Auth().BearerToken(notificationConf.EmailAPIKey).
		Header().Add("Content-Type", "application/json").
		Build().POST("/v3/mail/send").
		Body().AsJSON(reqBody).
		Send()
	if err != nil {
		logger.Errorf("Failed to send Email: %v", err)
		return types.SendEmailResponse{}, fmt.Errorf("error sending request: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		logger.Errorf("Failed to decode %v response after sending Email: %v", data, err)
		return types.SendEmailResponse{}, fmt.Errorf("error parsing response: %w", err)
	}

	return types.SendEmailResponse{
		Response: res.RawResponse.Header.Get("X-Message-Id"),
		Id:       res.RawResponse.Header.Get("X-Message-Id"),
	}, nil
}

// SendTemplateEmailWithJsonAttachment sends an email using SendGrid's dynamic template with a JSON attachment.
func SendTemplateEmailWithJsonAttachment(content types.SendEmailPayload, templateId string) error {
	reqBody := map[string]interface{}{
		"from": map[string]string{
			"email": content.FromAddress,
		},
		"personalizations": []map[string]interface{}{
			{
				"to": []map[string]string{
					{
						"email": content.ToAddress,
						"name":  "Paycrest",
					},
				},
				"dynamic_template_data": content.DynamicData,
			},
		},
		"template_id": templateId,
		"attachments": []map[string]interface{}{
			{
				"content": content.Body,
				"type":    "text/json", "disposition": "attachment",
				"filename": "payload.json",
			},
		},
	}

	res, err := fastshot.NewClient(fmt.Sprintf("https://%s", notificationConf.EmailDomain)).
		Config().SetTimeout(30*time.Second).
		Auth().BearerToken(notificationConf.EmailAPIKey).
		Header().Add("Content-Type", "application/json").
		Build().POST("/v3/mail/send").
		Body().AsJSON(reqBody).
		Send()
	if err != nil {
		logger.Errorf("Failed to send Email with JSON attachment: %v", err)
		return fmt.Errorf("error sending request: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		logger.Errorf("Failed to decode %v response after sending Email with JSON attachment: %v", data, err)
		return fmt.Errorf("error parsing response: %w", err)
	}

	return nil
}

// SendWelcomeEmail sends a welcome email to the user
func (m *EmailService) SendWelcomeEmail(ctx context.Context, email, firstName string, scopes []string) (types.SendEmailResponse, error) {
    payload := types.SendEmailPayload{
        FromAddress: _DefaultFromAddress,
        ToAddress:   email,
        DynamicData: map[string]interface{}{
            "first_name": firstName,
            "email":     email,
            "scopes":    scopes,
        },
    }
    return SendTemplateEmail(payload, "WELCOME_EMAIL_TEMPLATE_ID")
}
