package services

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/types"
	"github.com/stretchr/testify/assert"
)

var (
	mailgunEndpoint  = fmt.Sprintf("https://api.mailgun.net/v3/%s/messages", notificationConf.EmailDomain)
	sendGridEndpoint = "https://api.sendgrid.com/v3/mail/send"

	testToken     = "test-token"
	testEmail     = "test@paycrest.io"
	testFirstName = "John"
)

func TestEmailService(t *testing.T) {
	// activate httpmock
	httpmock.Activate()
	defer httpmock.Deactivate()

	// register mock response
	httpmock.RegisterResponder("POST", mailgunEndpoint,
		func(r *http.Request) (*http.Response, error) {
			return httpmock.NewBytesResponse(200, []byte(`{"id": "01", "message": "Sent"}`)), nil
		},
	)

	httpmock.RegisterResponder("POST", sendGridEndpoint,
		func(r *http.Request) (*http.Response, error) {
			resp := httpmock.NewBytesResponse(202, nil)
			resp.Header.Set("X-Message-Id", "thisisatestid")
			return resp, nil
		},
	)
	srv := NewEmailService(SENDGRID_MAIL_PROVIDER)
	ctx := context.Background()

	// t.Run("Mailgun", func(t *testing.T) {

	// 	t.Run("SendVerificationEmail should work properly and return a response payload", func(t *testing.T) {
	// 		srv := NewEmailService(MAILGUN_MAIL_PROVIDER)

	// 		response, err := srv.SendVerificationEmail(context.Background(), testToken, testEmail)

	// 		// error checker.
	// 		assert.NoError(t, err, "unexpected error")

	// 		// assert the test token was sent.
	// 		assert.NotEmpty(t, response.Id, "response ID should not be empty")
	// 	})
	// })

	t.Run("SendGrid", func(t *testing.T) {

		t.Run("SendVerificationEmail should work properly and return a response payload", func(t *testing.T) {

			response, err := srv.SendVerificationEmail(ctx, testToken, testEmail, testFirstName)

			// error checker.
			assert.NoError(t, err, "unexpected error")

			// assert the test token was sent.
			assert.NotEmpty(t, response.Id, "response ID should not be empty")
			assert.Equal(t, "thisisatestid", response.Id, "response ID should be equal to thisisatestid")
		})

		t.Run("testMail service",
			func(t *testing.T) {
				_, err := SendTemplateEmail(types.SendEmailPayload{
					FromAddress: config.NotificationConfig().EmailFromAddress,
					ToAddress:   "johnDoe@gmail.com",
					DynamicData: map[string]interface{}{
						"code":       "654321",
						"first_name": testFirstName,
					},
				}, "d-f26d853bbb884c0c856f0bbda894032c")
				assert.NoError(t, err)
			})

		t.Run("SendWelcomeEmail should work properly and return a response payload", func(t *testing.T) {

			scopes := []string{"sender", "provider"}
			response, err := srv.SendWelcomeEmail(ctx, testEmail, testFirstName, scopes)

			// error checker
			assert.NoError(t, err, "unexpected error")

			// assert the response
			assert.NotEmpty(t, response.Id, "response ID should not be empty")
			assert.Equal(t, "thisisatestid", response.Id, "response ID should be equal to thisisatestid")
		})

		t.Run("SendWelcomeEmail with single scope", func(t *testing.T) {

			scopes := []string{"sender"}
			response, err := srv.SendWelcomeEmail(ctx, testEmail, testFirstName, scopes)

			// error checker
			assert.NoError(t, err, "unexpected error")

			// assert the response
			assert.NotEmpty(t, response.Id, "response ID should not be empty")
			assert.Equal(t, "thisisatestid", response.Id, "response ID should be equal to thisisatestid")
		})

		t.Run("SendWelcomeEmail with empty scopes", func(t *testing.T) {

			scopes := []string{}
			response, err := srv.SendWelcomeEmail(ctx, testEmail, testFirstName, scopes)

			// error checker
			assert.NoError(t, err, "unexpected error")

			// assert the response
			assert.NotEmpty(t, response.Id, "response ID should not be empty")
			assert.Equal(t, "thisisatestid", response.Id, "response ID should be equal to thisisatestid")
		})
	})
}
