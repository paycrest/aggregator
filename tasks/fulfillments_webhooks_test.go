package tasks

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/paycrest/aggregator/ent/webhookretryattempt"
	db "github.com/paycrest/aggregator/storage"
	"github.com/stretchr/testify/assert"
)

func TestRetryFailedWebhookNotifications(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	httpmock.Activate()
	defer httpmock.Deactivate()

	// Register mock failure response for Webhook
	httpmock.RegisterResponder("POST", testCtx.sender.WebhookURL,
		func(r *http.Request) (*http.Response, error) {
			return httpmock.NewBytesResponse(400, []byte(`{"id": "01", "message": "Sent"}`)), nil
		},
	)

	// Register mock email response for Brevo (primary provider)
	httpmock.RegisterResponder("POST", "https://api.brevo.com/v3/smtp/email",
		func(r *http.Request) (*http.Response, error) {
			bytes, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}

			// Assert email response contains userEmail and Name
			assert.Contains(t, string(bytes), testCtx.user.Email)
			assert.Contains(t, string(bytes), testCtx.user.FirstName)

			resp := httpmock.NewBytesResponse(201, nil)
			return resp, nil
		},
	)

	// Register mock email response for SendGrid (fallback provider)
	httpmock.RegisterResponder("POST", "https://api.sendgrid.com/v3/mail/send",
		func(r *http.Request) (*http.Response, error) {
			bytes, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}

			// Assert email response contains userEmail and Name
			assert.Contains(t, string(bytes), testCtx.user.Email)
			assert.Contains(t, string(bytes), testCtx.user.FirstName)

			resp := httpmock.NewBytesResponse(202, nil)
			return resp, nil
		},
	)

	err := RetryFailedWebhookNotifications()
	assert.NoError(t, err)

	hook, err := db.Client.WebhookRetryAttempt.
		Query().
		Where(webhookretryattempt.IDEQ(testCtx.webhook.ID)).
		Only(context.Background())
	assert.NoError(t, err)

	assert.Equal(t, webhookretryattempt.StatusExpired, hook.Status)
}
