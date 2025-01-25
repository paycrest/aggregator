package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
	"fmt"

	"github.com/google/uuid"
	"github.com/jarcoal/httpmock"
	_ "github.com/mattn/go-sqlite3"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/routers/middleware"
	svc "github.com/paycrest/aggregator/services"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
	"github.com/paycrest/aggregator/ent/enttest"
	userEnt "github.com/paycrest/aggregator/ent/user"
	"github.com/paycrest/aggregator/ent/verificationtoken"
	"github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/test"
	"github.com/paycrest/aggregator/utils/token"
	"github.com/stretchr/testify/assert"
	"github.com/paycrest/aggregator/config"
)

func TestAuth(t *testing.T) {
	// setup httpmock
	httpmock.Activate()
	defer httpmock.Deactivate()

	// register mock response
	httpmock.RegisterResponder("POST", "https://api.mailgun.net/v3/sandbox9c66b379b78d43d2b1533bf2a09a5325.mailgun.org/messages",
		func(r *http.Request) (*http.Response, error) {
			return httpmock.NewBytesResponse(200, []byte(`{"id": "01", "message": "Sent"}`)), nil
		},
	)

	httpmock.RegisterResponder("POST", "https://api.sendgrid.com/v3/mail/send",
		func(r *http.Request) (*http.Response, error) {
			resp := httpmock.NewBytesResponse(202, nil)
			resp.Header.Set("X-Message-Id", "thisisatestid")
			return resp, nil
		},
	)

	// Set up test database client
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	db.Client = client

	// Set up test fiat currency
	_, _ = test.CreateTestFiatCurrency(nil)

	// Set up test routers
	router := gin.New()
	ctrl := &AuthController{
		apiKeyService: svc.NewAPIKeyService(),
		emailService:  svc.NewEmailService(svc.SENDGRID_MAIL_PROVIDER),
	}

	router.POST("/register", ctrl.Register)
	router.POST("/login", ctrl.Login)
	router.POST("/confirm-account", ctrl.ConfirmEmail)
	router.POST("/resend-token", ctrl.ResendVerificationToken)
	router.POST("/refresh", ctrl.RefreshJWT)
	router.POST("/reset-password-token", ctrl.ResetPasswordToken)
	router.PATCH("/reset-password", ctrl.ResetPassword)
	router.PATCH("/change-password", middleware.JWTMiddleware, ctrl.ChangePassword)

	var userID string
	var accessToken string

	t.Run("Register", func(t *testing.T) {
		t.Run("with valid payload and both sender and provider scopes", func(t *testing.T) {
			// Test register with valid payload
			payload := types.RegisterPayload{
				FirstName: "Ike",
				LastName:  "Ayo",
				Email:     "ikeayo@example.com",
				Password:  "password",
				Currency:  "NGN",
				Scopes:    []string{"sender", "provider"},
			}

			header := map[string]string{
				"Client-Type": "web",
			}

			res, err := test.PerformRequest(t, "POST", "/register", payload, header, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusCreated, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "User created successfully", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is not of type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			// Assert the response data
			assert.Contains(t, data, "id")
			match, _ := regexp.MatchString(
				`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`,
				data["id"].(string),
			)
			if !match {
				t.Errorf("Expected '%s' to be a valid UUID", data["id"].(string))
			}

			userID = data["id"].(string)

			// Parse the user ID string to uuid.UUID
			userUUID, err := uuid.Parse(userID)
			assert.NoError(t, err)
			assert.Equal(t, "", data["email"].(string))
			assert.Equal(t, payload.FirstName, data["firstName"].(string))
			assert.Equal(t, payload.LastName, data["lastName"].(string))

			// Query the database to check if API key and profile were created for the sender
			user, err := db.Client.User.
				Query().
				Where(userEnt.IDEQ(userUUID)).
				WithProviderProfile(
					func(q *ent.ProviderProfileQuery) {
						q.WithAPIKey()
					}).
				WithSenderProfile(func(q *ent.SenderProfileQuery) {
					q.WithAPIKey()
				}).
				Only(context.Background())

			assert.NoError(t, err)

			assert.NotNil(t, user)
			assert.NotNil(t, user.Edges.SenderProfile.Edges.APIKey)
			assert.NotNil(t, user.Edges.ProviderProfile.Edges.APIKey)

		})
		t.Run("with only sender scope payload", func(t *testing.T) {
			// Test register with valid payload
			payload := types.RegisterPayload{
				FirstName: "Ike",
				LastName:  "Ayo",
				Email:     "ikeayo1@example.com",
				Password:  "password1",
				Scopes:    []string{"sender"},
			}

			res, err := test.PerformRequest(t, "POST", "/register", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusCreated, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "User created successfully", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is not of type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			// Assert the response data
			assert.Contains(t, data, "id")
			match, _ := regexp.MatchString(
				`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`,
				data["id"].(string),
			)
			if !match {
				t.Errorf("Expected '%s' to be a valid UUID", data["id"].(string))
			}

			userID = data["id"].(string)

			// Parse the user ID string to uuid.UUID
			userUUID, err := uuid.Parse(userID)
			assert.NoError(t, err)
			assert.Equal(t, "", data["email"].(string))
			assert.Equal(t, payload.FirstName, data["firstName"].(string))
			assert.Equal(t, payload.LastName, data["lastName"].(string))

			// Query the database to check if API key and profile were created for the sender
			user, err := db.Client.User.
				Query().
				Where(userEnt.IDEQ(userUUID)).
				WithProviderProfile().
				WithSenderProfile(func(spq *ent.SenderProfileQuery) {
					spq.WithAPIKey()
				}).
				Only(context.Background())
			assert.NoError(t, err)

			assert.NotNil(t, user)
			assert.NotNil(t, user.Edges.SenderProfile.Edges.APIKey)
			assert.Nil(t, user.Edges.ProviderProfile)
		})
		t.Run("with only provider scope payload", func(t *testing.T) {
			// Test register with valid payload
			payload := types.RegisterPayload{
				FirstName: "Ike",
				LastName:  "Ayo",
				Email:     "ikeayo2@example.com",
				Password:  "password2",
				Currency:  "NGN",
				Scopes:    []string{"provider"},
			}

			header := map[string]string{
				"Client-Type": "web",
			}

			res, err := test.PerformRequest(t, "POST", "/register", payload, header, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusCreated, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "User created successfully", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is not of type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			// Assert the response data
			assert.Contains(t, data, "id")
			match, _ := regexp.MatchString(
				`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`,
				data["id"].(string),
			)
			if !match {
				t.Errorf("Expected '%s' to be a valid UUID", data["id"].(string))
			}

			// Parse the user ID string to uuid.UUID
			userUUID, err := uuid.Parse(data["id"].(string))
			assert.NoError(t, err)
			assert.Equal(t, "", data["email"].(string))
			assert.Equal(t, payload.FirstName, data["firstName"].(string))
			assert.Equal(t, payload.LastName, data["lastName"].(string))

			// Query the database to check if API key and profile were created for the sender
			user, err := db.Client.User.
				Query().
				Where(userEnt.IDEQ(userUUID)).
				WithProviderProfile(
					func(ppq *ent.ProviderProfileQuery) {
						ppq.WithAPIKey()
					}).
				WithSenderProfile().
				Only(context.Background())
			assert.NoError(t, err)

			assert.NotNil(t, user)
			assert.NotNil(t, user.Edges.ProviderProfile.Edges.APIKey)
			assert.Nil(t, user.Edges.SenderProfile)

			// t.Run("test unsupported fiat", func(t *testing.T) {
			// 	// Test register with valid payload
			// 	payload := types.RegisterPayload{
			// 		FirstName:   "john",
			// 		LastName:    "doe",
			// 		Email:       "john@example.com",
			// 		Password:    "password",
			// 		Currency:    "GHS",
			// 		Scopes:      []string{"provider"},
			// 	}

			// 	headers := map[string]string{
			// 		"Client-Type": "mobile",
			// 	}

			// 	res, err := test.PerformRequest(t, "POST", "/register", payload, headers, router)
			// 	assert.NoError(t, err)

			// 	// Assert the response body
			// 	assert.Equal(t, http.StatusInternalServerError, res.Code)
			// })
		})
		t.Run("from the provider app", func(t *testing.T) {
			// Test register with valid payload
			payload := types.RegisterPayload{
				FirstName: "Ike",
				LastName:  "Ayo",
				Email:     "ikeayoprovider@example.com",
				Password:  "password",
				Currency:  "NGN",
				Scopes:    []string{"provider"},
			}

			headers := map[string]string{
				"Client-Type": "mobile",
			}

			res, err := test.PerformRequest(t, "POST", "/register", payload, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusCreated, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is not of type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			// Parse the user ID string to uuid.UUID
			userUUID, err := uuid.Parse(data["id"].(string))
			assert.NoError(t, err)

			// Query the database to check if API key and profile were created for the provider
			user, err := db.Client.User.
				Query().
				Where(userEnt.IDEQ(userUUID)).
				WithProviderProfile(
					func(q *ent.ProviderProfileQuery) {
						q.WithAPIKey()
					}).
				WithSenderProfile().
				Only(context.Background())
			assert.NoError(t, err)

			assert.NotNil(t, user)
			assert.NotNil(t, user.Edges.ProviderProfile.Edges.APIKey)
			assert.Nil(t, user.Edges.SenderProfile)
		})

		t.Run("with existing user", func(t *testing.T) {
			// Test register with existing user
			payload := types.RegisterPayload{
				FirstName: "Ike",
				LastName:  "Ayo",
				Email:     "ikeayo@example.com",
				Password:  "password",
				Scopes:    []string{"sender"},
			}

			res, err := test.PerformRequest(t, "POST", "/register", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "User with email already exists", response.Message)
			assert.Nil(t, response.Data)
		})

		t.Run("with invalid email", func(t *testing.T) {
			// Test register with invalid email
			payload := types.RegisterPayload{
				FirstName: "Ike",
				LastName:  "Ayo",
				Email:     "invalid-email",
				Password:  "password",
				Scopes:    []string{"sender"},
			}

			res, err := test.PerformRequest(t, "POST", "/register", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Failed to validate payload", response.Message)
			assert.Equal(t, "error", response.Status)
			data, ok := response.Data.([]interface{})
			assert.True(t, ok, "response.Data is not of type []interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			// Assert the response errors in data
			assert.Len(t, data, 1)
			errorMap, ok := data[0].(map[string]interface{})
			assert.True(t, ok, "error is not of type map[string]interface{}")
			assert.NotNil(t, errorMap, "error is nil")
			assert.Contains(t, errorMap, "field")
			assert.Equal(t, "Email", errorMap["field"].(string))
			assert.Contains(t, errorMap, "message")
			assert.Equal(t, "Must be a valid email address", errorMap["message"].(string))
		})

		t.Run("with invalid scope", func(t *testing.T) {
			// Test register with invalid email
			payload := types.RegisterPayload{
				FirstName: "Ike",
				LastName:  "Ayo",
				Email:     "ikeayovalidator@example.com",
				Password:  "password",
				Scopes:    []string{"validator"},
			}

			res, err := test.PerformRequest(t, "POST", "/register", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Failed to validate payload", response.Message)
			assert.Equal(t, "error", response.Status)
			data, ok := response.Data.([]interface{})
			assert.True(t, ok, "response.Data is not of type []interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			// Assert the response errors in data
			assert.Len(t, data, 1)
			errorMap, ok := data[0].(map[string]interface{})
			assert.True(t, ok, "error is not of type map[string]interface{}")
			assert.NotNil(t, errorMap, "error is nil")
			assert.Contains(t, errorMap, "field")
			assert.Equal(t, "Scopes[0]", errorMap["field"].(string))
			assert.Contains(t, errorMap, "message")
		})

		t.Run("testing UserEarlyAccess", func(t *testing.T) {
			tests := []struct {
				name             string
				environment      string
				expectedEarlyAccess bool
			}{
				{
					name:             "Non-production environment (development)", 
					environment:      "development", 
					expectedEarlyAccess: true,
				},
				{
					name:             "Non-production environment (staging)", 
					environment:      "staging", 
					expectedEarlyAccess: true,
				},
				{
					name:             "Production environment", 
					environment:      "production", 
					expectedEarlyAccess: false,
				},
			}
	
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					// Mock the server configuration
					config.ServerConfig().Environment = tt.environment
	
					// Simulate user registration
					ctx := context.Background()
					user, err := client.User.Create().
						SetFirstName("Test").
						SetLastName("User").
						SetEmail(fmt.Sprintf("test-%s@example.com", tt.environment)).
						SetPassword("password").
						Save(ctx)
					assert.NoError(t, err)
	
					// Check the HasEarlyAccess field
					assert.Equal(t, tt.expectedEarlyAccess, user.HasEarlyAccess)
	
					// Cleanup
					err = client.User.DeleteOne(user).Exec(ctx)
					assert.NoError(t, err)
				})
			}
		})

	})

	t.Run("ConfirmEmail", func(t *testing.T) {
		// fetch user
		userUUID, err := uuid.Parse(userID)
		assert.NoError(t, err)

		user, fetchUserErr := db.Client.User.
			Query().
			Where(userEnt.IDEQ(userUUID)).
			Only(context.Background())
		assert.NoError(t, fetchUserErr, "failed to fetch user by userID")

		// generate verificationToken
		verificationtoken, vtErr := user.QueryVerificationToken().
			Where(verificationtoken.ScopeEQ(verificationtoken.ScopeEmailVerification)).
			Only(context.Background())
		assert.NoError(t, vtErr)

		t.Run("confirm user email", func(t *testing.T) {
			// Test user email confirmation-token
			payload := types.ConfirmEmailPayload{
				Token: verificationtoken.Token,
				Email: user.Email,
			}

			res, err := test.PerformRequest(t, "POST", "/confirm-account", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Nil(t, response.Data)

			updateUser, uErr := client.User.Query().Where(
				userEnt.EmailEQ(user.Email),
			).Only(context.Background())
			assert.NoError(t, uErr)
			assert.True(t, updateUser.IsEmailVerified)
		})
	})

	t.Run("expiriedToken", func(t *testing.T) {
		// fetch user
		userUUID, err := uuid.Parse(userID)
		assert.NoError(t, err)

		user, fetchUserErr := db.Client.User.
			Query().
			Where(userEnt.IDEQ(userUUID)).
			Only(context.Background())
		assert.NoError(t, fetchUserErr, "failed to fetch user by userID")

		// generate verificationToken
		verificationtoken, vtErr := db.Client.VerificationToken.
			Create().
			SetOwner(user).
			SetScope(verificationtoken.ScopeResetPassword).
			SetExpiryAt(time.Now().Add(authConf.PasswordResetLifespan)).
			Save(context.Background())
		assert.NoError(t, vtErr)
		t.Run("try to use expired token", func(t *testing.T) {
			time.Sleep(time.Duration(viper.GetInt("PASSWORD_RESET_LIFESPAN")) * time.Minute)
			// Test user email confirmation-token
			payload := types.ConfirmEmailPayload{
				Token: verificationtoken.Token,
				Email: user.Email,
			}

			res, err := test.PerformRequest(t, "POST", "/confirm-account", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Nil(t, response.Data)
		})
	})

	t.Run("Login", func(t *testing.T) {
		t.Run("with valid credentials for user with unverified email", func(t *testing.T) {
			// Test login with unverified account
			payload := types.LoginPayload{
				Email:    "ikeayo@example.com",
				Password: "password",
			}

			// Mark user as unverified
			_, err := db.Client.User.
				Update().
				Where(userEnt.EmailEQ(strings.ToLower(payload.Email))).
				SetIsEmailVerified(false).
				Save(context.Background())
			assert.NoError(t, err, "failed to set isEmailVerified to false")

			res, err := test.PerformRequest(t, "POST", "/login", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Email is not verified, please verify your email", response.Message)
			assert.Nil(t, response.Data)
		})

		t.Run("with valid credentials for user with provider and sender scopes", func(t *testing.T) {
			// Test login with valid credentials
			payload := types.LoginPayload{
				Email:    "ikeayo@example.com",
				Password: "password",
			}

			// Mark user as verified
			user, _ := db.Client.User.
				Query().
				Where(userEnt.EmailEQ(strings.ToLower(payload.Email))).
				Only(context.Background())

			_, err := db.Client.User.
				UpdateOne(user).
				SetIsEmailVerified(true).
				Save(context.Background())
			assert.NoError(t, err, "failed to set isEmailVerified to true")

			res, err := test.PerformRequest(t, "POST", "/login", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Successfully logged in", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is not of type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			// Assert the response data
			assert.Contains(t, data, "accessToken")
			assert.NotEmpty(t, data["accessToken"].(string))
			assert.Contains(t, data, "refreshToken")
			assert.NotEmpty(t, data["refreshToken"].(string))
		})

		t.Run("with valid credentials for user with only sender scope", func(t *testing.T) {
			// Test login with valid credentials
			payload := types.LoginPayload{
				Email:    "ikeayo1@example.com",
				Password: "password1",
			}

			res, err := test.PerformRequest(t, "POST", "/login", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Successfully logged in", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is not of type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			// Assert the response data
			assert.Contains(t, data, "accessToken")
			assert.NotEmpty(t, data["accessToken"].(string))
			assert.Contains(t, data, "refreshToken")
			assert.NotEmpty(t, data["refreshToken"].(string))
		})

		t.Run("with invalid credentials", func(t *testing.T) {
			// Test login with invalid credentials
			payload := types.LoginPayload{
				Email:    "ikeayo@example.com",
				Password: "wrong-password",
			}

			res, err := test.PerformRequest(t, "POST", "/login", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusUnauthorized, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Email and password do not match any user", response.Message)
			assert.Nil(t, response.Data)
		})
	})

	t.Run("RefreshJWT", func(t *testing.T) {
		t.Run("with a valid refresh token", func(t *testing.T) {
			refreshToken, err := token.GenerateRefreshJWT(userID, "sender")
			assert.NoError(t, err, "failed to generate refresh token")

			// Test refresh token with valid refresh token
			payload := types.RefreshJWTPayload{
				RefreshToken: refreshToken,
			}

			res, err := test.PerformRequest(t, "POST", "/refresh", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Successfully refreshed access token", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is not of type map[string]interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			// Assert the response data
			assert.Contains(t, data, "accessToken")
			assert.NotEmpty(t, data["accessToken"].(string))
			assert.NotContains(t, data, "refreshToken")
			accessToken = data["accessToken"].(string)
		})

		t.Run("with an invalid refresh token", func(t *testing.T) {
			refreshToken := "invalid-refresh-token"

			// Test refresh token with invalid refresh token
			payload := types.RefreshJWTPayload{
				RefreshToken: refreshToken,
			}

			res, err := test.PerformRequest(t, "POST", "/refresh", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusUnauthorized, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Invalid or expired refresh token", response.Message)
		})
	})

	t.Run("ResendVerificationToken", func(t *testing.T) {
		// fetch user
		user, fetchUserErr := db.Client.User.
			Query().
			Where(userEnt.IDEQ(uuid.MustParse(userID))).
			Only(context.Background())
		assert.NoError(t, fetchUserErr, "failed to fetch user by userID")

		_, err := user.Update().SetIsEmailVerified(false).Save(context.Background())
		assert.NoError(t, err, "failed to set isEmailVerified to false")

		t.Run("verification token should be resent", func(t *testing.T) {
			// construct resend verification token payload
			payload := types.ResendTokenPayload{
				Scope: verificationtoken.ScopeEmailVerification.String(),
				Email: user.Email,
			}

			res, err := test.PerformRequest(t, "POST", "/resend-token", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			// verificationtokens should be one
			amount := user.QueryVerificationToken().
				Where(verificationtoken.ScopeEQ(verificationtoken.ScopeEmailVerification)).
				CountX(context.Background())
			assert.Equal(t, 1, amount)
		})
	})

	t.Run("ResetPasswordToken", func(t *testing.T) {
		user, err := db.Client.User.
			Query().
			Where(userEnt.IDEQ(uuid.MustParse(userID))).
			Only(context.Background())
		assert.NoError(t, err, "Failed to fetch user by userID")

		t.Run("password reset token should be set in db", func(t *testing.T) {
			payload := types.ResetPasswordTokenPayload{
				Email: user.Email,
			}
			res, err := test.PerformRequest(t, "POST", "/reset-password-token", payload, nil, router)

			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			// There should be 1 scoped reset-password verification token
			amount := db.Client.VerificationToken.Query().
				Where(verificationtoken.ScopeEQ(verificationtoken.ScopeResetPassword)).
				CountX(context.Background())

			assert.Equal(t, 1, amount)
		})
	})

	t.Run("ResetPassword", func(t *testing.T) {

		userUUID, err := uuid.Parse(userID)
		assert.NoError(t, err)

		userInstance, getUserErr := db.Client.User.
			Query().
			Where(userEnt.IDEQ(userUUID)).
			Only(context.Background())
		assert.NoError(t, getUserErr, "failed to get user by userID")

		t.Run("FailsForEmptyResetToken", func(t *testing.T) {
			ResetPasswordPayload := map[string]string{
				"new-password": "1111000090",
			}
			res, err := test.PerformRequest(t, "PATCH", "/reset-password", ResetPasswordPayload, nil, router)

			assert.Error(t, errors.New("Invalid password reset token"), err)
			// Assert the response body
			assert.Equal(t, http.StatusBadRequest, res.Code)
		})

		t.Run("FailsForExpiredResetToken", func(t *testing.T) {

			resetToken, err := db.Client.VerificationToken.Create().SetExpiryAt(time.Now().
				Add(-10 * time.Second)).SetOwner(userInstance).SetScope(verificationtoken.ScopeResetPassword).
				Save(context.Background())
			assert.NoError(t, err)

			ResetPasswordPayload := map[string]string{
				"new-password": "1111000090",
				"reset-token":  resetToken.Token,
			}
			res, err := test.PerformRequest(t, "PATCH", "/reset-password", ResetPasswordPayload, nil, router)

			assert.Error(t, errors.New("Invalid password reset token"), err)
			// Assert the response body
			assert.Equal(t, http.StatusBadRequest, res.Code)
		})

		t.Run("FailsForWrongScope", func(t *testing.T) {

			emailVerificationToken, err := db.Client.VerificationToken.Create().SetExpiryAt(time.Now().
				Add(10 * time.Second)).SetOwner(userInstance).SetScope(verificationtoken.ScopeEmailVerification).
				Save(context.Background())
			assert.NoError(t, err)

			ResetPasswordPayload := map[string]string{
				"new-password": "1111000090",
				"reset-token":  emailVerificationToken.Token,
			}
			res, err := test.PerformRequest(t, "PATCH", "/reset-password", ResetPasswordPayload, nil, router)

			assert.Error(t, errors.New("Invalid password reset token"), err)
			// Assert the response body
			assert.Equal(t, http.StatusBadRequest, res.Code)
		})

		t.Run("ResetPasswordInDBForValidResetToken", func(t *testing.T) {

			// get initial VerificationToken count
			beforeTestCount, err := db.Client.VerificationToken.Query().Aggregate(ent.Count()).Int(context.Background())
			assert.NoError(t, err)

			resetToken, err := db.Client.VerificationToken.Create().SetExpiryAt(time.Now().
				Add(5 * time.Minute)).SetOwner(userInstance).SetScope(verificationtoken.ScopeResetPassword).
				Save(context.Background())
			assert.NoError(t, err)

			resetPasswordPayload := map[string]string{
				"password":   "1111000090",
				"resetToken": resetToken.Token,
			}

			res, err := test.PerformRequest(t, "PATCH", "/reset-password", resetPasswordPayload, nil, router)
			assert.NoError(t, err)
			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			// Check password in DB is reset for user
			updatedUser, getUserErr := db.Client.User.
				Query().
				Where(userEnt.IDEQ(userUUID)).
				Only(context.Background())
			assert.NoError(t, getUserErr, "failed to get updated user after password reset")

			passwordCompareErr := bcrypt.CompareHashAndPassword([]byte(updatedUser.Password), []byte(resetPasswordPayload["password"]))
			assert.NoError(t, passwordCompareErr, "Password reset did not update DB properly")

			// get initial VerificationToken count
			afterTestCount, err := db.Client.VerificationToken.Query().Aggregate(ent.Count()).Int(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, beforeTestCount, afterTestCount)
		})
	})

	// test change password for an authenticated user
	t.Run("ChangePassword", func(t *testing.T) {
		t.Run("with wrong old password", func(t *testing.T) {
			// Test change password with invalid old password
			payload := types.ChangePasswordPayload{
				OldPassword: "wrong-password",
				NewPassword: "new-password",
			}

			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			res, err := test.PerformRequest(t, "PATCH", "/change-password", payload, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Old password is incorrect", response.Message)
			assert.Nil(t, response.Data)
		})

		t.Run("with correct old password", func(t *testing.T) {
			// Test change password with valid old password
			payload := types.ChangePasswordPayload{
				OldPassword: "1111000090",
				NewPassword: "new-password",
			}

			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			res, err := test.PerformRequest(t, "PATCH", "/change-password", payload, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Password changed successfully", response.Message)
			assert.Nil(t, response.Data)

			// Query the database to check if password was changed
			user, err := db.Client.User.
				Query().
				Where(userEnt.IDEQ(uuid.MustParse(userID))).
				Only(context.Background())
			assert.NoError(t, err)

			assert.NotNil(t, user)
			assert.True(t, crypto.CheckPasswordHash(payload.NewPassword, user.Password))
		})
	})
}
