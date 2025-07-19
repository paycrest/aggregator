package accounts

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/providerprofile"
	userEnt "github.com/paycrest/aggregator/ent/user"
	"github.com/paycrest/aggregator/ent/verificationtoken"
	svc "github.com/paycrest/aggregator/services"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	u "github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/paycrest/aggregator/utils/token"
)

var authConf = config.AuthConfig()
var serverConf = config.ServerConfig()

// AuthController is the controller type for the auth endpoints
type AuthController struct {
	apiKeyService *svc.APIKeyService
	emailService  *svc.EmailService
	slackService  *svc.SlackService
}

// NewAuthController creates a new instance of AuthController with injected services
func NewAuthController() *AuthController {
	return &AuthController{
		apiKeyService: svc.NewAPIKeyService(),
		emailService:  svc.NewEmailService(svc.SENDGRID_MAIL_PROVIDER),
		slackService:  svc.NewSlackService(serverConf.SlackWebhookURL),
	}
}

// Register controller validates the payload and creates a new user.
// It hashes the password provided by the user.
// It also sends an email to verify the user's email address.
func (ctrl *AuthController) Register(ctx *gin.Context) {
	var payload types.RegisterPayload

	serverConf := config.ServerConfig()

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	tx, err := db.Client.Tx(ctx)
	if err != nil {
		logger.Errorf("Error: Failed to create new user: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error",
			"Failed to create new user", nil)
		return
	}

	// Check if user with email already exists
	userTmp, _ := tx.User.
		Query().
		Where(
			userEnt.EmailEQ(strings.ToLower(payload.Email)),
		).
		Only(ctx)

	if userTmp != nil {
		_ = tx.Rollback()
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"User with email already exists", nil)
		return
	}

	// Save the user
	scope := strings.Join(payload.Scopes, " ")
	userCreate := tx.User.
		Create().
		SetFirstName(payload.FirstName).
		SetLastName(payload.LastName).
		SetEmail(strings.ToLower(payload.Email)).
		SetPassword(payload.Password).
		SetScope(scope)

	// Checking the environment to set the user as verified and give early access
	if serverConf.Environment != "production" && serverConf.Environment != "staging" {
		userCreate = userCreate.SetIsEmailVerified(true)
	}

	user, err := userCreate.Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		logger.Errorf("Error: Failed to save new user: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error",
			"Failed to create new user", nil)
		return
	}

	// Send verification email
	verificationToken, err := tx.VerificationToken.
		Create().
		SetOwner(user).
		SetScope(verificationtoken.ScopeEmailVerification).
		SetExpiryAt(time.Now().Add(authConf.PasswordResetLifespan)).
		Save(ctx)
	if err != nil {
		logger.Errorf("Error: Failed to create verification token: %v", err)
	}

	if serverConf.Environment == "production" {
		if verificationToken != nil {
			if _, err := ctrl.emailService.SendVerificationEmail(ctx, verificationToken.Token, user.Email, user.FirstName); err != nil {
				logger.WithFields(logger.Fields{
					"Error":  fmt.Sprintf("%v", err),
					"UserID": user.ID,
				}).Errorf("Failed to send verification email")
			}
		}
	}

	scopes := payload.Scopes

	// Create a provider profile
	var providerCurrencies []string
	if u.ContainsString(scopes, "provider") {
		currencies := payload.Currencies
		if len(currencies) == 0 {
			_ = tx.Rollback()
			u.APIResponse(ctx, http.StatusBadRequest, "error",
				"Currencies are required for provider account", nil)
			return
		}

		fiatCurrencies := make([]*ent.FiatCurrency, len(currencies))
		var unsupportedCurrencies []string
		for i, currency := range currencies {
			fiatCurrency, err := tx.FiatCurrency.
				Query().
				Where(
					fiatcurrency.IsEnabledEQ(true),
					fiatcurrency.CodeEQ(strings.ToUpper(currency)),
				).
				Only(ctx)
			if err != nil {
				if ent.IsNotFound(err) {
					unsupportedCurrencies = append(unsupportedCurrencies, strings.ToUpper(currency))
					continue
				}
				_ = tx.Rollback()
				u.APIResponse(ctx, http.StatusInternalServerError, "error",
					"Failed to create new user", nil)
				return
			}
			fiatCurrencies[i] = fiatCurrency
			providerCurrencies = append(providerCurrencies, fiatCurrency.Code) // Collect all currencies
		}

		if len(unsupportedCurrencies) > 0 {
			_ = tx.Rollback()
			u.APIResponse(ctx, http.StatusBadRequest, "error",
				"Failed to validate payload", []types.ErrorData{{
					Field:   "Currencies",
					Message: fmt.Sprintf("Currencies not supported: %s", strings.Join(unsupportedCurrencies, ", ")),
				}})
			return
		}

		provider, err := tx.ProviderProfile.
			Create().
			AddCurrencies(fiatCurrencies...).
			SetVisibilityMode(providerprofile.VisibilityModePrivate).
			SetUser(user).
			SetProvisionMode(providerprofile.ProvisionModeAuto).
			Save(ctx)
		if err != nil {
			_ = tx.Rollback()
			logger.WithFields(logger.Fields{
				"Error":  fmt.Sprintf("%v", err),
				"UserID": user.ID,
			}).Errorf("Failed to create provider profile")
			u.APIResponse(ctx, http.StatusInternalServerError, "error",
				"Failed to create new user", nil)
			return
		}

		// Generate the API key using the service
		_, _, err = ctrl.apiKeyService.GenerateAPIKey(ctx, tx, nil, provider)
		if err != nil {
			_ = tx.Rollback()
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"UserID":     user.ID,
				"ProviderID": provider.ID,
			}).Errorf("Failed to create API key for provider")
			u.APIResponse(ctx, http.StatusInternalServerError, "error",
				"Failed to create new user", nil)
			return
		}
	}

	// Create a sender profile
	if u.ContainsString(scopes, "sender") {
		sender, err := tx.SenderProfile.
			Create().
			SetUser(user).
			Save(ctx)
		if err != nil {
			_ = tx.Rollback()
			logger.WithFields(logger.Fields{
				"Error":  fmt.Sprintf("%v", err),
				"UserID": user.ID,
			}).Errorf("Failed to create sender profile")
			u.APIResponse(ctx, http.StatusInternalServerError, "error",
				"Failed to create new user", nil)
			return
		}

		// Generate the API key using the service
		_, _, err = ctrl.apiKeyService.GenerateAPIKey(ctx, tx, sender, nil)
		if err != nil {
			_ = tx.Rollback()
			logger.WithFields(logger.Fields{
				"Error":    fmt.Sprintf("%v", err),
				"UserID":   user.ID,
				"SenderID": sender.ID,
			}).Errorf("Failed to create API key for sender")
			u.APIResponse(ctx, http.StatusInternalServerError, "error",
				"Failed to create new user", nil)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		logger.Errorf("Error: Failed to commit transaction: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error",
			"Failed to create new user", nil)
		return
	}

	response := &types.RegisterResponse{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		FirstName: user.FirstName,
		LastName:  user.LastName,
	}

	if !user.IsEmailVerified {
		response.Email = user.Email
	}

	u.APIResponse(ctx, http.StatusCreated, "success", "User created successfully", response)
}

// Login controller validates the payload and creates a new user.
func (ctrl *AuthController) Login(ctx *gin.Context) {
	var payload types.LoginPayload

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	// Fetch user by email
	user, err := db.Client.User.
		Query().
		Where(userEnt.EmailEQ(strings.ToLower(payload.Email))).
		Only(ctx)

	if err != nil {
		u.APIResponse(ctx, http.StatusUnauthorized, "error",
			"Email and password do not match any user", nil,
		)
		return
	}

	// Check if the password is correct
	passwordMatch := crypto.CheckPasswordHash(payload.Password, user.Password)
	if !passwordMatch {
		u.APIResponse(ctx, http.StatusUnauthorized, "error",
			"Email and password do not match any user", nil,
		)
		return
	}

	// Generate JWT pair
	accessToken, refreshToken, err := token.GeneratePairJWT(user.ID.String(), user.Scope)

	if err != nil {
		logger.Errorf("Error : Failed to create token pair during login: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error",
			"Failed to create token pair", nil,
		)
		return
	}

	// Check if user's email is verified
	if !user.IsEmailVerified {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Email is not verified, please verify your email", nil,
		)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Successfully logged in", &types.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Scopes:       strings.Split(user.Scope, " "),
	})
}

// RefreshJWT controller returns a new access token given a valid refresh token.
func (ctrl *AuthController) RefreshJWT(ctx *gin.Context) {
	var payload types.RefreshJWTPayload

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	// Validate the refresh token
	claims, err := token.ValidateJWT(payload.RefreshToken)
	userID, ok := claims["sub"].(string)
	if err != nil || !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid or expired refresh token", nil)
		return
	}
	scope, ok := claims["scope"].(string)
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid or expired refresh token", nil)
		return
	}

	// Generate a new access token
	accessToken, err := token.GenerateAccessJWT(userID, scope)
	if err != nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to generate access token", nil)
		return
	}

	// Return the new access token
	u.APIResponse(ctx, http.StatusOK, "success", "Successfully refreshed access token", &types.RefreshResponse{
		AccessToken: accessToken,
	})
}

// ConfirmEmail controller validates the payload and confirm the users email.
func (ctrl *AuthController) ConfirmEmail(ctx *gin.Context) {
	var payload types.ConfirmEmailPayload

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	// Fetch verification token
	verificationToken, vtErr := db.Client.VerificationToken.
		Query().
		Where(
			verificationtoken.TokenEQ(payload.Token),
			verificationtoken.HasOwnerWith(userEnt.EmailEQ(payload.Email)),
		).
		WithOwner().
		Only(ctx)
	if vtErr != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid verification token", vtErr.Error())
		return
	}

	if time.Now().After(verificationToken.ExpiryAt) {
		err := db.Client.VerificationToken.
			DeleteOneID(verificationToken.ID).Exec(ctx)
		if err != nil {
			logger.Errorf("ConfirmEmailError.VerificationToken.Delete: %v", err)
		}
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Token is expired", nil)
		return
	}

	// Update User IsEmailVerified to true
	user, setIfVerifiedErr := verificationToken.Edges.Owner.
		Update().
		SetIsEmailVerified(true).
		Save(ctx)
	if setIfVerifiedErr != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to verify user email", setIfVerifiedErr.Error())
		return
	}

	err := db.Client.VerificationToken.
		DeleteOneID(verificationToken.ID).Exec(ctx)
	if err != nil {
		logger.Errorf("ConfirmEmailError.VerificationToken.Delete: %v", err)
	}

	// Send welcome email after email verification
	if _, err := ctrl.emailService.SendWelcomeEmail(ctx, user.Email, user.FirstName, strings.Split(user.Scope, " ")); err != nil {
		logger.WithFields(logger.Fields{
			"Error":  fmt.Sprintf("%v", err),
			"UserID": user.ID,
		}).Errorf("Failed to send welcome email")
	}

	// Return a success response
	u.APIResponse(ctx, http.StatusOK, "success", "User email verified successfully", nil)
}

// ResendVerificationToken controller resends the verification token to the users email.
func (ctrl *AuthController) ResendVerificationToken(ctx *gin.Context) {
	var payload types.ResendTokenPayload

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	// Fetch User account.
	user, userErr := db.Client.User.Query().Where(userEnt.EmailEQ(payload.Email)).Only(ctx)
	if userErr != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid credential", userErr.Error())
	}

	// Generate VerificationToken.
	verificationtoken, vtErr := db.Client.VerificationToken.
		Create().
		SetOwner(user).
		SetScope(verificationtoken.Scope(payload.Scope)).
		SetExpiryAt(time.Now().Add(authConf.PasswordResetLifespan)).
		Save(ctx)
	if vtErr != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to generate verification token", vtErr.Error())
		return
	}

	if _, err := ctrl.emailService.SendVerificationEmail(ctx, verificationtoken.Token, user.Email, user.FirstName); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to send verification email", err.Error())
		return
	}

	// Return a success response
	u.APIResponse(ctx, http.StatusOK, "success", "Verification token has been sent to your email", nil)
}

// ResetPassword resets user's password. A valid token is required to set new password
func (ctrl *AuthController) ResetPassword(ctx *gin.Context) {
	var payload types.ResetPasswordPayload

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	// Verify reset token
	token, err := db.Client.VerificationToken.
		Query().
		Where(
			verificationtoken.TokenEQ(payload.ResetToken),
			verificationtoken.ScopeEQ(verificationtoken.ScopeResetPassword),
		).
		WithOwner().
		Only(ctx)
	if err != nil || token == nil || token.Edges.Owner == nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid password reset token", nil)
		return
	}

	if time.Now().After(token.ExpiryAt) {
		err := db.Client.VerificationToken.
			DeleteOneID(token.ID).Exec(ctx)
		if err != nil {
			logger.Errorf("ResetPasswordError.VerificationToken.Delete: %v", err)
		}
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Token is expired", nil)
		return
	}

	_, err = db.Client.User.
		UpdateOne(token.Edges.Owner).
		SetPassword(payload.Password).
		Save(ctx)
	if err != nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to reset password", nil)
		return
	}

	// Delete verification token
	verificationErr := db.Client.VerificationToken.
		DeleteOneID(token.ID).Exec(ctx)
	if verificationErr != nil {
		logger.Errorf("ResetPasswordError.VerificationToken.Delete: %v", verificationErr)
	}

	// Return a success response
	u.APIResponse(ctx, http.StatusOK, "success", "Password reset was successful", nil)
}

// ResetPasswordToken sends a reset password token to user's email
func (ctrl *AuthController) ResetPasswordToken(ctx *gin.Context) {
	var payload types.ResetPasswordTokenPayload

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	// Get user account.
	user, userErr := db.Client.User.
		Query().
		Where(userEnt.EmailEQ(payload.Email)).
		Only(ctx)
	if userErr != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Email does not belong to any user", nil)
	}

	// Generate password reset token.
	passwordResetToken, rtErr := db.Client.VerificationToken.
		Create().
		SetOwner(user).
		SetScope(verificationtoken.ScopeResetPassword).
		SetExpiryAt(time.Now().Add(authConf.PasswordResetLifespan)).
		Save(ctx)
	if rtErr != nil || passwordResetToken == nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to generate reset password token", nil)
		return
	}

	if _, err := ctrl.emailService.SendPasswordResetEmail(ctx, passwordResetToken.Token, user.Email, user.FirstName); err != nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to send reset password token", nil)
		return
	}

	// Return a success response
	u.APIResponse(ctx, http.StatusOK, "success", "A reset token has been sent to your email", nil)
}

// ChangePassword changes user's password. An authorized user is required to change password
func (ctrl *AuthController) ChangePassword(ctx *gin.Context) {
	var payload types.ChangePasswordPayload

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	// get user id from context
	user_id := ctx.GetString("user_id")
	// parse user id to uuid
	userID, err := uuid.Parse(user_id)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid credential", nil)
		return
	}

	// Fetch user account.
	user, err := db.Client.User.
		Query().
		Where(userEnt.IDEQ(userID)).
		Only(ctx)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid credential", nil)
		return
	}

	// Check if the old password is correct
	passwordMatch := crypto.CheckPasswordHash(payload.OldPassword, user.Password)
	if !passwordMatch {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Old password is incorrect", nil)
		return
	}

	// Check if the new password is the same as the old password
	passwordMatch = crypto.CheckPasswordHash(payload.NewPassword, user.Password)
	if passwordMatch {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "New password cannot be the same as old password", nil)
		return
	}

	// Update user password
	_, err = db.Client.User.
		UpdateOne(user).
		SetPassword(payload.NewPassword).
		Save(ctx)
	if err != nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to change password", nil)
		return
	}

	// Return a success response
	u.APIResponse(ctx, http.StatusOK, "success", "Password changed successfully", nil)
}

// DeleteAccount deletes user's account. An authorized user is required to delete account
func (ctrl *AuthController) DeleteAccount(ctx *gin.Context) {
	// get user id from context
	user_id := ctx.GetString("user_id")
	// parse user id to uuid
	userID, err := uuid.Parse(user_id)
	if err != nil {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid authorization token", nil)
		return
	}

	// Fetch user account.
	user, err := db.Client.User.
		Query().
		Where(userEnt.IDEQ(userID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid authorization token", nil)
			return
		} else {
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to delete account", nil)
			return
		}
	}

	// Delete user account, delete user account will delete all related data via cascade
	err = db.Client.User.
		DeleteOne(user).
		Exec(ctx)
	if err != nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to delete account", nil)
		return
	}

	// Return a success response
	u.APIResponse(ctx, http.StatusOK, "success", "Account deleted successfully", nil)
}
