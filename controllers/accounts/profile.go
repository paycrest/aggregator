package accounts

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/kybprofile"
	"github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/providercurrencies"
	"github.com/paycrest/aggregator/ent/providerfiataccount"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/provisionbucket"
	"github.com/paycrest/aggregator/ent/senderordertoken"
	"github.com/paycrest/aggregator/ent/senderprofile"
	"github.com/paycrest/aggregator/ent/token"
	userkyb "github.com/paycrest/aggregator/ent/user"
	svc "github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	u "github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"

	"github.com/gin-gonic/gin"
)

var orderConf = config.OrderConfig()

// ProfileController is a controller type for profile settings
type ProfileController struct {
	apiKeyService        *svc.APIKeyService
	priorityQueueService *svc.PriorityQueueService
}

// NewProfileController creates a new instance of ProfileController
func NewProfileController() *ProfileController {
	return &ProfileController{
		apiKeyService:        svc.NewAPIKeyService(),
		priorityQueueService: svc.NewPriorityQueueService(),
	}
}

// UpdateSenderProfile controller updates the sender profile
func (ctrl *ProfileController) UpdateSenderProfile(ctx *gin.Context) {
	var payload types.SenderProfilePayload

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	if payload.WebhookURL != "" && !u.IsURL(payload.WebhookURL) {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", []types.ErrorData{{
			Field:   "WebhookURL",
			Message: "Invalid URL",
		}})
		return
	}

	// Get sender profile from the context
	senderCtx, ok := ctx.Get("sender")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	sender := senderCtx.(*ent.SenderProfile)

	// save or update SenderOrderToken
	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
		return
	}

	update := tx.SenderProfile.Update().Where(senderprofile.IDEQ(sender.ID))

	if payload.WebhookURL != "" && payload.WebhookURL != sender.WebhookURL {
		update.SetWebhookURL(payload.WebhookURL)
	}

	if payload.DomainWhitelist != nil {
		update.SetDomainWhitelist(payload.DomainWhitelist)
	}

	hasConfiguredToken := false

	for _, tokenPayload := range payload.Tokens {

		if len(tokenPayload.Addresses) == 0 {
			u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("No wallet address provided for %s token", tokenPayload.Symbol), nil)
			return
		}

		// Check if token is supported
		_, err := tx.Token.
			Query().
			Where(token.Symbol(tokenPayload.Symbol)).
			First(ctx)
		if err != nil {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Token not supported", nil)
			return
		}

		var networksToTokenId map[string]int = map[string]int{}
		for _, address := range tokenPayload.Addresses {

			if strings.HasPrefix(address.Network, "tron") {
				feeAddressIsValid := u.IsValidTronAddress(address.FeeAddress)
				if address.FeeAddress != "" && !feeAddressIsValid {
					u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", []types.ErrorData{{
						Field:   "FeeAddress",
						Message: "Invalid Tron address",
					}})
					return
				}
				networksToTokenId[address.Network] = 0
			} else {
				feeAddressIsValid := u.IsValidEthereumAddress(address.FeeAddress)
				if address.FeeAddress != "" && !feeAddressIsValid {
					u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", []types.ErrorData{{
						Field:   "FeeAddress",
						Message: "Invalid Ethereum address",
					}})
					return
				}
				networksToTokenId[address.Network] = 0
			}
		}

		// Check if network is supported
		for key := range networksToTokenId {
			tokenId, err := tx.Token.
				Query().
				Where(
					token.And(
						token.HasNetworkWith(network.IdentifierEQ(key)),
						token.SymbolEQ(tokenPayload.Symbol),
					),
				).
				Only(ctx)
			if err != nil {
				u.APIResponse(
					ctx,
					http.StatusBadRequest,
					"error", "Network not supported - "+key,
					nil,
				)
				return
			}
			networksToTokenId[key] = tokenId.ID
		}

		// Delete existing sender order tokens for this token symbol to handle removals
		_, err = tx.SenderOrderToken.
			Delete().
			Where(
				senderordertoken.HasTokenWith(token.SymbolEQ(tokenPayload.Symbol)),
				senderordertoken.HasSenderWith(senderprofile.IDEQ(sender.ID)),
			).
			Exec(ctx)
		if err != nil {
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
			return
		}

		// Create new sender order tokens for the networks in the payload
		for _, address := range tokenPayload.Addresses {
			_, err := tx.SenderOrderToken.
				Create().
				SetSenderID(sender.ID).
				SetTokenID(networksToTokenId[address.Network]).
				SetRefundAddress(address.RefundAddress).
				SetFeePercent(tokenPayload.FeePercent).
				SetNillableMaxFeeCap(tokenPayload.MaxFeeCap).
				SetFeeAddress(address.FeeAddress).
				Save(ctx)
			if err != nil {
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
				return
			}
			// Check if this token is properly configured
			if address.RefundAddress != "" && address.FeeAddress != "" {
				hasConfiguredToken = true
			}
		}
	}

	// Set activation status based on whether at least one token is configured
	if hasConfiguredToken && !sender.IsActive {
		update.SetIsActive(true)
	} else if !hasConfiguredToken && sender.IsActive {
		update.SetIsActive(false)
	}

	// Save the sender profile update within the transaction
	_, err = update.Save(ctx)
	if err != nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
		return
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Profile updated successfully", nil)
}

// UpdateProviderProfile controller updates the provider profile
func (ctrl *ProfileController) UpdateProviderProfile(ctx *gin.Context) {
	var payload types.ProviderProfilePayload

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	// Get provider profile from the context
	providerCtx, ok := ctx.Get("provider")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	provider := providerCtx.(*ent.ProviderProfile)

	// Validate basic fields first (before starting transaction)
	if payload.HostIdentifier != "" {
		// Validate HTTPS protocol
		if !u.IsValidHttpsUrl(payload.HostIdentifier) {
			u.APIResponse(ctx, http.StatusBadRequest, "error",
				"Host identifier must use HTTPS protocol and be a valid URL", []types.ErrorData{{
					Field:   "HostIdentifier",
					Message: "Please provide a valid URL starting with https://",
				}})
			return
		}
	}

	// Capture currency availability update intent (no writes yet)
	var availabilityOp *struct {
		currencyCode string
		isAvailable  bool
	}
	if payload.Currency != "" {
		availabilityOp = &struct {
			currencyCode string
			isAvailable  bool
		}{payload.Currency, payload.IsAvailable}
	}

	// PHASE 1: Validate all tokens and prepare operations
	type TokenOperation struct {
		TokenPayload  types.ProviderOrderTokenPayload
		ProviderToken *ent.Token
		Currency      *ent.FiatCurrency
		Rate          decimal.Decimal
		IsUpdate      bool
		ExistingToken *ent.ProviderOrderToken
	}

	var tokenOperations []TokenOperation
	var validationErrors []types.ErrorData

	type FiatAccountOperation struct {
		Payload         types.FiatAccountPayload
		IsUpdate        bool
		ExistingAccount *ent.ProviderFiatAccount
	}

	var fiatAccountOps []FiatAccountOperation

	// Validate all tokens first
	for _, tokenPayload := range payload.Tokens {
		// Check if token is supported
		providerToken, err := storage.Client.Token.
			Query().
			Where(
				token.Symbol(tokenPayload.Symbol),
				token.HasNetworkWith(network.IdentifierEQ(tokenPayload.Network)),
				token.IsEnabledEQ(true),
			).
			Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				validationErrors = append(validationErrors, types.ErrorData{
					Field:   "Tokens",
					Message: fmt.Sprintf("Token not supported - %s on %s", tokenPayload.Symbol, tokenPayload.Network),
				})
			} else {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"Token": tokenPayload.Symbol,
				}).Errorf("Failed to check token support during update")
				u.APIResponse(
					ctx,
					http.StatusInternalServerError,
					"error", "Failed to update profile",
					nil,
				)
				return
			}
			continue
		}

		// Ensure rate is within allowed deviation from the market rate
		currency, err := storage.Client.FiatCurrency.Query().
			Where(
				fiatcurrency.IsEnabledEQ(true),
				fiatcurrency.CodeEQ(payload.Currency),
			).
			Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				validationErrors = append(validationErrors, types.ErrorData{
					Field:   "Currency",
					Message: "Currency not supported",
				})
			} else {
				logger.WithFields(logger.Fields{
					"Error":    fmt.Sprintf("%v", err),
					"Currency": payload.Currency,
				}).Errorf("Failed to fetch currency during update")
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
				return
			}
			continue
		}

		// Calculate rate from tokenPayload based on conversion type
		var rate decimal.Decimal
		if tokenPayload.ConversionRateType == providerordertoken.ConversionRateTypeFixed {
			rate = tokenPayload.FixedConversionRate
		} else {
			rate = currency.MarketRate.Add(tokenPayload.FloatingConversionRate)
		}

		// Validate rate deviation for floating rates
		if tokenPayload.ConversionRateType == providerordertoken.ConversionRateTypeFloating {
			percentDeviation := u.AbsPercentageDeviation(currency.MarketRate, rate)
			if percentDeviation.GreaterThan(orderConf.PercentDeviationFromMarketRate) {
				validationErrors = append(validationErrors, types.ErrorData{
					Field:   "Tokens",
					Message: fmt.Sprintf("Rate is too far from market rate for %s", tokenPayload.Symbol),
				})
				continue
			}
		}

		// Handle slippage validation
		if tokenPayload.RateSlippage.IsZero() {
			tokenPayload.RateSlippage = decimal.NewFromFloat(0)
		} else if tokenPayload.RateSlippage.LessThan(decimal.NewFromFloat(0.1)) {
			validationErrors = append(validationErrors, types.ErrorData{
				Field:   "Tokens",
				Message: fmt.Sprintf("Rate slippage cannot be less than 0.1%% for %s", tokenPayload.Symbol),
			})
			continue
		} else if rate.Mul(tokenPayload.RateSlippage.Div(decimal.NewFromFloat(100))).GreaterThan(currency.MarketRate.Mul(decimal.NewFromFloat(0.05))) {
			validationErrors = append(validationErrors, types.ErrorData{
				Field:   "Tokens",
				Message: fmt.Sprintf("Rate slippage is too high for %s", tokenPayload.Symbol),
			})
			continue
		}

		// Check if token already exists for provider
		existingToken, err := storage.Client.ProviderOrderToken.
			Query().
			Where(
				providerordertoken.HasTokenWith(token.IDEQ(providerToken.ID)),
				providerordertoken.HasProviderWith(providerprofile.IDEQ(provider.ID)),
				providerordertoken.HasCurrencyWith(fiatcurrency.IDEQ(currency.ID)),
				providerordertoken.NetworkEQ(tokenPayload.Network),
			).
			WithCurrency().
			Only(ctx)

		isUpdate := err == nil
		if err != nil && !ent.IsNotFound(err) {
			logger.WithFields(logger.Fields{
				"Error":    fmt.Sprintf("%v", err),
				"Token":    tokenPayload.Symbol,
				"Currency": payload.Currency,
			}).Errorf("Failed to query existing token during validation")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
			return
		}

		// If updating and changing network, ensure target network doesn't already exist
		if isUpdate && existingToken.Network != tokenPayload.Network {
			dup, derr := storage.Client.ProviderOrderToken.
				Query().
				Where(
					providerordertoken.HasTokenWith(token.IDEQ(providerToken.ID)),
					providerordertoken.HasProviderWith(providerprofile.IDEQ(provider.ID)),
					providerordertoken.HasCurrencyWith(fiatcurrency.IDEQ(currency.ID)),
					providerordertoken.NetworkEQ(tokenPayload.Network),
				).Exist(ctx)
			if derr != nil {
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
				return
			}
			if dup {
				validationErrors = append(validationErrors, types.ErrorData{
					Field:   "Tokens",
					Message: fmt.Sprintf("Token already configured on network %s for %s", tokenPayload.Network, tokenPayload.Symbol),
				})
				continue
			}
		}

		// If updating, preserve existing rate slippage if not provided
		if isUpdate && tokenPayload.RateSlippage.IsZero() && existingToken.RateSlippage.GreaterThan(decimal.NewFromFloat(0)) {
			tokenPayload.RateSlippage = existingToken.RateSlippage
		}

		tokenOperations = append(tokenOperations, TokenOperation{
			TokenPayload:  tokenPayload,
			ProviderToken: providerToken,
			Currency:      currency,
			Rate:          rate,
			IsUpdate:      isUpdate,
			ExistingToken: existingToken,
		})
	}

	// Validate all fiat accounts (same pattern as tokens)
	for _, fiatAccountPayload := range payload.FiatAccounts {
		// Validate institution exists
		institutionExists, err := storage.Client.Institution.
			Query().
			Where(institution.CodeEQ(fiatAccountPayload.Institution)).
			Exist(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":       fmt.Sprintf("%v", err),
				"Institution": fiatAccountPayload.Institution,
			}).Errorf("Failed to validate institution")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
			return
		}
		if !institutionExists {
			validationErrors = append(validationErrors, types.ErrorData{
				Field:   "FiatAccounts",
				Message: fmt.Sprintf("Institution %s is not supported", fiatAccountPayload.Institution),
			})
			continue
		}

		// Check if account already exists (upsert check)
		existingAccount, err := storage.Client.ProviderFiatAccount.
			Query().
			Where(
				providerfiataccount.AccountIdentifierEQ(fiatAccountPayload.AccountIdentifier),
				providerfiataccount.InstitutionEQ(fiatAccountPayload.Institution),
				providerfiataccount.HasProviderWith(providerprofile.IDEQ(provider.ID)),
			).
			Only(ctx)

		isUpdate := err == nil
		if err != nil && !ent.IsNotFound(err) {
			logger.WithFields(logger.Fields{
				"Error":             fmt.Sprintf("%v", err),
				"Institution":       fiatAccountPayload.Institution,
			}).Errorf("Failed to check for existing fiat account")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
			return
		}

		fiatAccountOps = append(fiatAccountOps, FiatAccountOperation{
			Payload:         fiatAccountPayload,
			IsUpdate:        isUpdate,
			ExistingAccount: existingAccount,
		})
	}

	// Return validation errors if any
	if len(validationErrors) > 0 {
		var mainMessage string
		if len(validationErrors) == 1 {
			mainMessage = validationErrors[0].Message
		} else {
			mainMessage = fmt.Sprintf("Validation failed: %d errors found", len(validationErrors))
		}
		u.APIResponse(ctx, http.StatusBadRequest, "error", mainMessage, validationErrors)
		return
	}

	// PHASE 2: Execute all operations in a single transaction
	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		logger.Errorf("Failed to start transaction: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
		return
	}
	defer func() { _ = tx.Rollback() }()

	// Handle currency availability updates within the transaction
	if availabilityOp != nil {
		curr, err := tx.FiatCurrency.Query().
			Where(fiatcurrency.CodeEQ(availabilityOp.currencyCode), fiatcurrency.IsEnabledEQ(true)).
			Only(ctx)
		if err != nil {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Currency not supported", nil)
			return
		}

		pc, err := tx.ProviderCurrencies.Query().
			Where(providercurrencies.HasProviderWith(providerprofile.IDEQ(provider.ID)),
				providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(availabilityOp.currencyCode))).
			Only(ctx)
		if ent.IsNotFound(err) {
			_, err = tx.ProviderCurrencies.Create().
				SetProvider(provider).
				SetCurrency(curr).
				SetAvailableBalance(decimal.Zero).
				SetTotalBalance(decimal.Zero).
				SetReservedBalance(decimal.Zero).
				SetIsAvailable(availabilityOp.isAvailable).
				Save(ctx)
		} else if err == nil {
			_, err = pc.Update().SetIsAvailable(availabilityOp.isAvailable).Save(ctx)
		}
		if err != nil {
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update availability", nil)
			return
		}
	}

	// Update provider profile within the same transaction
	txUpdate := tx.ProviderProfile.Update().Where(providerprofile.IDEQ(provider.ID))

	// Set basic profile fields within the transaction
	if payload.TradingName != "" {
		txUpdate.SetTradingName(payload.TradingName)
	}

	if payload.HostIdentifier != "" {
		txUpdate.SetHostIdentifier(payload.HostIdentifier)
	}

	if payload.VisibilityMode != "" {
		txUpdate.SetVisibilityMode(providerprofile.VisibilityMode(payload.VisibilityMode))
	}

	var allBuckets []*ent.ProvisionBucket

	// Process all token operations
	for _, op := range tokenOperations {

		if op.IsUpdate {
			// Update existing token using transaction-bound client
			_, err := tx.ProviderOrderToken.
				UpdateOneID(op.ExistingToken.ID).
				SetAddress(op.TokenPayload.Address).
				SetNetwork(op.TokenPayload.Network).
				SetRateSlippage(op.TokenPayload.RateSlippage).
				SetConversionRateType(op.TokenPayload.ConversionRateType).
				SetFixedConversionRate(op.TokenPayload.FixedConversionRate).
				SetFloatingConversionRate(op.TokenPayload.FloatingConversionRate).
				SetMaxOrderAmount(op.TokenPayload.MaxOrderAmount).
				SetMinOrderAmount(op.TokenPayload.MinOrderAmount).
				SetMaxOrderAmountOtc(op.TokenPayload.MaxOrderAmountOTC).
				SetMinOrderAmountOtc(op.TokenPayload.MinOrderAmountOTC).
				Save(ctx)
			if err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					logger.Errorf("Failed to rollback transaction: %v", rollbackErr)
				}
				logger.WithFields(logger.Fields{
					"Error":    fmt.Sprintf("%v", err),
					"Token":    op.TokenPayload.Symbol,
					"Currency": payload.Currency,
				}).Errorf("Failed to update token during update")
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
				return
			}
		} else {
			// Create new token
			_, err = tx.ProviderOrderToken.
				Create().
				SetConversionRateType(op.TokenPayload.ConversionRateType).
				SetFixedConversionRate(op.TokenPayload.FixedConversionRate).
				SetFloatingConversionRate(op.TokenPayload.FloatingConversionRate).
				SetMaxOrderAmount(op.TokenPayload.MaxOrderAmount).
				SetMinOrderAmount(op.TokenPayload.MinOrderAmount).
				SetMaxOrderAmountOtc(op.TokenPayload.MaxOrderAmountOTC).
				SetMinOrderAmountOtc(op.TokenPayload.MinOrderAmountOTC).
				SetAddress(op.TokenPayload.Address).
				SetNetwork(op.TokenPayload.Network).
				SetProviderID(provider.ID).
				SetRateSlippage(op.TokenPayload.RateSlippage).
				SetTokenID(op.ProviderToken.ID).
				SetCurrencyID(op.Currency.ID).
				Save(ctx)
			if err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					logger.Errorf("Failed to rollback transaction: %v", rollbackErr)
				}
				logger.WithFields(logger.Fields{
					"Error":    fmt.Sprintf("%v", err),
					"Token":    op.TokenPayload.Symbol,
					"Currency": payload.Currency,
				}).Errorf("Failed to create token during update")
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
				return
			}
		}

		// Collect buckets for this token
		convertedMin := op.TokenPayload.MinOrderAmount.Mul(op.Rate)
		convertedMax := op.TokenPayload.MaxOrderAmount.Mul(op.Rate)

		buckets, err := tx.ProvisionBucket.
			Query().
			Where(
				provisionbucket.And(
					provisionbucket.MinAmountLTE(convertedMax), // providerMin ≤ bucketMax
					provisionbucket.MaxAmountGTE(convertedMin), // providerMax ≥ bucketMin
				),
			).
			All(ctx)
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				logger.Errorf("Failed to rollback transaction: %v", rollbackErr)
			}
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"ProviderID": provider.ID,
				"MinAmount":  op.TokenPayload.MinOrderAmount,
				"MaxAmount":  op.TokenPayload.MaxOrderAmount,
			}).Errorf("Failed to assign provider to buckets")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
			return
		}
		allBuckets = append(allBuckets, buckets...)
	}

	// Process all fiat account operations (same pattern as tokens)
	for _, op := range fiatAccountOps {
		if op.IsUpdate {
			// Update existing account
			_, err := tx.ProviderFiatAccount.
				UpdateOneID(op.ExistingAccount.ID).
				SetAccountIdentifier(op.Payload.AccountIdentifier).
				SetAccountName(op.Payload.AccountName).
				SetInstitution(op.Payload.Institution).
				Save(ctx)
			if err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					logger.Errorf("Failed to rollback transaction: %v", rollbackErr)
				}
				logger.WithFields(logger.Fields{
					"Error":             fmt.Sprintf("%v", err),
					"Institution":       op.Payload.Institution,
				}).Errorf("Failed to update fiat account")
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
				return
			}
		} else {
			// Create new account
			_, err := tx.ProviderFiatAccount.
				Create().
				SetAccountIdentifier(op.Payload.AccountIdentifier).
				SetAccountName(op.Payload.AccountName).
				SetInstitution(op.Payload.Institution).
				SetProviderID(provider.ID).
				Save(ctx)
			if err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					logger.Errorf("Failed to rollback transaction: %v", rollbackErr)
				}
				logger.WithFields(logger.Fields{
					"Error":             fmt.Sprintf("%v", err),
					"Institution":       op.Payload.Institution,
				}).Errorf("Failed to create fiat account")
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
				return
			}
		}
	}

	// Deduplicate buckets to prevent duplicate many-to-many edges
	seenBuckets := make(map[int]bool)
	var dedupedBuckets []*ent.ProvisionBucket
	for _, bucket := range allBuckets {
		if !seenBuckets[bucket.ID] {
			seenBuckets[bucket.ID] = true
			dedupedBuckets = append(dedupedBuckets, bucket)
		}
	}

	// Update provider profile with deduplicated buckets
	if len(dedupedBuckets) > 0 {
		txUpdate.ClearProvisionBuckets()
		txUpdate.AddProvisionBuckets(dedupedBuckets...)
	}

	// Save provider profile update within the transaction
	_, err = txUpdate.Save(ctx)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Errorf("Failed to rollback transaction: %v", rollbackErr)
		}
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": provider.ID,
		}).Errorf("Failed to commit update of provider profile")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
		return
	}

	// Commit all changes
	if err := tx.Commit(); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Errorf("Failed to rollback transaction: %v", rollbackErr)
		}
		logger.Errorf("Failed to commit transaction: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Profile updated successfully", nil)
}

// GetSenderProfile retrieves the sender profile
func (ctrl *ProfileController) GetSenderProfile(ctx *gin.Context) {
	// Get sender profile from the context
	senderCtx, ok := ctx.Get("sender")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	sender := senderCtx.(*ent.SenderProfile)

	user, err := sender.QueryUser().Only(ctx)
	if err != nil {
		logger.Errorf("Error: Failed to fetch sender profile for user %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to retrieve profile", nil)
		return
	}

	// Get API key
	apiKey, err := ctrl.apiKeyService.GetAPIKey(ctx, sender, nil)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"SenderID": sender.ID,
		}).Errorf("Failed to fetch sender API key")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to retrieve profile", nil)
		return
	}

	senderToken, err := storage.Client.SenderOrderToken.
		Query().
		Where(senderordertoken.HasSenderWith(senderprofile.IDEQ(sender.ID))).
		WithToken(
			func(tq *ent.TokenQuery) {
				tq.WithNetwork()
			},
		).
		All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"SenderID": sender.ID,
		}).Errorf("Failed to fetch sender order tokens")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to retrieve profile", nil)
		return
	}

	tokensPayload := make([]types.SenderOrderTokenResponse, len(senderToken))
	for i, token := range senderToken {
		payload := types.SenderOrderTokenResponse{
			Symbol:        token.Edges.Token.Symbol,
			RefundAddress: token.RefundAddress,
			FeePercent:    token.FeePercent,
			MaxFeeCap:     token.MaxFeeCap,
			FeeAddress:    token.FeeAddress,
			Network:       token.Edges.Token.Edges.Network.Identifier,
		}

		tokensPayload[i] = payload
	}

	// Fetch KYB profile to get rejection comment if available
	var kybRejectionComment *string
	kybProfile, err := storage.Client.KYBProfile.
		Query().
		Where(kybprofile.HasUserWith(userkyb.IDEQ(user.ID))).
		Only(ctx)

	if err == nil && kybProfile != nil && kybProfile.KybRejectionComment != nil {
		kybRejectionComment = kybProfile.KybRejectionComment
	}

	response := &types.SenderProfileResponse{
		ID:                    sender.ID,
		FirstName:             user.FirstName,
		LastName:              user.LastName,
		Email:                 user.Email,
		WebhookURL:            sender.WebhookURL,
		DomainWhitelist:       sender.DomainWhitelist,
		Tokens:                tokensPayload,
		APIKey:                *apiKey,
		IsActive:              sender.IsActive,
		KYBVerificationStatus: user.KybVerificationStatus,
		KYBRejectionComment:   kybRejectionComment,
	}

	linkedProvider, err := storage.Client.ProviderProfile.
		Query().
		Where(providerprofile.IDEQ(sender.ProviderID)).
		WithProviderCurrencies(
			func(query *ent.ProviderCurrenciesQuery) {
				query.WithCurrency()
			},
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			// do nothing
		} else {
			logger.WithFields(logger.Fields{
				"Error":    fmt.Sprintf("%v", err),
				"SenderID": sender.ID,
			}).Errorf("Failed to fetch linked providerf for sender")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to retrieve profile", nil)
			return
		}
	}

	if linkedProvider != nil {
		response.ProviderID = sender.ProviderID
		// Extract currency codes from linked provider
		currencyCodes := make([]string, len(linkedProvider.Edges.ProviderCurrencies))
		for i, pc := range linkedProvider.Edges.ProviderCurrencies {
			currencyCodes[i] = pc.Edges.Currency.Code
		}
		response.ProviderCurrencies = currencyCodes
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Profile retrieved successfully", response)
}

// GetProviderProfile retrieves the provider profile
func (ctrl *ProfileController) GetProviderProfile(ctx *gin.Context) {
	// Get provider profile from the context
	providerCtx, ok := ctx.Get("provider")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	provider := providerCtx.(*ent.ProviderProfile)

	user, err := provider.QueryUser().Only(ctx)
	if err != nil {
		logger.Errorf("Error: Failed to fetch provider profile for user %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to retrieve profile", nil)
		return
	}

	// Get currencies through ProviderCurrencies
	providerCurrencies, err := provider.QueryProviderCurrencies().
		WithCurrency(func(fcq *ent.FiatCurrencyQuery) {
			fcq.Where(fiatcurrency.IsEnabledEQ(true))
		}).
		All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": provider.ID,
		}).Errorf("Failed to fetch currencies for provider")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to retrieve profile", nil)
		return
	}

	// Provider profile should also return all the currencies associated with the provider
	currencyCodes := make([]string, len(providerCurrencies))
	currencyAvailability := make(map[string]bool)
	for i, pc := range providerCurrencies {
		currencyCodes[i] = pc.Edges.Currency.Code
		currencyAvailability[pc.Edges.Currency.Code] = pc.IsAvailable
	}

	// Get token settings, optionally filtering by currency query parameter
	currencyFilter := ctx.Query("currency")
	query := provider.QueryOrderTokens().
		Where(providerordertoken.HasTokenWith(token.IsEnabledEQ(true))).
		WithToken().
		WithCurrency()
	if currencyFilter != "" {
		query = query.Where(providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(currencyFilter)))
	}
	orderTokens, err := query.All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": provider.ID,
		}).Errorf("Failed to fetch order tokens for provider")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to retrieve profile", nil)
		return
	}

	fiatAccounts, err := provider.QueryFiatAccounts().
		Order(ent.Desc(providerfiataccount.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": provider.ID,
		}).Errorf("Failed to fetch fiat accounts for provider")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to retrieve profile", nil)
		return
	}

	fiatAccountsPayload := make([]types.FiatAccountResponse, len(fiatAccounts))
	for i, account := range fiatAccounts {
		fiatAccountsPayload[i] = types.FiatAccountResponse{
			ID:                account.ID,
			AccountIdentifier: account.AccountIdentifier,
			AccountName:       account.AccountName,
			Institution:       account.Institution,
			CreatedAt:         account.CreatedAt,
			UpdatedAt:         account.UpdatedAt,
		}
	}

	tokensPayload := make([]types.ProviderOrderTokenPayload, len(orderTokens))
	for i, orderToken := range orderTokens {
		payload := types.ProviderOrderTokenPayload{
			Symbol:                 orderToken.Edges.Token.Symbol,
			ConversionRateType:     orderToken.ConversionRateType,
			FixedConversionRate:    orderToken.FixedConversionRate,
			FloatingConversionRate: orderToken.FloatingConversionRate,
			MaxOrderAmount:         orderToken.MaxOrderAmount,
			MinOrderAmount:         orderToken.MinOrderAmount,
			MaxOrderAmountOTC:      orderToken.MaxOrderAmountOtc,
			MinOrderAmountOTC:      orderToken.MinOrderAmountOtc,
			RateSlippage:           orderToken.RateSlippage,
			Address:                orderToken.Address,
			Network:                orderToken.Network,
		}
		tokensPayload[i] = payload
	}

	// Fetch KYB profile to get rejection comment if available
	var kybRejectionComment *string
	kybProfile, err := storage.Client.KYBProfile.
		Query().
		Where(kybprofile.HasUserWith(userkyb.IDEQ(user.ID))).
		Only(ctx)

	if err == nil && kybProfile != nil && kybProfile.KybRejectionComment != nil {
		kybRejectionComment = kybProfile.KybRejectionComment
	}

	// Get API key
	apiKey, err := ctrl.apiKeyService.GetAPIKey(ctx, nil, provider)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": provider.ID,
		}).Errorf("Failed to fetch provider API key")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to retrieve profile", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Profile retrieved successfully", &types.ProviderProfileResponse{
		ID:                    provider.ID,
		FirstName:             user.FirstName,
		LastName:              user.LastName,
		Email:                 user.Email,
		TradingName:           provider.TradingName,
		Currencies:            currencyCodes,
		HostIdentifier:        provider.HostIdentifier,
		CurrencyAvailability:  currencyAvailability,
		Tokens:                tokensPayload,
		FiatAccounts:          fiatAccountsPayload,
		APIKey:                *apiKey,
		IsActive:              provider.IsActive,
		VisibilityMode:        provider.VisibilityMode,
		KYBVerificationStatus: user.KybVerificationStatus,
		KYBRejectionComment:   kybRejectionComment,
	})
}
