package accounts

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/provisionbucket"
	"github.com/paycrest/aggregator/ent/senderordertoken"
	"github.com/paycrest/aggregator/ent/senderprofile"
	"github.com/paycrest/aggregator/ent/token"
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

	update := sender.Update()

	if payload.WebhookURL != "" || (payload.WebhookURL == "" && sender.WebhookURL != "") {
		update.SetWebhookURL(payload.WebhookURL)
	}

	if payload.DomainWhitelist != nil || (payload.DomainWhitelist == nil && sender.DomainWhitelist != nil) {
		update.SetDomainWhitelist(payload.DomainWhitelist)
	}

	// save or update SenderOrderToken
	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
		return
	}

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
					u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
						Field:   "FeeAddress",
						Message: "Invalid Tron address",
					})
					return
				}
				networksToTokenId[address.Network] = 0
			} else {
				feeAddressIsValid := u.IsValidEthereumAddress(address.FeeAddress)
				if address.FeeAddress != "" && !feeAddressIsValid {
					u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
						Field:   "FeeAddress",
						Message: "Invalid Ethereum address",
					})
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

		for _, address := range tokenPayload.Addresses {
			senderToken, err := tx.SenderOrderToken.
				Query().
				Where(
					senderordertoken.And(
						senderordertoken.HasTokenWith(token.IDEQ(networksToTokenId[address.Network])),
						senderordertoken.HasSenderWith(senderprofile.IDEQ(sender.ID)),
					),
				).
				Only(ctx)
			if err != nil {
				if ent.IsNotFound(err) {
					_, err := tx.SenderOrderToken.
						Create().
						SetSenderID(sender.ID).
						SetTokenID(networksToTokenId[address.Network]).
						SetRefundAddress(address.RefundAddress).
						SetFeePercent(tokenPayload.FeePercent).
						SetFeeAddress(address.FeeAddress).
						Save(ctx)
					if err != nil {
						u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
						return
					}
				} else {
					u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
					return
				}

			} else {
				_, err := senderToken.
					Update().
					SetRefundAddress(address.RefundAddress).
					SetFeePercent(tokenPayload.FeePercent).
					SetFeeAddress(address.FeeAddress).
					Save(ctx)
				if err != nil {
					u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
					return
				}
			}
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
		return
	}

	if !sender.IsActive {
		update.SetIsActive(true)
	}

	_, err = update.Save(ctx)
	if err != nil {
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

	update := provider.Update()

	if payload.TradingName != "" {
		update.SetTradingName(payload.TradingName)
	}

	if payload.HostIdentifier != "" {
		// Validate HTTPS protocol
		if !u.IsValidHttpsUrl(payload.HostIdentifier) {
			u.APIResponse(ctx, http.StatusBadRequest, "error",
				"Host identifier must use HTTPS protocol and be a valid URL", types.ErrorData{
					Field:   "HostIdentifier",
					Message: "Please provide a valid URL starting with https://",
				})
			return
		}
		update.SetHostIdentifier(payload.HostIdentifier)
	}

	if payload.IsAvailable {
		update.SetIsAvailable(true)
	} else {
		update.SetIsAvailable(false)
	}

	if len(payload.Currencies) > 0 {
		newCurrencies, err := storage.Client.FiatCurrency.Query().
			Where(
				fiatcurrency.And(
					fiatcurrency.IsEnabledEQ(true),
					fiatcurrency.CodeIn(payload.Currencies...),
				),
			).
			All(ctx)
		if err != nil {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "FiatCurrency",
				Message: "This field is required",
			})
			return
		}

		// Fetch the existing currencies associated with the provider profile
		existingCurrencies, err := storage.Client.ProviderProfile.
			Query().
			Where(providerprofile.IDEQ(provider.ID)).
			QueryCurrencies().
			All(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"ProviderID": provider.ID,
			}).Errorf("Failed to fetch existing currencies for provider")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch existing currencies", nil)
			return
		}

		// Combine existing and new currencies
		allCurrencies := append(existingCurrencies, newCurrencies...)

		// will be set currencies
		update.AddCurrencies(allCurrencies...)
	}

	if payload.VisibilityMode != "" {
		update.SetVisibilityMode(providerprofile.VisibilityMode(payload.VisibilityMode))
	}

	// Update tokens
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
				u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("Token not supported - %s", tokenPayload.Symbol), nil)
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
			}
			return
		}

		// Ensure rate is within allowed deviation from the market rate
		currency, err := storage.Client.FiatCurrency.Query().
			Where(
				fiatcurrency.IsEnabledEQ(true),
				fiatcurrency.CodeEQ(tokenPayload.Currency),
			).
			Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Currency not supported", nil)
			} else {
				logger.WithFields(logger.Fields{
					"Error":    fmt.Sprintf("%v", err),
					"Currency": tokenPayload.Currency,
				}).Errorf("Failed to fetch currency during update")
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
			}
			return
		}

		if tokenPayload.ConversionRateType == providerordertoken.ConversionRateTypeFloating {
			rate := currency.MarketRate.Add(tokenPayload.FloatingConversionRate)

			percentDeviation := u.AbsPercentageDeviation(currency.MarketRate, rate)
			if percentDeviation.GreaterThan(orderConf.PercentDeviationFromMarketRate) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Rate is too far from market rate", nil)
				return
			}
		}

		// Calculate rate from tokenPayload based on conversion type
		var rate decimal.Decimal
		if tokenPayload.ConversionRateType == providerordertoken.ConversionRateTypeFixed {
			rate = tokenPayload.FixedConversionRate
		} else {
			rate = currency.MarketRate.Add(tokenPayload.FloatingConversionRate)
		}

		// See if token already exists for provider
		tx, err := storage.Client.Tx(ctx)
		if err != nil {
			logger.Errorf("Failed to start transaction: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
			return
		}

		// Handle slippage validation and default value
		if tokenPayload.RateSlippage.IsZero() {
			// Set default slippage to 0% if not provided
			tokenPayload.RateSlippage = decimal.NewFromFloat(0)
		} else if tokenPayload.RateSlippage.LessThan(decimal.NewFromFloat(0.1)) {
			if err := tx.Rollback(); err != nil {
				logger.Errorf("Failed to rollback transaction: %v", err)
			}
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Rate slippage cannot be less than 0.1%", nil)
			return
		} else if rate.Mul(tokenPayload.RateSlippage.Div(decimal.NewFromFloat(100))).GreaterThan(currency.MarketRate.Mul(decimal.NewFromFloat(0.05))) {
			if err := tx.Rollback(); err != nil {
				logger.Errorf("Failed to rollback transaction: %v", err)
			}
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Rate slippage is too high", nil)
			return
		}

		orderToken, err := tx.ProviderOrderToken.
			Query().
			Where(
				providerordertoken.HasTokenWith(token.IDEQ(providerToken.ID)),
				providerordertoken.HasProviderWith(providerprofile.IDEQ(provider.ID)),
				providerordertoken.HasCurrencyWith(fiatcurrency.IDEQ(currency.ID)),
				providerordertoken.NetworkEQ(tokenPayload.Network),
			).
			WithCurrency().
			Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				// Token doesn't exist, create it
				_, err = tx.ProviderOrderToken.
					Create().
					SetConversionRateType(tokenPayload.ConversionRateType).
					SetFixedConversionRate(tokenPayload.FixedConversionRate).
					SetFloatingConversionRate(tokenPayload.FloatingConversionRate).
					SetMaxOrderAmount(tokenPayload.MaxOrderAmount).
					SetMinOrderAmount(tokenPayload.MinOrderAmount).
					SetAddress(tokenPayload.Address).
					SetNetwork(tokenPayload.Network).
					SetProviderID(provider.ID).
					SetRateSlippage(tokenPayload.RateSlippage).
					SetTokenID(providerToken.ID).
					SetCurrencyID(currency.ID).
					Save(ctx)
				if err != nil {
					if err := tx.Rollback(); err != nil {
						logger.Errorf("Failed to rollback transaction: %v", err)
					}
					logger.WithFields(logger.Fields{
						"Error":    fmt.Sprintf("%v", err),
						"Token":    tokenPayload.Symbol,
						"Currency": tokenPayload.Currency,
					}).Errorf("Failed to create token during update")
					u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
					return
				}
			} else {
				if err := tx.Rollback(); err != nil {
					logger.Errorf("Failed to rollback transaction: %v", err)
				}
				logger.WithFields(logger.Fields{
					"Error":    fmt.Sprintf("%v", err),
					"Token":    tokenPayload.Symbol,
					"Currency": tokenPayload.Currency,
				}).Errorf("Failed to query token during update")
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
				return
			}
		} else {
			// TODO: Remove when dashboard allows rate slippage to be set
			if tokenPayload.RateSlippage.IsZero() && orderToken.RateSlippage.GreaterThan(decimal.NewFromFloat(0)) {
				tokenPayload.RateSlippage = orderToken.RateSlippage
			}

			// Token exists, update it
			_, err := orderToken.Update().
				SetAddress(tokenPayload.Address).
				SetNetwork(tokenPayload.Network).
				SetRateSlippage(tokenPayload.RateSlippage).
				SetConversionRateType(tokenPayload.ConversionRateType).
				SetFixedConversionRate(tokenPayload.FixedConversionRate).
				SetFloatingConversionRate(tokenPayload.FloatingConversionRate).
				SetMaxOrderAmount(tokenPayload.MaxOrderAmount).
				SetMinOrderAmount(tokenPayload.MinOrderAmount).
				Save(ctx)
			if err != nil {
				if err := tx.Rollback(); err != nil {
					logger.Errorf("Failed to rollback transaction: %v", err)
				}
				logger.WithFields(logger.Fields{
					"Error":    fmt.Sprintf("%v", err),
					"Token":    tokenPayload.Symbol,
					"Currency": tokenPayload.Currency,
				}).Errorf("Failed to update token during update")
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
				return
			}
		}

		if err := tx.Commit(); err != nil {
			if err := tx.Rollback(); err != nil {
				logger.Errorf("Failed to rollback transaction: %v", err)
			}
			logger.Errorf("Failed to commit transaction: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update profile", nil)
			return
		}

		// Add provider to buckets
		buckets, err := storage.Client.ProvisionBucket.
			Query().
			Where(
				provisionbucket.Or(
					provisionbucket.MinAmountLTE(tokenPayload.MinOrderAmount.Mul(rate)),
					provisionbucket.MinAmountLTE(tokenPayload.MaxOrderAmount.Mul(rate)),
					provisionbucket.MaxAmountGTE(tokenPayload.MaxOrderAmount.Mul(rate)),
				),
			).
			All(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"ProviderID": provider.ID,
				"MinAmount":  tokenPayload.MinOrderAmount,
				"MaxAmount":  tokenPayload.MaxOrderAmount,
			}).Errorf("Failed to assign provider to buckets")
		} else {
			update.ClearProvisionBuckets()
			update.AddProvisionBuckets(buckets...)
		}
	}

	_, err := update.Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": provider.ID,
		}).Errorf("Failed to commit update of provider profile")
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

	tokensPayload := make([]types.SenderOrderTokenResponse, len(sender.Edges.OrderTokens))
	for i, token := range senderToken {
		payload := types.SenderOrderTokenResponse{
			Symbol:        token.Edges.Token.Symbol,
			RefundAddress: token.RefundAddress,
			FeePercent:    token.FeePercent,
			FeeAddress:    token.FeeAddress,
			Network:       token.Edges.Token.Edges.Network.Identifier,
		}

		tokensPayload[i] = payload
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
	}

	linkedProvider, err := storage.Client.ProviderProfile.
		Query().
		Where(providerprofile.IDEQ(sender.ProviderID)).
		WithCurrencies().
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
		currencyCodes := make([]string, len(linkedProvider.Edges.Currencies))
		for i, currency := range linkedProvider.Edges.Currencies {
			currencyCodes[i] = currency.Code
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

	// Get currencies
	currencies, err := provider.QueryCurrencies().All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": provider.ID,
		}).Errorf("Failed to fetch currencies for provider")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to retrieve profile", nil)
		return
	}

	// Provider profile should also return all the currencies associated with the provider
	currencyCodes := make([]string, len(currencies))
	for i, currency := range currencies {
		currencyCodes[i] = currency.Code
	}

	// Get token settings, optionally filtering by currency query parameter
	currencyFilter := ctx.Query("currency")
	query := provider.QueryOrderTokens().WithToken().WithCurrency()
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

	tokensPayload := make([]types.ProviderOrderTokenPayload, len(orderTokens))
	for i, orderToken := range orderTokens {
		payload := types.ProviderOrderTokenPayload{
			Currency:               orderToken.Edges.Currency.Code,
			Symbol:                 orderToken.Edges.Token.Symbol,
			ConversionRateType:     orderToken.ConversionRateType,
			FixedConversionRate:    orderToken.FixedConversionRate,
			FloatingConversionRate: orderToken.FloatingConversionRate,
			MaxOrderAmount:         orderToken.MaxOrderAmount,
			MinOrderAmount:         orderToken.MinOrderAmount,
			RateSlippage:           orderToken.RateSlippage,
			Address:                orderToken.Address,
			Network:                orderToken.Network,
		}
		tokensPayload[i] = payload
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
		IsAvailable:           provider.IsAvailable,
		Tokens:                tokensPayload,
		APIKey:                *apiKey,
		IsActive:              provider.IsActive,
		KYBVerificationStatus: user.KybVerificationStatus,
	})
}
