package controllers

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/linkedaddress"
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	tokenEnt "github.com/paycrest/aggregator/ent/token"
	svc "github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/indexer"
	kycErrors "github.com/paycrest/aggregator/services/kyc/errors"
	"github.com/paycrest/aggregator/services/kyc/smile"
	orderSvc "github.com/paycrest/aggregator/services/order"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	u "github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
)

var cryptoConf = config.CryptoConfig()

var serverConf = config.ServerConfig()
var identityConf = config.IdentityConfig()

// Controller is the default controller for other endpoints
type Controller struct {
	orderService          types.OrderService
	priorityQueueService  *svc.PriorityQueueService
	receiveAddressService *svc.ReceiveAddressService
	kycService            types.KYCProvider
}

// NewController creates a new instance of AuthController with injected services
func NewController() *Controller {
	return &Controller{
		orderService:          orderSvc.NewOrderEVM(),
		priorityQueueService:  svc.NewPriorityQueueService(),
		receiveAddressService: svc.NewReceiveAddressService(),
		kycService:            smile.NewSmileIDService(),
	}
}

// GetFiatCurrencies controller fetches the supported fiat currencies
func (ctrl *Controller) GetFiatCurrencies(ctx *gin.Context) {
	// fetch stored fiat currencies.
	fiatcurrencies, err := storage.Client.FiatCurrency.
		Query().
		Where(fiatcurrency.IsEnabledEQ(true)).
		All(ctx)
	if err != nil {
		logger.Errorf("Error: Failed to fetch fiat currencies: %v", err)

		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to fetch FiatCurrencies", fmt.Sprintf("%v", err))
		return
	}

	currencies := make([]types.SupportedCurrencies, 0, len(fiatcurrencies))
	for _, currency := range fiatcurrencies {
		currencies = append(currencies, types.SupportedCurrencies{
			Code:       currency.Code,
			Name:       currency.Name,
			ShortName:  currency.ShortName,
			Decimals:   int8(currency.Decimals),
			Symbol:     currency.Symbol,
			MarketRate: currency.MarketRate,
		})
	}

	u.APIResponse(ctx, http.StatusOK, "success", "OK", currencies)
}

// GetInstitutionsByCurrency controller fetches the supported institutions for a given currency
func (ctrl *Controller) GetInstitutionsByCurrency(ctx *gin.Context) {
	// Get currency code from the URL
	currencyCode := ctx.Param("currency_code")

	institutions, err := storage.Client.Institution.
		Query().
		Where(institution.HasFiatCurrencyWith(
			fiatcurrency.CodeEQ(strings.ToUpper(currencyCode)),
		)).
		All(ctx)
	if err != nil {
		logger.Errorf("Error: Failed to fetch institutions: %v", err)
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to fetch institutions", nil)
		return
	}

	response := make([]types.SupportedInstitutions, 0, len(institutions))
	for _, institution := range institutions {
		response = append(response, types.SupportedInstitutions{
			Code: institution.Code,
			Name: institution.Name,
			Type: institution.Type,
		})
	}

	u.APIResponse(ctx, http.StatusOK, "success", "OK", response)
}

// GetTokenRate controller fetches the current rate of the cryptocurrency token against the fiat currency
func (ctrl *Controller) GetTokenRate(ctx *gin.Context) {
	// Parse path parameters
	tokenSymbol := strings.ToUpper(ctx.Param("token"))
	networkFilter := ctx.Query("network")

	// Build token query
	tokenQuery := storage.Client.Token.
		Query().
		Where(
			tokenEnt.SymbolEQ(tokenSymbol),
			tokenEnt.IsEnabledEQ(true),
		)

	// Apply network filter if provided
	if networkFilter != "" {
		tokenQuery = tokenQuery.Where(tokenEnt.HasNetworkWith(
			networkent.Identifier(strings.ToLower(networkFilter)),
		))
	}

	token, err := tokenQuery.First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			errorMsg := fmt.Sprintf("Token %s is not supported", tokenSymbol)
			if networkFilter != "" {
				errorMsg = fmt.Sprintf("Token %s is not supported on network %s", tokenSymbol, networkFilter)
			}
			u.APIResponse(ctx, http.StatusBadRequest, "error", errorMsg, nil)
			return
		}
		logger.Errorf("Error: Failed to fetch token rate: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch token rate", nil)
		return
	}

	currency, err := storage.Client.FiatCurrency.
		Query().
		Where(
			fiatcurrency.IsEnabledEQ(true),
			fiatcurrency.CodeEQ(strings.ToUpper(ctx.Param("fiat"))),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("Fiat currency %s is not supported", strings.ToUpper(ctx.Param("fiat"))), nil)
			return
		}
		logger.Errorf("Error: Failed to fetch token rate: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch token rate", nil)
		return
	}

	if !strings.EqualFold(token.BaseCurrency, currency.Code) && !strings.EqualFold(token.BaseCurrency, "USD") {
		u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("%s can only be converted to %s", token.Symbol, token.BaseCurrency), nil)
		return
	}

	tokenAmount, err := decimal.NewFromString(ctx.Param("amount"))
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid amount", nil)
		return
	}

	// Resolve rate using extracted logic
	rateResponse, err := ctrl.resolveRate(ctx, token, currency, tokenAmount, ctx.Query("provider_id"), networkFilter)
	if err != nil {
		// Error response is handled within resolveRate methods
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Rate fetched successfully", rateResponse)
}

// resolveRate handles the rate resolution logic based on different scenarios
func (ctrl *Controller) resolveRate(ctx *gin.Context, token *ent.Token, currency *ent.FiatCurrency, amount decimal.Decimal, providerID, networkFilter string) (decimal.Decimal, error) {
	// Direct currency match
	if strings.EqualFold(token.BaseCurrency, currency.Code) {
		return decimal.NewFromInt(1), nil
	}

	// Provider-specific rate
	if providerID != "" {
		return ctrl.resolveProviderRate(ctx, token, currency, amount, providerID, networkFilter)
	}

	// Bucket-based rate resolution
	return ctrl.resolveBucketRate(ctx, token, currency, amount, networkFilter)
}

// resolveProviderRate handles provider-specific rate resolution
func (ctrl *Controller) resolveProviderRate(ctx *gin.Context, token *ent.Token, currency *ent.FiatCurrency, amount decimal.Decimal, providerID, networkFilter string) (decimal.Decimal, error) {
	// Get the provider from the database
	provider, err := storage.Client.ProviderProfile.
		Query().
		Where(providerprofile.IDEQ(providerID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Provider not found", nil)
			return decimal.Zero, err
		}
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch provider profile", nil)
		return decimal.Zero, err
	}

	// Get the provider's order token configuration to validate min/max amounts
	providerOrderTokenQuery := storage.Client.ProviderOrderToken.
		Query().
		Where(
			providerordertoken.HasProviderWith(providerprofile.IDEQ(provider.ID)),
			providerordertoken.HasTokenWith(tokenEnt.IDEQ(token.ID)),
			providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(currency.Code)),
		)

	// Filter by network if provided
	if networkFilter != "" {
		providerOrderTokenQuery = providerOrderTokenQuery.Where(
			providerordertoken.NetworkEQ(networkFilter),
		)
	}

	providerOrderToken, err := providerOrderTokenQuery.First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Provider does not support this token/currency combination", nil)
			return decimal.Zero, err
		}
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch provider configuration", nil)
		return decimal.Zero, err
	}

	// Validate that the token amount is within the provider's min/max limits
	if amount.LessThan(providerOrderToken.MinOrderAmount) || amount.GreaterThan(providerOrderToken.MaxOrderAmount) {
		u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("Amount must be between %s and %s for this provider", providerOrderToken.MinOrderAmount, providerOrderToken.MaxOrderAmount), nil)
		return decimal.Zero, fmt.Errorf("amount out of range")
	}

	// Get provider-specific rate
	rate, err := ctrl.priorityQueueService.GetProviderRate(ctx, provider, token.Symbol, currency.Code)
	if err != nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch provider rate", nil)
		return decimal.Zero, err
	}

	return rate, nil
}

// resolveBucketRate handles bucket-based rate resolution
func (ctrl *Controller) resolveBucketRate(ctx *gin.Context, token *ent.Token, currency *ent.FiatCurrency, amount decimal.Decimal, networkFilter string) (decimal.Decimal, error) {
	// Get redis keys for provision buckets
	keys, _, err := storage.RedisClient.Scan(ctx, uint64(0), "bucket_"+currency.Code+"_*_*", 100).Result()
	if err != nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch rates", nil)
		return decimal.Zero, err
	}

	// Track the best available rate and reason for logging
	var bestRate decimal.Decimal
	var bestRateReason string
	var foundExactMatch bool

	// Scan through the buckets to find a matching rate
	for _, key := range keys {
		bucketData, err := parseBucketKey(key)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Key":   key,
				"Error": err,
			}).Errorf("GetTokenRate.InvalidBucketKey: failed to parse bucket key")
			continue
		}

		// Get all providers in this bucket to find the first suitable one (priority queue order)
		providers, err := storage.RedisClient.LRange(ctx, key, 0, -1).Result()
		if err != nil {
			logger.WithFields(logger.Fields{
				"Key":   key,
				"Error": err,
			}).Errorf("GetTokenRate.FailedToGetProviders: failed to get providers from bucket")
			continue
		}

		// Find the first provider at the top of the queue that matches our criteria
		rate, found := ctrl.findSuitableProviderRate(providers, token.Symbol, amount, bucketData)
		if found {
			foundExactMatch = true
			bestRate = rate
			bestRateReason = fmt.Sprintf("exact match in bucket %s", key)
			break // Found exact match, no need to continue
		}

		// Track the best available rate for logging purposes
		if rate.GreaterThan(bestRate) {
			bestRate = rate
			bestRateReason = fmt.Sprintf("best available rate from bucket %s", key)
		}
	}

	// If no exact match found, return error with details
	if !foundExactMatch {
		logger.WithFields(logger.Fields{
			"Token":          token.Symbol,
			"Currency":       currency.Code,
			"Amount":         amount,
			"NetworkFilter":  networkFilter,
			"BestRate":       bestRate,
			"BestRateReason": bestRateReason,
		}).Warnf("GetTokenRate.NoSuitableProvider: no provider found for the given parameters")

		u.APIResponse(ctx, http.StatusNotFound, "error",
			fmt.Sprintf("No provider available for %s to %s conversion with amount %s",
				token.Symbol, currency.Code, amount), nil)
		return decimal.Zero, fmt.Errorf("no suitable provider found")
	}

	return bestRate, nil
}

// parseBucketKey parses and validates bucket key format
type BucketData struct {
	Currency  string
	MinAmount decimal.Decimal
	MaxAmount decimal.Decimal
}

func parseBucketKey(key string) (*BucketData, error) {
	// Expected format: "bucket_{currency}_{minAmount}_{maxAmount}"
	parts := strings.Split(key, "_")
	if len(parts) != 4 && len(parts) != 5 {
		return nil, fmt.Errorf("invalid bucket key format: expected 4 parts, got %d", len(parts))
	}

	if parts[0] != "bucket" {
		return nil, fmt.Errorf("invalid bucket key prefix: expected 'bucket', got '%s'", parts[0])
	}

	currency := parts[1]
	if currency == "" {
		return nil, fmt.Errorf("empty currency in bucket key")
	}

	minAmount, err := decimal.NewFromString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid min amount '%s': %v", parts[2], err)
	}

	maxAmount, err := decimal.NewFromString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid max amount '%s': %v", parts[3], err)
	}

	if minAmount.GreaterThanOrEqual(maxAmount) {
		return nil, fmt.Errorf("min amount (%s) must be less than max amount (%s)", minAmount, maxAmount)
	}

	return &BucketData{
		Currency:  currency,
		MinAmount: minAmount,
		MaxAmount: maxAmount,
	}, nil
}

// findSuitableProviderRate finds the first suitable provider rate from the provider list
func (ctrl *Controller) findSuitableProviderRate(providers []string, tokenSymbol string, tokenAmount decimal.Decimal, bucketData *BucketData) (decimal.Decimal, bool) {
	var bestRate decimal.Decimal
	var foundExactMatch bool

	for _, providerData := range providers {
		parts := strings.Split(providerData, ":")
		if len(parts) != 5 {
			logger.WithFields(logger.Fields{
				"ProviderData": providerData,
				"Token":        tokenSymbol,
				"Currency":     bucketData.Currency,
				"MinAmount":    bucketData.MinAmount,
				"MaxAmount":    bucketData.MaxAmount,
			}).Errorf("GetTokenRate.InvalidProviderData: provider data format is invalid")
			continue
		}

		// Skip entry if token doesn't match
		if parts[1] != tokenSymbol {
			continue
		}

		// Parse provider order amounts
		minOrderAmount, err := decimal.NewFromString(parts[3])
		if err != nil {
			logger.WithFields(logger.Fields{
				"ProviderData": providerData,
				"Error":        err,
			}).Errorf("GetTokenRate.InvalidMinOrderAmount: failed to parse min order amount")
			continue
		}

		maxOrderAmount, err := decimal.NewFromString(parts[4])
		if err != nil {
			logger.WithFields(logger.Fields{
				"ProviderData": providerData,
				"Error":        err,
			}).Errorf("GetTokenRate.InvalidMaxOrderAmount: failed to parse max order amount")
			continue
		}

		// Skip if order amount is not within provider's min and max order amount
		if tokenAmount.LessThan(minOrderAmount) || tokenAmount.GreaterThan(maxOrderAmount) {
			continue
		}

		// Parse rate
		rate, err := decimal.NewFromString(parts[2])
		if err != nil {
			logger.WithFields(logger.Fields{
				"ProviderData": providerData,
				"Error":        err,
			}).Errorf("GetTokenRate.InvalidRate: failed to parse rate")
			continue
		}

		// Track the best rate we've seen (for logging purposes)
		if rate.GreaterThan(bestRate) {
			bestRate = rate
		}

		// Calculate fiat equivalent of the token amount
		fiatAmount := tokenAmount.Mul(rate)

		// Check if fiat amount is within the bucket range
		if fiatAmount.GreaterThanOrEqual(bucketData.MinAmount) && fiatAmount.LessThanOrEqual(bucketData.MaxAmount) {
			foundExactMatch = true
			return rate, true
		}
	}

	// Return the best rate we found (even if no exact match) for logging purposes
	return bestRate, foundExactMatch
}

// GetSupportedTokens controller fetches supported cryptocurrency tokens
func (ctrl *Controller) GetSupportedTokens(ctx *gin.Context) {
	// Get network filter from query parameter
	networkFilter := ctx.Query("network")

	// Build query
	query := storage.Client.Token.
		Query().
		Where(tokenEnt.IsEnabled(true)).
		WithNetwork()

	// Apply network filter if provided
	if networkFilter != "" {
		query = query.Where(tokenEnt.HasNetworkWith(
			networkent.Identifier(strings.ToLower(networkFilter)),
		))
	}

	// Execute query
	tokens, err := query.All(ctx)
	if err != nil {
		logger.Errorf("Error: Failed to fetch tokens: error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch tokens", nil)
		return
	}

	// Transform tokens for response
	response := make([]types.SupportedTokenResponse, 0, len(tokens))
	for _, t := range tokens {
		response = append(response, types.SupportedTokenResponse{
			Symbol:          t.Symbol,
			ContractAddress: t.ContractAddress,
			Decimals:        t.Decimals,
			BaseCurrency:    t.BaseCurrency,
			Network:         t.Edges.Network.Identifier,
		})
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Tokens retrieved successfully", response)
}

// GetAggregatorPublicKey controller expose Aggregator Public Key
func (ctrl *Controller) GetAggregatorPublicKey(ctx *gin.Context) {
	u.APIResponse(ctx, http.StatusOK, "success", "OK", cryptoConf.AggregatorPublicKey)
}

// VerifyAccount controller verifies an account of a given institution
func (ctrl *Controller) VerifyAccount(ctx *gin.Context) {
	var payload types.VerifyAccountRequest

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		logger.WithFields(logger.Fields{
			"Error":             fmt.Sprintf("%v", err),
			"Institution":       payload.Institution,
			"AccountIdentifier": payload.AccountIdentifier,
		}).Errorf("Failed to validate payload when verifying account")
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	accountInstitution, err := storage.Client.Institution.
		Query().
		Where(institution.CodeEQ(payload.Institution)).
		WithFiatCurrency(
			func(fq *ent.FiatCurrencyQuery) {
				fq.Where(fiatcurrency.IsEnabledEQ(true))
			},
		).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":             fmt.Sprintf("%v", err),
			"Institution":       payload.Institution,
			"AccountIdentifier": payload.AccountIdentifier,
		}).Errorf("Failed to validate payload when verifying account")
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", []types.ErrorData{{
			Field:   "Institution",
			Message: "Institution is not supported",
		}})
		return
	}

	// Skip account verification for mobile money institutions
	if accountInstitution.Type == institution.TypeMobileMoney {
		u.APIResponse(ctx, http.StatusOK, "success", "Account name was fetched successfully", "OK")
		return
	}

	providers, err := storage.Client.ProviderProfile.
		Query().
		Where(
			providerprofile.HasCurrenciesWith(
				fiatcurrency.CodeEQ(accountInstitution.Edges.FiatCurrency.Code),
			),
			providerprofile.HostIdentifierNotNil(),
			providerprofile.IsActiveEQ(true),
			providerprofile.IsAvailableEQ(true),
			providerprofile.VisibilityModeEQ(providerprofile.VisibilityModePublic),
		).
		All(ctx)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to verify account", fmt.Sprintf("%v", err))
		return
	}

	if len(providers) == 0 {
		logger.WithFields(logger.Fields{
			"Institution":       payload.Institution,
			"AccountIdentifier": payload.AccountIdentifier,
			"Currency":          accountInstitution.Edges.FiatCurrency.Code,
		}).Errorf("No providers available for account verification")
		u.APIResponse(ctx, http.StatusServiceUnavailable, "error", "No providers available for account verification", nil)
		return
	}

	var res fastshot.Response
	var data map[string]interface{}
	for _, provider := range providers {
		res, err = fastshot.NewClient(provider.HostIdentifier).
			Config().SetTimeout(30 * time.Second).
			Build().POST("/verify_account").
			Body().AsJSON(payload).
			Send()
		if err != nil {
			continue
		}

		data, err = u.ParseJSONResponse(res.RawResponse)
		if err != nil {
			continue
		}

		// Success - break out of loop
		break
	}

	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":             fmt.Sprintf("%v", err),
			"Institution":       payload.Institution,
			"AccountIdentifier": payload.AccountIdentifier,
		}).Errorf("Failed to verify account")
		u.APIResponse(ctx, http.StatusBadGateway, "error", "Failed to verify account", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Account name was fetched successfully", data["data"].(string))
}

// GetLockPaymentOrderStatus controller fetches a payment order status by ID
func (ctrl *Controller) GetLockPaymentOrderStatus(ctx *gin.Context) {
	// Get order and chain ID from the URL
	orderID := ctx.Param("id")
	chainID, err := strconv.ParseInt(ctx.Param("chain_id"), 10, 64)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid chain ID", nil)
		return
	}

	// Fetch related payment orders from the database
	orders, err := storage.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.GatewayIDEQ(orderID),
			lockpaymentorder.HasTokenWith(
				tokenEnt.HasNetworkWith(
					networkent.ChainIDEQ(chainID),
				),
			),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithTransactions().
		All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":   fmt.Sprintf("%v", err),
			"OrderID": orderID,
			"ChainID": chainID,
		}).Errorf("Failed to fetch locked order status")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch order status", nil)
		return
	}

	var settlements []types.LockPaymentOrderSplitOrder
	var receipts []types.LockPaymentOrderTxReceipt
	var settlePercent decimal.Decimal
	var totalAmount decimal.Decimal

	for _, order := range orders {
		for _, transaction := range order.Edges.Transactions {
			if u.ContainsString([]string{"order_settled", "order_created", "order_refunded"}, transaction.Status.String()) {
				var status lockpaymentorder.Status
				if transaction.Status.String() == "order_created" {
					status = lockpaymentorder.StatusPending
				} else {
					status = lockpaymentorder.Status(strings.TrimPrefix(transaction.Status.String(), "order_"))
				}
				receipts = append(receipts, types.LockPaymentOrderTxReceipt{
					Status:    status,
					TxHash:    transaction.TxHash,
					Timestamp: transaction.CreatedAt,
				})
			}
		}

		settlements = append(settlements, types.LockPaymentOrderSplitOrder{
			SplitOrderID: order.ID,
			Amount:       order.Amount,
			Rate:         order.Rate,
			OrderPercent: order.OrderPercent,
		})

		settlePercent = settlePercent.Add(order.OrderPercent)
		totalAmount = totalAmount.Add(order.Amount)
	}

	// Sort receipts by latest timestamp
	slices.SortStableFunc(receipts, func(a, b types.LockPaymentOrderTxReceipt) int {
		return b.Timestamp.Compare(a.Timestamp)
	})

	if (len(orders) == 0) || (len(receipts) == 0) {
		u.APIResponse(ctx, http.StatusNotFound, "error", "Order not found", nil)
		return
	}

	status := orders[0].Status
	if status == lockpaymentorder.StatusCancelled {
		status = lockpaymentorder.StatusProcessing
	}

	response := &types.LockPaymentOrderStatusResponse{
		OrderID:       orders[0].GatewayID,
		Amount:        totalAmount,
		Token:         orders[0].Edges.Token.Symbol,
		Network:       orders[0].Edges.Token.Edges.Network.Identifier,
		SettlePercent: settlePercent,
		Status:        status,
		TxHash:        receipts[0].TxHash,
		Settlements:   settlements,
		TxReceipts:    receipts,
		UpdatedAt:     orders[0].UpdatedAt,
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Order status fetched successfully", response)
}

// CreateLinkedAddress controller creates a new linked address
func (ctrl *Controller) CreateLinkedAddress(ctx *gin.Context) {
	var payload types.NewLinkedAddressRequest

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		logger.WithFields(logger.Fields{
			"Error":             fmt.Sprintf("%v", err),
			"Institution":       payload.Institution,
			"AccountIdentifier": payload.AccountIdentifier,
		}).Errorf("Failed to validate payload when creating linked address")
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	ownerAddress, _ := ctx.Get("owner_address")

	// Generate smart account
	address, err := ctrl.receiveAddressService.CreateSmartAddress(ctx, "")
	if err != nil {
		logger.Errorf("Error: Failed to create linked address: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to create linked address", nil)
		return
	}

	// Create a new linked address
	linkedAddress, err := storage.Client.LinkedAddress.
		Create().
		SetAddress(address).
		SetInstitution(payload.Institution).
		SetAccountIdentifier(payload.AccountIdentifier).
		SetAccountName(payload.AccountName).
		SetOwnerAddress(ownerAddress.(string)).
		Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":        fmt.Sprintf("%v", err),
			"Institution":  payload.Institution,
			"OwnerAddress": ownerAddress,
			"Address":      address,
		}).Errorf("Failed to set linked address")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to create linked address", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Linked address created successfully", &types.NewLinkedAddressResponse{
		LinkedAddress:     linkedAddress.Address,
		Institution:       linkedAddress.Institution,
		AccountIdentifier: linkedAddress.AccountIdentifier,
		AccountName:       linkedAddress.AccountName,
		UpdatedAt:         linkedAddress.UpdatedAt,
		CreatedAt:         linkedAddress.CreatedAt,
	})
}

// GetLinkedAddress controller fetches a linked address
func (ctrl *Controller) GetLinkedAddress(ctx *gin.Context) {
	// Get owner address from the URL
	owner_address := ctx.Query("owner_address")

	linkedAddress, err := storage.Client.LinkedAddress.
		Query().
		Where(
			linkedaddress.OwnerAddressEQ(owner_address),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusNotFound, "error", "Linked address not found", nil)
			return
		} else {
			logger.WithFields(logger.Fields{
				"Error":        fmt.Sprintf("%v", err),
				"OwnerAddress": owner_address,
			}).Errorf("Failed to fetch linked address")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch linked address", nil)
			return
		}
	}

	institution, err := storage.Client.Institution.
		Query().
		Where(institution.CodeEQ(linkedAddress.Institution)).
		WithFiatCurrency().
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":                    fmt.Sprintf("%v", err),
			"OwnerAddress":             owner_address,
			"LinkedAddressInstitution": linkedAddress.Institution,
		}).Errorf("Failed to fetch linked address")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch linked address", nil)
		return
	}

	ownerAddressFromAuth, _ := ctx.Get("owner_address")

	response := &types.LinkedAddressResponse{
		LinkedAddress: linkedAddress.Address,
		Currency:      institution.Edges.FiatCurrency.Code,
	}

	if ownerAddressFromAuth != nil {
		response.AccountIdentifier = linkedAddress.AccountIdentifier
		response.AccountName = linkedAddress.AccountName
		response.Institution = institution.Name
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Linked address fetched successfully", response)
}

// GetLinkedAddressTransactions controller fetches transactions for a linked address
func (ctrl *Controller) GetLinkedAddressTransactions(ctx *gin.Context) {
	// Get linked address from the URL
	linked_address := ctx.Param("linked_address")

	linkedAddress, err := storage.Client.LinkedAddress.
		Query().
		Where(
			linkedaddress.AddressEQ(linked_address),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusNotFound, "error", "Linked address not found", nil)
			return
		} else {
			logger.WithFields(logger.Fields{
				"Error":         fmt.Sprintf("%v", err),
				"LinkedAddress": linked_address,
			}).Errorf("Failed to fetch linked address")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch linked address", nil)
			return
		}
	}

	// Get page and pageSize query params
	page, offset, pageSize := u.Paginate(ctx)

	// Fetch related transactions from the database
	paymentOrderQuery := linkedAddress.QueryPaymentOrders()

	count, err := paymentOrderQuery.Count(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":                     fmt.Sprintf("%v", err),
			"LinkedAddress":             linked_address,
			"LinkedAddressID":           linkedAddress.ID,
			"LinkedAddressOwnerAddress": linkedAddress.OwnerAddress,
		}).Errorf("Failed to count payment orders for linked address")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch transactions", nil)
		return
	}

	paymentOrders, err := paymentOrderQuery.
		Limit(pageSize).
		Offset(offset).
		WithRecipient().
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":                     fmt.Sprintf("%v", err),
			"LinkedAddress":             linked_address,
			"LinkedAddressID":           linkedAddress.ID,
			"LinkedAddressOwnerAddress": linkedAddress.OwnerAddress,
		}).Errorf("Failed to fetch fetch payment orders for linked address")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch transactions", nil)
		return
	}

	orders := make([]types.LinkedAddressTransaction, 0, len(paymentOrders))

	for _, paymentOrder := range paymentOrders {
		institution, err := storage.Client.Institution.
			Query().
			Where(institution.CodeEQ(paymentOrder.Edges.Recipient.Institution)).
			WithFiatCurrency().
			Only(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":                     fmt.Sprintf("%v", err),
				"LinkedAddress":             linked_address,
				"LinkedAddressID":           linkedAddress.ID,
				"LinkedAddressOwnerAddress": linkedAddress.OwnerAddress,
				"PaymentOrderID":            paymentOrder.ID,
			}).Errorf("Failed to get institution for linked address")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch payment orders", nil)
			return
		}

		orders = append(orders, types.LinkedAddressTransaction{
			ID:      paymentOrder.ID,
			Amount:  paymentOrder.Amount,
			Token:   paymentOrder.Edges.Token.Symbol,
			Rate:    paymentOrder.Rate,
			Network: paymentOrder.Edges.Token.Edges.Network.Identifier,
			Recipient: types.LinkedAddressTransactionRecipient{
				Currency:          institution.Edges.FiatCurrency.Code,
				Institution:       institution.Name,
				AccountIdentifier: paymentOrder.Edges.Recipient.AccountIdentifier,
				AccountName:       paymentOrder.Edges.Recipient.AccountName,
			},
			FromAddress:   paymentOrder.FromAddress,
			ReturnAddress: paymentOrder.ReturnAddress,
			GatewayID:     paymentOrder.GatewayID,
			TxHash:        paymentOrder.TxHash,
			CreatedAt:     paymentOrder.CreatedAt,
			UpdatedAt:     paymentOrder.UpdatedAt,
			Status:        paymentOrder.Status,
		})
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Transactions fetched successfully", &types.LinkedAddressTransactionList{
		Page:         page,
		PageSize:     pageSize,
		TotalRecords: count,
		Transactions: orders,
	})

}

// verifyWalletSignature verifies the Ethereum signature for wallet verification
func (ctrl *Controller) verifyWalletSignature(walletAddress, signature, nonce string) error {
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature: signature is not in the correct format")
	}
	if len(sig) != 65 {
		return fmt.Errorf("invalid signature: signature length is not correct")
	}
	if sig[64] != 27 && sig[64] != 28 {
		return fmt.Errorf("invalid signature: invalid recovery ID")
	}
	sig[64] -= 27

	message := fmt.Sprintf("I accept the KYC Policy and hereby request an identity verification check for %s with nonce %s", walletAddress, nonce)
	prefix := "\x19Ethereum Signed Message:\n" + fmt.Sprint(len(message))
	hash := crypto.Keccak256Hash([]byte(prefix + message))

	sigPublicKeyECDSA, err := crypto.SigToPub(hash.Bytes(), sig)
	if err != nil {
		return fmt.Errorf("invalid signature")
	}
	recoveredAddress := crypto.PubkeyToAddress(*sigPublicKeyECDSA)
	if !strings.EqualFold(recoveredAddress.Hex(), walletAddress) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// RequestIDVerification controller requests identity verification details
func (ctrl *Controller) RequestIDVerification(ctx *gin.Context) {
	var payload types.VerificationRequest

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	// Verify signature before proceeding
	if err := ctrl.verifyWalletSignature(payload.WalletAddress, payload.Signature, payload.Nonce); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid signature", fmt.Sprintf("%v", err))
		return
	}

	response, err := ctrl.kycService.RequestVerification(ctx, payload)
	if err != nil {
		switch e := err.(type) {
		case kycErrors.ErrSignatureAlreadyUsed:
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Signature already used for identity verification", nil)
			return
		case kycErrors.ErrAlreadyVerified:
			u.APIResponse(ctx, http.StatusBadRequest, "success", "Failed to request identity verification", e.Error())
			return
		case kycErrors.ErrProviderUnreachable:
			logger.WithFields(logger.Fields{
				"Error":         fmt.Sprintf("%v", e.Err),
				"WalletAddress": payload.WalletAddress,
				"Nonce":         payload.Nonce,
			}).Errorf("Failed to reach identity provider")
			u.APIResponse(ctx, http.StatusBadGateway, "error", "Failed to request identity verification", "Couldn't reach identity provider")
			return
		case kycErrors.ErrProviderResponse:
			logger.WithFields(logger.Fields{
				"Error":         fmt.Sprintf("%v", e.Err),
				"WalletAddress": payload.WalletAddress,
				"Nonce":         payload.Nonce,
			}).Errorf("Invalid response from identity provider")
			u.APIResponse(ctx, http.StatusBadGateway, "error", "Failed to request identity verification", e.Error())
			return
		case kycErrors.ErrDatabase:
			logger.WithFields(logger.Fields{
				"Error":         fmt.Sprintf("%v", e.Err),
				"WalletAddress": payload.WalletAddress,
				"Nonce":         payload.Nonce,
			}).Errorf("Database error during identity verification")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to request identity verification", nil)
			return
		default:
			logger.WithFields(logger.Fields{
				"Error":         fmt.Sprintf("%v", err),
				"WalletAddress": payload.WalletAddress,
				"Nonce":         payload.Nonce,
			}).Errorf("Failed to request identity verification")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to request identity verification", nil)
			return
		}
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Identity verification requested successfully", response)
}

// GetIDVerificationStatus controller fetches the status of an identity verification request
func (ctrl *Controller) GetIDVerificationStatus(ctx *gin.Context) {
	// Get wallet address from the URL
	walletAddress := ctx.Param("wallet_address")

	response, err := ctrl.kycService.CheckStatus(ctx, walletAddress)
	if err != nil {
		switch err.(type) {
		case kycErrors.ErrNotFound:
			u.APIResponse(ctx, http.StatusNotFound, "error", "No verification request found for this wallet address", nil)
			return
		default:
			logger.WithFields(logger.Fields{
				"Error":         fmt.Sprintf("%v", err),
				"WalletAddress": walletAddress,
			}).Errorf("Failed to fetch identity verification status")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch identity verification status", nil)
			return
		}
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Identity verification status fetched successfully", response)
}

// KYCWebhook handles the webhook callback from Smile Identity
func (ctrl *Controller) KYCWebhook(ctx *gin.Context) {
	payload, err := ctx.GetRawData()
	if err != nil {
		logger.Errorf("Error: KYCWebhook: Failed to read webhook payload: %v", err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
		return
	}

	err = ctrl.kycService.HandleWebhook(ctx, payload)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":   fmt.Sprintf("%v", err),
			"Payload": string(payload),
		}).Errorf("Failed to process webhook for kyc")
		if fmt.Sprintf("%v", err) == "invalid payload" {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
			return
		}
		if fmt.Sprintf("%v", err) == "invalid signature" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process webhook"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Webhook processed successfully"})
}

// IndexTransaction controller indexes a specific transaction for blockchain events
func (ctrl *Controller) IndexTransaction(ctx *gin.Context) {
	// Get network and txHash from URL parameters
	networkParam := ctx.Param("network")
	txHash := ctx.Param("tx_hash")

	// Validate txHash format (basic hex validation)
	if !strings.HasPrefix(txHash, "0x") || len(txHash) != 66 {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid transaction hash format", nil)
		return
	}

	// Validate network based on server environment
	isTestnet := false
	if serverConf.Environment != "production" {
		isTestnet = true
	}

	// Try to parse as chain ID first, then fall back to identifier
	var network *ent.Network
	var err error

	chainID, parseErr := strconv.ParseInt(networkParam, 10, 64)
	if parseErr == nil {
		// networkParam is a chain ID
		network, err = storage.Client.Network.
			Query().
			Where(
				networkent.ChainIDEQ(chainID),
				networkent.IsTestnetEQ(isTestnet),
			).
			Only(ctx)
	} else {
		// networkParam is an identifier (e.g., "base", "ethereum")
		network, err = storage.Client.Network.
			Query().
			Where(
				networkent.IdentifierEqualFold(networkParam),
				networkent.IsTestnetEQ(isTestnet),
			).
			Only(ctx)
	}

	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Network not found or not supported for current environment", nil)
			return
		}
		logger.WithFields(logger.Fields{
			"Error":        fmt.Sprintf("%v", err),
			"NetworkParam": networkParam,
		}).Errorf("Failed to fetch network")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to validate network", nil)
		return
	}

	// Fetch enabled tokens for the network
	tokens, err := storage.Client.Token.
		Query().
		Where(
			tokenEnt.IsEnabled(true),
			tokenEnt.HasNetworkWith(
				networkent.IDEQ(network.ID),
			),
		).
		WithNetwork().
		All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":        fmt.Sprintf("%v", err),
			"NetworkParam": networkParam,
		}).Errorf("Failed to fetch tokens for network")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch tokens", nil)
		return
	}

	// Create indexer instance based on network type
	var indexerInstance types.Indexer
	if strings.HasPrefix(network.Identifier, "tron") {
		indexerInstance = indexer.NewIndexerTron()
	} else {
		indexerInstance = indexer.NewIndexerEVM()
	}

	// Track event counts
	eventCounts := struct {
		Transfer      int `json:"Transfer"`
		OrderCreated  int `json:"OrderCreated"`
		OrderSettled  int `json:"OrderSettled"`
		OrderRefunded int `json:"OrderRefunded"`
	}{}

	// Run each event type in separate goroutines
	var wg sync.WaitGroup

	// Index OrderCreated events
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := indexerInstance.IndexOrderCreated(ctx, network, 0, 0, txHash)
		if err != nil && err.Error() != "no events found" {
			logger.WithFields(logger.Fields{
				"Error":        fmt.Sprintf("%v", err),
				"NetworkParam": networkParam,
				"TxHash":       txHash,
				"EventType":    "OrderCreated",
			}).Errorf("Failed to index OrderCreated events")
		} else {
			eventCounts.OrderCreated++
		}
	}()

	// Index OrderSettled events
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := indexerInstance.IndexOrderSettled(ctx, network, 0, 0, txHash)
		if err != nil && err.Error() != "no events found" {
			logger.WithFields(logger.Fields{
				"Error":        fmt.Sprintf("%v", err),
				"NetworkParam": networkParam,
				"TxHash":       txHash,
				"EventType":    "OrderSettled",
			}).Errorf("Failed to index OrderSettled events")
		} else {
			eventCounts.OrderSettled++
		}
	}()

	// Index OrderRefunded events
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := indexerInstance.IndexOrderRefunded(ctx, network, 0, 0, txHash)
		if err != nil && err.Error() != "no events found" {
			logger.WithFields(logger.Fields{
				"Error":        fmt.Sprintf("%v", err),
				"NetworkParam": networkParam,
				"TxHash":       txHash,
				"EventType":    "OrderRefunded",
			}).Errorf("Failed to index OrderRefunded events")
		} else {
			eventCounts.OrderRefunded++
		}
	}()

	// Index Transfer events for each token
	for _, token := range tokens {
		wg.Add(1)
		go func(token *ent.Token) {
			defer wg.Done()
			err := indexerInstance.IndexTransfer(ctx, token, "", 0, 0, txHash)
			if err != nil && err.Error() != "no events found" {
				logger.WithFields(logger.Fields{
					"Error":        fmt.Sprintf("%v", err),
					"NetworkParam": networkParam,
					"Token":        token.Symbol,
					"TxHash":       txHash,
					"EventType":    "Transfer",
				}).Errorf("Failed to index Transfer events")
			} else {
				eventCounts.Transfer++
			}
		}(token)
	}

	// Wait for all indexing operations to complete
	wg.Wait()

	response := types.IndexTransactionResponse{
		Message: fmt.Sprintf("Successfully indexed transaction %s for network %s", txHash, networkParam),
		Events:  eventCounts,
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Transaction indexing completed", response)
}
