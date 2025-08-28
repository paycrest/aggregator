package controllers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/beneficialowner"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/kybprofile"
	"github.com/paycrest/aggregator/ent/linkedaddress"
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentwebhook"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/receiveaddress"
	tokenEnt "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/user"
	svc "github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/services/email"
	"github.com/paycrest/aggregator/services/indexer"
	kycErrors "github.com/paycrest/aggregator/services/kyc/errors"
	"github.com/paycrest/aggregator/services/kyc/smile"
	orderSvc "github.com/paycrest/aggregator/services/order"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	u "github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
)

var cryptoConf = config.CryptoConfig()

var serverConf = config.ServerConfig()
var identityConf = config.IdentityConfig()
var orderConf = config.OrderConfig()

// Controller is the default controller for other endpoints
type Controller struct {
	orderService          types.OrderService
	priorityQueueService  *svc.PriorityQueueService
	receiveAddressService *svc.ReceiveAddressService
	kycService            types.KYCProvider
	slackService          *svc.SlackService
	emailService          email.EmailServiceInterface
	cache                 map[string]bool
	processedActions      map[string]bool
	actionMutex           sync.RWMutex
}

// NewController creates a new instance of AuthController with injected services
func NewController() *Controller {
	return &Controller{
		orderService:          orderSvc.NewOrderEVM(),
		priorityQueueService:  svc.NewPriorityQueueService(),
		receiveAddressService: svc.NewReceiveAddressService(),
		kycService:            smile.NewSmileIDService(),
		slackService:          svc.NewSlackService(serverConf.SlackWebhookURL),
		emailService:          email.NewEmailServiceWithProviders(),
		cache:                 make(map[string]bool),
		processedActions:      make(map[string]bool),
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
		networkFilter = strings.ToLower(networkFilter)
		tokenQuery = tokenQuery.Where(tokenEnt.HasNetworkWith(
			networkent.Identifier(networkFilter),
		))
	}

	token, err := tokenQuery.First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			errorMsg := fmt.Sprintf("Token %s is not supported", tokenSymbol)
			if networkFilter != "" {
				errorMsg = fmt.Sprintf("Token %s is not supported on network %s", tokenSymbol, networkFilter)
			}
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Token":   tokenSymbol,
				"Network": networkFilter,
			}).Errorf("Failed to fetch token rate: %v", err)
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

	// Validate rate using extracted logic
	rateResponse, _, err := u.ValidateRate(ctx, token, currency, tokenAmount, ctx.Query("provider_id"), networkFilter)
	if err != nil {
		// Return 404 if no provider found, else 500 for other errors
		if strings.Contains(err.Error(), "no provider available") {
			u.APIResponse(ctx, http.StatusNotFound, "error", err.Error(), nil)
		} else {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Token":   tokenSymbol,
				"Network": networkFilter,
			}).Errorf("Failed to fetch token rate: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", err.Error(), nil)
		}
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Rate fetched successfully", rateResponse)
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

	// Use the abstracted ValidateAccount utility function
	accountName, err := u.ValidateAccount(ctx, payload.Institution, payload.AccountIdentifier)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":             fmt.Sprintf("%v", err),
			"Institution":       payload.Institution,
			"AccountIdentifier": payload.AccountIdentifier,
		}).Errorf("Failed to verify account")
		u.APIResponse(ctx, http.StatusServiceUnavailable, "error", "Failed to verify account", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Account name was fetched successfully", accountName)
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

// SlackInteractionHandler handles Slack interaction requests
func (ctrl *Controller) SlackInteractionHandler(ctx *gin.Context) {
	startTime := time.Now()

	// Parse form-encoded payload
	payloadStr := ctx.PostForm("payload")
	if payloadStr == "" {
		body, err := ctx.GetRawData()
		if err != nil {
			logger.Errorf("Missing payload and failed to read raw body: %v", err)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing payload"})
			return
		}
		payloadStr = string(body)
	}

	// Parse JSON payload
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
		logger.Errorf("Error parsing Slack interaction payload: %v", err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Error parsing payload"})
		return
	}

	// Handle modal trigger (button clicks)
	if payload["type"] == "block_actions" {
		actions, ok := payload["actions"].([]interface{})
		if !ok || len(actions) == 0 {
			logger.Errorf("Invalid or empty actions in Slack payload: %v", payload)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid actions"})
			return
		}

		action, ok := actions[0].(map[string]interface{})
		if !ok {
			logger.Errorf("Invalid action format: %v", actions[0])
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action format"})
			return
		}

		actionID, ok := action["action_id"].(string)
		if !ok {
			logger.Errorf("Missing or invalid action_id")
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing action_id"})
			return
		}

		var kybProfileID string
		if strings.Contains(actionID, "_") {
			kybProfileID = actionID[strings.Index(actionID, "_")+1:]
		} else {
			logger.Errorf("Invalid action_id format: %s", actionID)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action_id format"})
			return
		}

		// Parse KYB Profile ID as UUID
		kybProfileUUID, err := uuid.Parse(kybProfileID)
		if err != nil {
			logger.Errorf("Invalid KYB Profile ID format: %s, error: %v", kybProfileID, err)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid KYB Profile ID format"})
			return
		}

		// Fetch KYB submission details from database
		kybProfile, err := storage.Client.KYBProfile.
			Query().
			Where(kybprofile.IDEQ(kybProfileUUID)).
			WithUser().
			WithBeneficialOwners().
			Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				logger.Errorf("KYB Profile not found: %s", kybProfileID)
				ctx.JSON(http.StatusNotFound, gin.H{"error": "KYB Profile not found"})
				return
			}
			logger.Errorf("Failed to fetch KYB Profile %s: %v", kybProfileID, err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch KYB Profile"})
			return
		}

		// Extract user details
		var firstName, email string
		if kybProfile.Edges.User != nil {
			firstName = kybProfile.Edges.User.FirstName
			email = kybProfile.Edges.User.Email
		} else {
			logger.Errorf("KYB Profile %s has no associated user", kybProfileID)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "KYB Profile has no associated user"})
			return
		}

		if email == "" {
			logger.Errorf("Missing email for KYB Profile %s", kybProfileID)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing email"})
			return
		}
		if firstName == "" {
			logger.Warnf("Missing firstName for KYB Profile %s, using default", kybProfileID)
			firstName = "User"
		}

		// Handle reject button - only open modal
		if strings.HasPrefix(actionID, "reject_") {
			logger.Infof("Reject button clicked for KYB Profile %s, action: %+v", kybProfileID, action)
			triggerID, ok := payload["trigger_id"].(string)
			if !ok {
				logger.Errorf("Missing trigger_id for modal, KYB Profile ID: %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing trigger_id"})
				return
			}

			modal := map[string]interface{}{
				"trigger_id": triggerID,
				"view": map[string]interface{}{
					"type":             "modal",
					"callback_id":      "reject_modal_" + kybProfileID,
					"private_metadata": fmt.Sprintf(`{"email":"%s","kyb_profile_id":"%s","firstName":"%s"}`, email, kybProfileID, firstName),
					"title": map[string]interface{}{
						"type": "plain_text",
						"text": "Reject KYB Submission",
					},
					"submit": map[string]interface{}{
						"type": "plain_text",
						"text": "Submit",
					},
					"blocks": []map[string]interface{}{
						{
							"type":     "input",
							"block_id": "reason_block",
							"element": map[string]interface{}{
								"type":      "static_select",
								"action_id": "reason_select",
								"placeholder": map[string]interface{}{
									"type": "plain_text",
									"text": "Select a reason",
								},
								"options": []map[string]interface{}{
									{
										"text": map[string]interface{}{
											"type": "plain_text",
											"text": "Incomplete or falsified documentation",
										},
										"value": "Incomplete or falsified documentation",
									},
									{
										"text": map[string]interface{}{
											"type": "plain_text",
											"text": "Unverifiable business identity",
										},
										"value": "Unverifiable business identity",
									},
									{
										"text": map[string]interface{}{
											"type": "plain_text",
											"text": "Sanctions or watchlist hits",
										},
										"value": "Sanctions or watchlist hits",
									},
									{
										"text": map[string]interface{}{
											"type": "plain_text",
											"text": "Inability to identify beneficial owners (UBOs)",
										},
										"value": "Inability to identify beneficial owners (UBOs)",
									},
									{
										"text": map[string]interface{}{
											"type": "plain_text",
											"text": "Inconsistent business details across documents",
										},
										"value": "Inconsistent business details across documents",
									},
								},
							},
							"label": map[string]interface{}{
								"type": "plain_text",
								"text": "Reason for Rejection",
							},
						},
					},
				},
			}

			jsonPayload, err := json.Marshal(modal)
			if err != nil {
				logger.Errorf("Failed to marshal modal payload for KYB Profile %s: %v", kybProfileID, err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create modal"})
				return
			}

			client := &http.Client{}
			req, err := http.NewRequest("POST", "https://slack.com/api/views.open", bytes.NewBuffer(jsonPayload))
			if err != nil {
				logger.Errorf("Failed to create Slack API request for KYB Profile %s: %v", kybProfileID, err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create modal request"})
				return
			}
			req.Header.Set("Content-Type", "application/json")
			cnfg := config.AuthConfig()
			if cnfg.SlackBotToken == "" {
				logger.Errorf("Slack bot token not configured for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Slack bot token not configured"})
				return
			}
			req.Header.Set("Authorization", "Bearer "+cnfg.SlackBotToken)

			resp, err := client.Do(req)
			if err != nil {
				logger.Errorf("Failed to open Slack modal for KYB Profile %s: %v", kybProfileID, err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open modal"})
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				logger.Errorf("Slack API responded with status %d for KYB Profile %s: %s", resp.StatusCode, kybProfileID, string(body))
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open modal"})
				return
			}

			ctx.JSON(http.StatusOK, gin.H{})
			return
		}

		if strings.HasPrefix(actionID, "approve_") {
			if ctrl.isActionProcessed(kybProfileID, "approve") || ctrl.isActionProcessed(kybProfileID, "reject") {
				logger.Warnf("Action already processed for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusOK, gin.H{"text": "This submission has already been processed."})
				return
			}

			// Mark as processed immediately
			ctrl.markActionProcessed(kybProfileID, "approve")

			// Respond immediately to Slack to remove loading state
			responseURL, _ := payload["response_url"].(string)
			if responseURL != "" {
				go func() {
					message := map[string]interface{}{
						"replace_original": true,
						"text":             fmt.Sprintf("✅ *APPROVED* - KYB submission for %s (%s) from %s has been approved.", firstName, email, kybProfile.CompanyName),
					}
					jsonPayload, _ := json.Marshal(message)
					if _, err := http.Post(responseURL, "application/json", bytes.NewBuffer(jsonPayload)); err != nil {
						logger.Errorf("Failed to post response to URL: %v", err)
					}
				}()
			}

			// Send immediate response to Slack
			ctx.JSON(http.StatusOK, gin.H{"text": "Approving submission..."})

			// Update User KYB status
			_, err := storage.Client.User.
				Update().
				Where(user.IDEQ(kybProfile.Edges.User.ID)).
				SetKybVerificationStatus(user.KybVerificationStatusApproved).
				Save(ctx)
			if err != nil {
				logger.Errorf("Failed to approve KYB for user %s (KYB Profile %s): %v", email, kybProfileID, err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user KYB status"})
				return
			}

			// Update KYB Profile status (assuming you have a status field)
			_, err = storage.Client.KYBProfile.
				UpdateOne(kybProfile).
				Save(ctx)
			if err != nil {
				logger.Errorf("Failed to update KYB Profile status %s: %v", kybProfileID, err)
			}

			// Send approval email
			resp, err := ctrl.emailService.SendKYBApprovalEmail(ctx, email, firstName)
			if err != nil {
				logger.Errorf("Failed to send KYB approval email to %s (KYB Profile %s): %v, response: %+v", email, kybProfileID, err, resp)
			} else {
				logger.Infof("KYB approval email sent successfully to %s (KYB Profile %s), message ID: %s", email, kybProfileID, resp.Id)
			}

			// Send Slack feedback notification
			err = ctrl.slackService.SendActionFeedbackNotification(firstName, email, kybProfileID, "approve", "")
			if err != nil {
				logger.Warnf("Failed to send Slack feedback notification for KYB Profile %s: %v", kybProfileID, err)
			}

			logger.Infof("Processed Slack approve interaction in %v", time.Since(startTime))
			return
		}

		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Unknown action"})
		return
	}

	// Handle modal submission
	if payload["type"] == "view_submission" {
		view, ok := payload["view"].(map[string]interface{})
		if !ok {
			logger.Errorf("Invalid view format in payload")
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid view format"})
			return
		}
		callbackID, ok := view["callback_id"].(string)
		if !ok {
			logger.Errorf("Missing callback_id in view")
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing callback_id"})
			return
		}

		if strings.HasPrefix(callbackID, "reject_modal_") {
			kybProfileID := callbackID[len("reject_modal_"):]

			// Prevent modal if already processed
			if ctrl.isActionProcessed(kybProfileID, "approve") || ctrl.isActionProcessed(kybProfileID, "reject") {
				logger.Warnf("Action already processed for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusOK, gin.H{"text": "This submission has already been processed."})
				return
			}

			// Mark as processed immediately
			ctrl.markActionProcessed(kybProfileID, "reject")

			// Extract selected reason
			state, ok := view["state"].(map[string]interface{})
			if !ok {
				logger.Errorf("Invalid state in view for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state"})
				return
			}
			values, ok := state["values"].(map[string]interface{})
			if !ok {
				logger.Errorf("Invalid values in state for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid values"})
				return
			}
			reasonBlock, ok := values["reason_block"].(map[string]interface{})
			if !ok {
				logger.Errorf("Invalid reason_block in values for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid reason_block"})
				return
			}
			reasonSelect, ok := reasonBlock["reason_select"].(map[string]interface{})
			if !ok {
				logger.Errorf("Invalid reason_select in reason_block for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid reason_select"})
				return
			}
			selectedReason, ok := reasonSelect["selected_option"].(map[string]interface{})
			if !ok {
				logger.Errorf("No reason selected for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "No reason selected"})
				return
			}
			reasonForDecline, ok := selectedReason["value"].(string)
			if !ok {
				logger.Errorf("Invalid reason value for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid reason value"})
				return
			}

			// Extract email and firstName from private_metadata
			privateMetadata, ok := view["private_metadata"].(string)
			if !ok {
				logger.Errorf("Missing private_metadata in view for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing private_metadata"})
				return
			}
			var metadata map[string]interface{}
			if err := json.Unmarshal([]byte(privateMetadata), &metadata); err != nil {
				logger.Errorf("Error parsing private_metadata for KYB Profile %s: %v", kybProfileID, err)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid metadata"})
				return
			}
			email, ok := metadata["email"].(string)
			if !ok || email == "" {
				logger.Errorf("Missing email in private_metadata for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing email in metadata"})
				return
			}
			firstName, ok := metadata["firstName"].(string)
			if !ok {
				logger.Warnf("Missing firstName in private_metadata for KYB Profile %s; using default", kybProfileID)
				firstName = "User"
			}

			// Parse KYB Profile ID for database operations
			kybProfileUUID, err := uuid.Parse(kybProfileID)
			if err != nil {
				logger.Errorf("Invalid KYB Profile ID format for rejection: %s, error: %v", kybProfileID, err)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid KYB Profile ID format"})
				return
			}

			// Update User KYB status
			_, err = storage.Client.User.
				Update().
				Where(user.EmailEQ(email)).
				SetKybVerificationStatus(user.KybVerificationStatusRejected).
				Save(ctx)
			if err != nil {
				logger.Errorf("Failed to reject KYB for user %s (KYB Profile %s): %v", email, kybProfileID, err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user KYB status"})
				return
			}

			// Update KYB Profile status (assuming you have a status field)
			_, err = storage.Client.KYBProfile.
				Update().
				Where(kybprofile.IDEQ(kybProfileUUID)).
				Save(ctx)
			if err != nil {
				logger.Errorf("Failed to update KYB Profile status %s: %v", kybProfileID, err)
			}

			// Send rejection email
			resp, err := ctrl.emailService.SendKYBRejectionEmail(ctx, email, firstName, reasonForDecline)
			if err != nil {
				logger.Errorf("Failed to send KYB rejection email to %s (KYB Profile %s): %v, response: %+v", email, kybProfileID, err, resp)
			} else {
				logger.Infof("KYB rejection email sent successfully to %s (KYB Profile %s), message ID: %s", email, kybProfileID, resp.Id)
			}

			// Send Slack feedback notification
			err = ctrl.slackService.SendActionFeedbackNotification(firstName, email, kybProfileID, "reject", reasonForDecline)
			if err != nil {
				logger.Warnf("Failed to send Slack feedback notification for KYB Profile %s: %v", kybProfileID, err)
			}

			logger.Infof("Processed Slack modal submission for rejection in %v", time.Since(startTime))
			return
		}

		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Unknown callback_id"})
		return
	}
	ctx.JSON(http.StatusBadRequest, gin.H{"error": "Unknown payload type"})
}

// isActionProcessed checks if an action has already been processed
func (ctrl *Controller) isActionProcessed(submissionID, actionType string) bool {
	ctrl.actionMutex.RLock()
	defer ctrl.actionMutex.RUnlock()
	key := fmt.Sprintf("%s_%s", submissionID, actionType)
	return ctrl.processedActions[key]
}

// markActionProcessed marks an action as processed
func (ctrl *Controller) markActionProcessed(submissionID, actionType string) {
	ctrl.actionMutex.Lock()
	defer ctrl.actionMutex.Unlock()
	key := fmt.Sprintf("%s_%s", submissionID, actionType)
	ctrl.processedActions[key] = true
}

// HandleKYBSubmission handles the POST request for KYB submission
func (ctrl *Controller) HandleKYBSubmission(ctx *gin.Context) {
	var input types.KYBSubmissionInput
	if err := ctx.ShouldBindJSON(&input); err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
		}).Errorf("Error: Failed to bind KYB submission input")
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid input", err.Error())
		return
	}

	// Get user ID from the context
	userIDValue, exists := ctx.Get("user_id")
	if !exists {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "User not authenticated", nil)
		return
	}

	// Validate user ID
	userID, err := uuid.Parse(userIDValue.(string))
	if err != nil {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid user ID", nil)
		return
	}

	// Fetch user record
	userRecord, err := storage.Client.User.
		Query().
		Where(user.IDEQ(userID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusNotFound, "error", "User not found", nil)
			return
		}
		logger.WithFields(logger.Fields{
			"Error":  fmt.Sprintf("%v", err),
			"UserID": userID,
		}).Error("Error: Failed to query user")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to process request", nil)
		return
	}

	// Check if user already has a KYB submission
	existingSubmission, err := storage.Client.KYBProfile.
		Query().
		Where(kybprofile.HasUserWith(user.IDEQ(userRecord.ID))).
		Exist(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":  fmt.Sprintf("%v", err),
			"UserID": userID,
		}).Errorf("Error: Failed to check existing KYB submission")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to process request", nil)
		return
	}

	if existingSubmission {
		u.APIResponse(ctx, http.StatusConflict, "error", "KYB submission already submitted for this user", nil)
		return
	}

	// --- Begin Transaction ---
	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":  fmt.Sprintf("%v", err),
			"UserID": userID,
		}).Errorf("Error: Failed to start transaction")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to process request", nil)
		return
	}
	defer func() {
		if p := recover(); p != nil {
			if err := tx.Rollback(); err != nil {
				logger.Errorf("Failed to rollback transaction during panic: %v", err)
			}
			panic(p)
		}
	}()

	kybBuilder := tx.KYBProfile.
		Create().
		SetMobileNumber(input.MobileNumber).
		SetCompanyName(input.CompanyName).
		SetRegisteredBusinessAddress(input.RegisteredBusinessAddress).
		SetCertificateOfIncorporationURL(input.CertificateOfIncorporationUrl).
		SetArticlesOfIncorporationURL(input.ArticlesOfIncorporationUrl).
		SetProofOfBusinessAddressURL(input.ProofOfBusinessAddressUrl).
		SetUserID(userRecord.ID)

	if input.BusinessLicenseUrl != nil {
		kybBuilder.SetBusinessLicenseURL(*input.BusinessLicenseUrl)
	}
	if input.AmlPolicyUrl != nil {
		kybBuilder.SetAmlPolicyURL(*input.AmlPolicyUrl)
	}
	if input.KycPolicyUrl != nil {
		kybBuilder.SetKycPolicyURL(*input.KycPolicyUrl)
	}

	kybSubmission, err := kybBuilder.Save(ctx)
	if err != nil {
		if err := tx.Rollback(); err != nil {
			logger.Errorf("Failed to rollback transaction: %v", err)
		}
		logger.WithFields(logger.Fields{
			"Error":  fmt.Sprintf("%v", err),
			"UserID": userID,
		}).Errorf("Error: Failed to save KYB submission: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to save KYB submission", nil)
		return
	}

	for _, owner := range input.BeneficialOwners {
		_, err := tx.BeneficialOwner.
			Create().
			SetFullName(owner.FullName).
			SetResidentialAddress(owner.ResidentialAddress).
			SetProofOfResidentialAddressURL(owner.ProofOfResidentialAddressUrl).
			SetGovernmentIssuedIDURL(owner.GovernmentIssuedIdUrl).
			SetDateOfBirth(owner.DateOfBirth).
			SetOwnershipPercentage(owner.OwnershipPercentage).
			SetGovernmentIssuedIDType(beneficialowner.GovernmentIssuedIDType(owner.GovernmentIssuedIdType)).
			SetKybProfileID(kybSubmission.ID).
			Save(ctx)
		if err != nil {
			if err := tx.Rollback(); err != nil {
				logger.Errorf("Failed to rollback transaction: %v", err)
			}
			logger.WithFields(logger.Fields{
				"Error":  fmt.Sprintf("%v", err),
				"UserID": userID,
			}).Errorf("Error: Failed to save beneficial owner")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to save beneficial owner", nil)
			return
		}
	}

	// Update user's KYB verification status to pending
	_, err = tx.User.
		Update().
		Where(user.IDEQ(userRecord.ID)).
		SetKybVerificationStatus(user.KybVerificationStatusPending).
		Save(ctx)
	if err != nil {
		if err := tx.Rollback(); err != nil {
			logger.Errorf("Failed to rollback transaction: %v", err)
		}
		logger.WithFields(logger.Fields{
			"Error":  fmt.Sprintf("%v", err),
			"UserID": userID,
		}).Errorf("Error: Failed to update user KYB verification status")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update user KYB verification status", nil)
		return
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		logger.WithFields(logger.Fields{
			"Error":  fmt.Sprintf("%v", err),
			"UserID": userID,
		}).Errorf("Error: Failed to commit transaction")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to process request", nil)
		return
	}

	// ✅ Send Slack notification (outside transaction)
	err = ctrl.slackService.SendSubmissionNotification(userRecord.FirstName, userRecord.Email, kybSubmission.ID.String())
	if err != nil {
		logger.Errorf("Webhook log: Error sending Slack notification for submission %s: %v", kybSubmission.ID, err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Error sending Slack notification", nil)
		return
	}

	u.APIResponse(ctx, http.StatusCreated, "success", "KYB submission submitted successfully", gin.H{
		"submission_id": kybSubmission.ID,
	})
}

// InsightWebhook handles the webhook callback from thirdweb insight, including signature verification and event processing
func (ctrl *Controller) InsightWebhook(ctx *gin.Context) {
	// Get raw body for signature verification
	rawBody, err := ctx.GetRawData()
	if err != nil {
		logger.Errorf("Error: InsightWebhook: Failed to read webhook payload: %v", err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
		return
	}

	// Get webhook signature and webhook ID from headers
	signature := ctx.GetHeader("x-webhook-signature")
	webhookID := ctx.GetHeader("x-webhook-id")
	if signature == "" || webhookID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing required headers"})
		return
	}

	// Verify webhook signature
	verification, err := ctrl.verifyWebhookSignature(string(rawBody), signature, webhookID)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":     err,
			"Signature": signature,
			"WebhookID": webhookID,
		}).Errorf("Error: InsightWebhook: Failed to verify signature")
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
		return
	}

	if !verification.IsValid {
		logger.WithFields(logger.Fields{
			"WebhookID": webhookID,
			"Signature": signature,
		}).Errorf("Error: InsightWebhook: Invalid signature")
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
		return
	}

	// Parse webhook payload
	var webhookPayload types.ThirdwebWebhookPayload
	if err := json.Unmarshal(rawBody, &webhookPayload); err != nil {
		logger.Errorf("Error: InsightWebhook: Failed to parse webhook payload: %v", err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload format"})
		return
	}

	// Verify payload age (optional - 10 minutes)
	if ctrl.isWebhookPayloadExpired(webhookPayload.Timestamp, int64(orderConf.ReceiveAddressValidity.Seconds())) {
		logger.WithFields(logger.Fields{
			"Timestamp":      webhookPayload.Timestamp,
			"Payload":        webhookPayload,
			"ValidityConfig": orderConf.ReceiveAddressValidity.Seconds(),
		}).Errorf("Error: InsightWebhook: Webhook payload expired")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Payload expired"})
		return
	}

	// Process webhook events
	err = ctrl.processWebhookEvents(ctx, webhookPayload)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":   err,
			"Payload": webhookPayload,
		}).Errorf("Error: InsightWebhook: Failed to process webhook events")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process events"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Webhook processed successfully"})
}

// verifyWebhookSignature verifies the webhook signature using the stored secret
func (ctrl *Controller) verifyWebhookSignature(rawBody, signature, webhookID string) (*types.WebhookSignatureVerification, error) {
	// Get webhook from database
	webhook, err := storage.Client.PaymentWebhook.
		Query().
		Where(paymentwebhook.WebhookIDEQ(webhookID)).
		First(context.Background())
	if err != nil {
		return nil, fmt.Errorf("webhook not found: %w", err)
	}

	// Generate expected signature
	expectedSignature := ctrl.generateWebhookSignature(rawBody, webhook.WebhookSecret)

	// Compare signatures using timing-safe comparison
	isValid := hmac.Equal([]byte(expectedSignature), []byte(signature))

	return &types.WebhookSignatureVerification{
		IsValid:   isValid,
		WebhookID: webhookID,
		Secret:    webhook.WebhookSecret,
	}, nil
}

// generateWebhookSignature generates HMAC-SHA256 signature for webhook verification
func (ctrl *Controller) generateWebhookSignature(rawBody, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(rawBody))
	return hex.EncodeToString(h.Sum(nil))
}

// isWebhookPayloadExpired checks if the webhook payload is older than the specified expiration time
func (ctrl *Controller) isWebhookPayloadExpired(timestamp int64, expirationInSeconds int64) bool {
	currentTime := time.Now().Unix()
	return currentTime-timestamp > expirationInSeconds
}

// processWebhookEvents processes the webhook events based on their type
func (ctrl *Controller) processWebhookEvents(ctx *gin.Context, payload types.ThirdwebWebhookPayload) error {
	for _, event := range payload.Data {
		// Handle reverted events (blockchain reorganization)
		if event.Status == "reverted" {
			if err := ctrl.handleRevertedEvent(ctx, event); err != nil {
				logger.WithFields(logger.Fields{
					"Error": err,
					"Event": event,
				}).Errorf("Error: InsightWebhook: Failed to handle reverted event")
				continue
			}
			continue
		}

		// Process new events
		if event.Status == "new" {
			if err := ctrl.handleNewEvent(ctx, event); err != nil {
				logger.WithFields(logger.Fields{
					"Error": err,
					"Event": event,
				}).Errorf("Error: InsightWebhook: Failed to handle new event")
				continue
			}
		}
	}

	return nil
}

// handleNewEvent processes a new webhook event
func (ctrl *Controller) handleNewEvent(ctx *gin.Context, event types.ThirdwebWebhookEvent) error {
	// Determine event type based on event signature (first topic)
	var eventSignature string
	if len(event.Data.Topics) > 0 {
		eventSignature = event.Data.Topics[0]
	}

	// Log the event signature for debugging
	logger.WithFields(logger.Fields{
		"EventSignature":   eventSignature,
		"EventName":        event.Data.Decoded.Name,
		"TxHash":           event.Data.TransactionHash,
		"BlockNumber":      event.Data.BlockNumber,
		"ChainId":          event.Data.ChainID,
		"Address":          event.Data.Address,
		"Topics":           event.Data.Topics,
		"Data":             event.Data.Data,
		"IndexedParams":    event.Data.Decoded.IndexedParams,
		"NonIndexedParams": event.Data.Decoded.NonIndexedParams,
	}).Infof("Processing webhook event")

	switch eventSignature {
	case utils.TransferEventSignature:
		return ctrl.handleTransferEvent(ctx, event)
	case utils.OrderCreatedEventSignature:
		return ctrl.handleOrderCreatedEvent(ctx, event)
	case utils.OrderSettledEventSignature:
		return ctrl.handleOrderSettledEvent(ctx, event)
	case utils.OrderRefundedEventSignature:
		return ctrl.handleOrderRefundedEvent(ctx, event)
	default:
		// Fallback to using decoded name if signature doesn't match
		switch event.Data.Decoded.Name {
		case "Transfer":
			return ctrl.handleTransferEvent(ctx, event)
		case "OrderCreated":
			return ctrl.handleOrderCreatedEvent(ctx, event)
		case "OrderSettled":
			return ctrl.handleOrderSettledEvent(ctx, event)
		case "OrderRefunded":
			return ctrl.handleOrderRefundedEvent(ctx, event)
		default:
			logger.WithFields(logger.Fields{
				"EventSignature": eventSignature,
				"EventName":      event.Data.Decoded.Name,
				"Event":          event,
			}).Errorf("Error: InsightWebhook: Unknown event type")
			return nil
		}
	}
}

// handleRevertedEvent handles reverted events by reverting any actions taken
func (ctrl *Controller) handleRevertedEvent(ctx *gin.Context, event types.ThirdwebWebhookEvent) error {
	// For now, just log the reverted event
	// In the future, this could implement rollback logic
	logger.Infof("Event reverted - txHash: %s, eventID: %s", event.Data.TransactionHash, event.ID)
	return nil
}

// handleTransferEvent processes Transfer events from webhook
func (ctrl *Controller) handleTransferEvent(ctx *gin.Context, event types.ThirdwebWebhookEvent) error {
	// Convert chain ID from string to int64
	chainID, err := strconv.ParseInt(event.Data.ChainID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid chain ID: %w", err)
	}

	// Get token from database
	token, err := storage.Client.Token.
		Query().
		Where(
			tokenEnt.ContractAddressEqualFold(event.Data.Address),
			tokenEnt.HasNetworkWith(
				networkent.ChainIDEQ(chainID),
			),
		).
		WithNetwork().
		Only(ctx)
	if err != nil {
		return fmt.Errorf("token not found: %w", err)
	}

	// Extract transfer data from decoded event
	indexedParams := event.Data.Decoded.IndexedParams
	nonIndexedParams := event.Data.Decoded.NonIndexedParams

	toAddress := ethcommon.HexToAddress(indexedParams["to"].(string)).Hex()
	fromAddress := ethcommon.HexToAddress(indexedParams["from"].(string)).Hex()
	valueStr := nonIndexedParams["value"].(string)

	// Skip if transfer is from gateway contract
	if strings.EqualFold(fromAddress, token.Edges.Network.GatewayContractAddress) {
		return nil
	}

	// Parse transfer value
	transferValue, err := decimal.NewFromString(valueStr)
	if err != nil {
		return fmt.Errorf("invalid transfer value: %w", err)
	}

	// Create transfer event
	transferEvent := &types.TokenTransferEvent{
		BlockNumber: event.Data.BlockNumber,
		TxHash:      event.Data.TransactionHash,
		From:        fromAddress,
		To:          toAddress,
		Value:       transferValue.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(token.Decimals)))),
	}

	// Process transfer using existing logic
	addressToEvent := map[string]*types.TokenTransferEvent{
		toAddress: transferEvent,
	}

	err = common.ProcessTransfers(ctx, ctrl.orderService, ctrl.priorityQueueService, []string{toAddress}, addressToEvent, token)
	if err != nil {
		return fmt.Errorf("failed to process transfer: %w", err)
	}

	return nil
}

// handleOrderCreatedEvent processes OrderCreated events from webhook
func (ctrl *Controller) handleOrderCreatedEvent(ctx *gin.Context, event types.ThirdwebWebhookEvent) error {
	// Convert chain ID from string to int64
	chainID, err := strconv.ParseInt(event.Data.ChainID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid chain ID: %w", err)
	}

	// Get network from database
	network, err := storage.Client.Network.
		Query().
		Where(networkent.ChainIDEQ(chainID)).
		Only(ctx)
	if err != nil {
		return fmt.Errorf("network not found: %w", err)
	}

	// Extract order data from decoded event
	indexedParams := event.Data.Decoded.IndexedParams
	nonIndexedParams := event.Data.Decoded.NonIndexedParams

	amount, err := decimal.NewFromString(indexedParams["amount"].(string))
	if err != nil {
		return fmt.Errorf("invalid amount: %w", err)
	}

	protocolFee, err := decimal.NewFromString(nonIndexedParams["protocolFee"].(string))
	if err != nil {
		return fmt.Errorf("invalid protocol fee: %w", err)
	}

	rate, err := decimal.NewFromString(nonIndexedParams["rate"].(string))
	if err != nil {
		return fmt.Errorf("invalid rate: %w", err)
	}

	// Create order created event
	orderEvent := &types.OrderCreatedEvent{
		BlockNumber: event.Data.BlockNumber,
		TxHash:      event.Data.TransactionHash,
		Token:       ethcommon.HexToAddress(indexedParams["token"].(string)).Hex(),
		Amount:      amount,
		ProtocolFee: protocolFee,
		OrderId:     nonIndexedParams["orderId"].(string),
		Rate:        rate.Div(decimal.NewFromInt(100)),
		MessageHash: nonIndexedParams["messageHash"].(string),
		Sender:      ethcommon.HexToAddress(indexedParams["sender"].(string)).Hex(),
	}

	// Process order using existing logic
	txHashes := []string{orderEvent.TxHash}
	hashToEvent := map[string]*types.OrderCreatedEvent{
		orderEvent.TxHash: orderEvent,
	}

	err = common.ProcessCreatedOrders(ctx, network, txHashes, hashToEvent, ctrl.orderService, ctrl.priorityQueueService)
	if err != nil {
		return fmt.Errorf("failed to process order: %w", err)
	}

	return nil
}

// handleOrderSettledEvent processes OrderSettled events from webhook
func (ctrl *Controller) handleOrderSettledEvent(ctx *gin.Context, event types.ThirdwebWebhookEvent) error {
	// Convert chain ID from string to int64
	chainID, err := strconv.ParseInt(event.Data.ChainID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid chain ID: %w", err)
	}

	// Get network from database
	network, err := storage.Client.Network.
		Query().
		Where(networkent.ChainIDEQ(chainID)).
		Only(ctx)
	if err != nil {
		return fmt.Errorf("network not found: %w", err)
	}

	// Extract order settled data from decoded event
	indexedParams := event.Data.Decoded.IndexedParams
	nonIndexedParams := event.Data.Decoded.NonIndexedParams

	settlePercent, err := decimal.NewFromString(nonIndexedParams["settlePercent"].(string))
	if err != nil {
		return fmt.Errorf("invalid settle percent: %w", err)
	}

	// Create order settled event
	settledEvent := &types.OrderSettledEvent{
		BlockNumber:       event.Data.BlockNumber,
		TxHash:            event.Data.TransactionHash,
		SplitOrderId:      nonIndexedParams["splitOrderId"].(string),
		OrderId:           indexedParams["orderId"].(string),
		LiquidityProvider: ethcommon.HexToAddress(indexedParams["liquidityProvider"].(string)).Hex(),
		SettlePercent:     settlePercent,
	}

	// Process settled order using existing logic
	lockOrder, err := storage.Client.LockPaymentOrder.
		Query().
		Where(lockpaymentorder.GatewayIDEQ(settledEvent.OrderId)).
		Only(ctx)
	if err != nil {
		return fmt.Errorf("lock payment order not found: %w", err)
	}

	err = common.UpdateOrderStatusSettled(ctx, network, settledEvent, lockOrder.MessageHash)
	if err != nil {
		return fmt.Errorf("failed to process settled order: %w", err)
	}

	return nil
}

// handleOrderRefundedEvent processes OrderRefunded events from webhook
func (ctrl *Controller) handleOrderRefundedEvent(ctx *gin.Context, event types.ThirdwebWebhookEvent) error {
	// Convert chain ID from string to int64
	chainID, err := strconv.ParseInt(event.Data.ChainID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid chain ID: %w", err)
	}

	// Get network from database
	network, err := storage.Client.Network.
		Query().
		Where(networkent.ChainIDEQ(chainID)).
		Only(ctx)
	if err != nil {
		return fmt.Errorf("network not found: %w", err)
	}

	// Extract order refunded data from decoded event
	indexedParams := event.Data.Decoded.IndexedParams
	nonIndexedParams := event.Data.Decoded.NonIndexedParams

	// Validate required parameters
	if indexedParams["orderId"] == nil {
		return fmt.Errorf("missing orderId in indexed params")
	}
	if nonIndexedParams["fee"] == nil {
		return fmt.Errorf("missing fee in non-indexed params")
	}

	fee, err := decimal.NewFromString(nonIndexedParams["fee"].(string))
	if err != nil {
		return fmt.Errorf("invalid fee: %w", err)
	}

	// Create order refunded event
	refundedEvent := &types.OrderRefundedEvent{
		BlockNumber: event.Data.BlockNumber,
		TxHash:      event.Data.TransactionHash,
		Fee:         fee,
		OrderId:     indexedParams["orderId"].(string),
	}

	// Process refunded order using existing logic
	lockOrder, err := storage.Client.LockPaymentOrder.
		Query().
		Where(lockpaymentorder.GatewayIDEQ(refundedEvent.OrderId)).
		Only(ctx)
	if err != nil {
		return fmt.Errorf("lock payment order not found: %w", err)
	}

	err = common.UpdateOrderStatusRefunded(ctx, network, refundedEvent, lockOrder.MessageHash)
	if err != nil {
		return fmt.Errorf("failed to process refunded order: %w", err)
	}

	return nil
}

// IndexTransaction controller indexes a specific transaction for blockchain events
func (ctrl *Controller) IndexTransaction(ctx *gin.Context) {
	// Get network from URL parameters
	networkParam := ctx.Param("network")

	// Get the second path param, which can be a tx_hash or an address
	pathParam := ctx.Param("tx_hash_or_address")

	// Get optional parameters from query string
	fromBlockStr := ctx.Query("from_block")
	toBlockStr := ctx.Query("to_block")

	// Determine if pathParam is a tx_hash or address based on length
	var txHash, address string
	if pathParam != "" && strings.HasPrefix(pathParam, "0x") {
		if len(pathParam) == 66 {
			txHash = pathParam
		} else if len(pathParam) == 42 {
			address = pathParam
		}
	}

	// Validate that pathParam is a valid tx_hash or address
	if pathParam == "" || !strings.HasPrefix(pathParam, "0x") {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid path parameter. Must be a valid transaction hash (66 chars) or address (42 chars)", nil)
		return
	}

	// Validate that at least one indexing method is provided
	if txHash == "" && address == "" && (fromBlockStr == "" || toBlockStr == "") {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Must provide either a valid transaction hash, address, or from_block/to_block range", nil)
		return
	}

	// Parse block range if provided
	var fromBlock, toBlock int64
	var blockErr error
	if fromBlockStr != "" {
		fromBlock, blockErr = strconv.ParseInt(fromBlockStr, 10, 64)
		if blockErr != nil {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid from_block format", nil)
			return
		}
	}
	if toBlockStr != "" {
		toBlock, blockErr = strconv.ParseInt(toBlockStr, 10, 64)
		if blockErr != nil {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid to_block format", nil)
			return
		}
	}

	// Validate block range if both are provided
	if fromBlockStr != "" && toBlockStr != "" && fromBlock >= toBlock {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "from_block must be less than to_block", nil)
		return
	}

	// Validate network based on server environment
	isTestnet := false
	if serverConf.Environment != "production" && serverConf.Environment != "staging" {
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

	// Create indexer instance based on network type
	var indexerInstance types.Indexer
	var indexerErr error
	if strings.HasPrefix(network.Identifier, "tron") {
		indexerInstance = indexer.NewIndexerTron()
	} else {
		indexerInstance, indexerErr = indexer.NewIndexerEVM()
		if indexerErr != nil {
			logger.WithFields(logger.Fields{
				"Error":        fmt.Sprintf("%v", indexerErr),
				"NetworkParam": networkParam,
			}).Errorf("Failed to create EVM indexer")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initialize indexer", nil)
			return
		}
	}

	// Track event counts
	eventCounts := struct {
		Transfer      int `json:"Transfer"`
		OrderCreated  int `json:"OrderCreated"`
		OrderSettled  int `json:"OrderSettled"`
		OrderRefunded int `json:"OrderRefunded"`
	}{}

	// Run indexing operations based on parameter type
	var wg sync.WaitGroup
	var eventCountsMutex sync.Mutex

	// If txHash is provided, index Gateway events (OrderCreated, OrderSettled, OrderRefunded)
	if txHash != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.WithFields(logger.Fields{
				"NetworkParam":   networkParam,
				"TxHash":         txHash,
				"GatewayAddress": network.GatewayContractAddress,
				"FromBlock":      fromBlock,
				"ToBlock":        toBlock,
				"EventType":      "Gateway",
			}).Infof("Starting Gateway event indexing for transaction")

			counts, err := indexerInstance.IndexGateway(ctx, network, network.GatewayContractAddress, fromBlock, toBlock, txHash)
			if err != nil && err.Error() != "no events found" {
				logger.WithFields(logger.Fields{
					"Error":          fmt.Sprintf("%v", err),
					"NetworkParam":   networkParam,
					"TxHash":         txHash,
					"GatewayAddress": network.GatewayContractAddress,
					"FromBlock":      fromBlock,
					"ToBlock":        toBlock,
					"EventType":      "Gateway",
				}).Errorf("Failed to index Gateway events")
			} else if err != nil && err.Error() == "no events found" {
				logger.WithFields(logger.Fields{
					"NetworkParam":   networkParam,
					"TxHash":         txHash,
					"GatewayAddress": network.GatewayContractAddress,
					"FromBlock":      fromBlock,
					"ToBlock":        toBlock,
					"EventType":      "Gateway",
				}).Infof("No Gateway events found for transaction")
			} else if err == nil && counts != nil {
				// Update event counts with actual counts from indexer
				eventCountsMutex.Lock()
				eventCounts.OrderCreated += counts.OrderCreated
				eventCounts.OrderSettled += counts.OrderSettled
				eventCounts.OrderRefunded += counts.OrderRefunded
				eventCountsMutex.Unlock()

				logger.WithFields(logger.Fields{
					"NetworkParam":   networkParam,
					"TxHash":         txHash,
					"GatewayAddress": network.GatewayContractAddress,
					"FromBlock":      fromBlock,
					"ToBlock":        toBlock,
					"EventType":      "Gateway",
					"OrderCreated":   counts.OrderCreated,
					"OrderSettled":   counts.OrderSettled,
					"OrderRefunded":  counts.OrderRefunded,
				}).Infof("Gateway event indexing completed successfully")
			}
		}()
	}

	// If address is provided, determine what type of indexing to perform
	if address != "" {
		logger.WithFields(logger.Fields{
			"NetworkParam": networkParam,
			"Address":      address,
			"FromBlock":    fromBlock,
			"ToBlock":      toBlock,
		}).Infof("Starting address-based indexing")

		// Check if the address is a gateway contract address
		if strings.EqualFold(address, network.GatewayContractAddress) {
			// Index Gateway events for the gateway contract address
			wg.Add(1)
			go func() {
				defer wg.Done()
				logger.WithFields(logger.Fields{
					"NetworkParam":   networkParam,
					"Address":        address,
					"GatewayAddress": network.GatewayContractAddress,
					"FromBlock":      fromBlock,
					"ToBlock":        toBlock,
					"EventType":      "Gateway",
				}).Infof("Starting Gateway event indexing for gateway contract address")

				counts, err := indexerInstance.IndexGateway(ctx, network, network.GatewayContractAddress, fromBlock, toBlock, "")
				if err != nil && err.Error() != "no events found" {
					logger.WithFields(logger.Fields{
						"Error":          fmt.Sprintf("%v", err),
						"NetworkParam":   networkParam,
						"Address":        address,
						"GatewayAddress": network.GatewayContractAddress,
						"FromBlock":      fromBlock,
						"ToBlock":        toBlock,
						"EventType":      "Gateway",
					}).Errorf("Failed to index Gateway events")
				} else if err != nil && err.Error() == "no events found" {
					logger.WithFields(logger.Fields{
						"NetworkParam":   networkParam,
						"Address":        address,
						"GatewayAddress": network.GatewayContractAddress,
						"FromBlock":      fromBlock,
						"ToBlock":        toBlock,
						"EventType":      "Gateway",
					}).Infof("No Gateway events found for gateway contract address")
				} else if err == nil && counts != nil {
					// Update event counts with actual counts from indexer
					eventCountsMutex.Lock()
					eventCounts.OrderCreated += counts.OrderCreated
					eventCounts.OrderSettled += counts.OrderSettled
					eventCounts.OrderRefunded += counts.OrderRefunded
					eventCountsMutex.Unlock()

					logger.WithFields(logger.Fields{
						"NetworkParam":   networkParam,
						"Address":        address,
						"GatewayAddress": network.GatewayContractAddress,
						"FromBlock":      fromBlock,
						"ToBlock":        toBlock,
						"EventType":      "Gateway",
						"OrderCreated":   counts.OrderCreated,
						"OrderSettled":   counts.OrderSettled,
						"OrderRefunded":  counts.OrderRefunded,
					}).Infof("Gateway event indexing completed successfully")
				}
			}()
		} else {
			// Check if the address is a receive address in the database
			receiveAddress, err := storage.Client.ReceiveAddress.
				Query().
				Where(receiveaddress.AddressEQ(address)).
				First(ctx)

			if err == nil && receiveAddress != nil {
				logger.WithFields(logger.Fields{
					"NetworkParam":     networkParam,
					"Address":          address,
					"ReceiveAddressID": receiveAddress.ID,
				}).Infof("Found receive address in database, starting transfer event indexing")

				// This is a receive address, index transfer events
				wg.Add(1)
				go func() {
					defer wg.Done()
					// Get a token for this network to use with IndexReceiveAddress
					token, err := storage.Client.Token.
						Query().
						Where(
							tokenEnt.IsEnabled(true),
							tokenEnt.HasNetworkWith(
								networkent.IDEQ(network.ID),
							),
						).
						WithNetwork().
						First(ctx)
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error":        fmt.Sprintf("%v", err),
							"NetworkParam": networkParam,
							"Address":      address,
						}).Errorf("Failed to get token for IndexReceiveAddress")
						return
					}

					logger.WithFields(logger.Fields{
						"NetworkParam": networkParam,
						"Address":      address,
						"Token":        token.Symbol,
						"TokenAddress": token.ContractAddress,
						"FromBlock":    fromBlock,
						"ToBlock":      toBlock,
						"EventType":    "ReceiveAddress",
					}).Infof("Starting transfer event indexing for receive address")

					counts, err := indexerInstance.IndexReceiveAddress(ctx, token, address, fromBlock, toBlock, txHash)
					if err != nil && err.Error() != "no events found" {
						logger.WithFields(logger.Fields{
							"Error":        fmt.Sprintf("%v", err),
							"NetworkParam": networkParam,
							"TxHash":       txHash,
							"Address":      address,
							"FromBlock":    fromBlock,
							"ToBlock":      toBlock,
							"EventType":    "ReceiveAddress",
						}).Errorf("Failed to index ReceiveAddress events")
					} else if err != nil && err.Error() == "no events found" {
						logger.WithFields(logger.Fields{
							"NetworkParam": networkParam,
							"Address":      address,
							"FromBlock":    fromBlock,
							"ToBlock":      toBlock,
							"EventType":    "ReceiveAddress",
						}).Infof("No transfer events found for receive address")
					} else if err == nil && counts != nil {
						// Update event counts with actual counts from indexer
						eventCountsMutex.Lock()
						eventCounts.Transfer += counts.Transfer
						eventCountsMutex.Unlock()

						logger.WithFields(logger.Fields{
							"NetworkParam": networkParam,
							"Address":      address,
							"FromBlock":    fromBlock,
							"ToBlock":      toBlock,
							"EventType":    "ReceiveAddress",
							"Transfer":     counts.Transfer,
						}).Infof("Transfer event indexing completed successfully")
					}
				}()
			} else {
				logger.WithFields(logger.Fields{
					"NetworkParam": networkParam,
					"Address":      address,
					"Error":        err,
				}).Errorf("Address not found in receive_addresses table")
				// Address not found in receive_addresses table, return error
				u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("Address %s is not a valid receive address or gateway contract address", address), nil)
				return
			}
		}
	}

	// Wait for all indexing operations to complete
	wg.Wait()

	response := types.IndexTransactionResponse{
		Events: eventCounts,
	}

	// Build response message based on what was indexed
	var responseMsg string
	if txHash != "" {
		responseMsg = fmt.Sprintf("Successfully indexed transaction %s for network %s", txHash, networkParam)
	} else if address != "" {
		responseMsg = fmt.Sprintf("Successfully indexed address %s for network %s", address, networkParam)
	} else {
		responseMsg = fmt.Sprintf("Successfully indexed block range %d-%d for network %s", fromBlock, toBlock, networkParam)
	}

	u.APIResponse(ctx, http.StatusOK, "success", responseMsg, response)
}

// IndexProviderAddress controller indexes provider addresses for OrderSettled events
func (ctrl *Controller) IndexProviderAddress(ctx *gin.Context) {
	var request struct {
		Network      string `json:"network" binding:"required"`
		ProviderID   string `json:"providerId" binding:"required"`
		TokenSymbol  string `json:"tokenSymbol" binding:"required"`
		CurrencyCode string `json:"currencyCode" binding:"required"`
		FromBlock    int64  `json:"fromBlock"`
		ToBlock      int64  `json:"toBlock"`
		TxHash       string `json:"txHash"`
	}

	if err := ctx.ShouldBindJSON(&request); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid request payload", nil)
		return
	}

	// Get network
	network, err := storage.Client.Network.
		Query().
		Where(networkent.IdentifierEQ(request.Network)).
		Only(ctx)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Network not found", nil)
		return
	}

	// Get token
	token, err := storage.Client.Token.
		Query().
		Where(
			tokenEnt.SymbolEQ(request.TokenSymbol),
			tokenEnt.HasNetworkWith(networkent.IDEQ(network.ID)),
		).
		WithNetwork().
		Only(ctx)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Token not found", nil)
		return
	}

	// Get provider order token to find the provider address
	providerOrderToken, err := storage.Client.ProviderOrderToken.
		Query().
		Where(
			providerordertoken.HasProviderWith(providerprofile.IDEQ(request.ProviderID)),
			providerordertoken.HasTokenWith(tokenEnt.IDEQ(token.ID)),
			providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(request.CurrencyCode)),
			providerordertoken.AddressNEQ(""),
		).
		Only(ctx)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Provider order token not found", nil)
		return
	}

	// Create indexer instance
	var indexerInstance types.Indexer
	if strings.HasPrefix(network.Identifier, "tron") {
		indexerInstance = indexer.NewIndexerTron()
	} else {
		indexerInstance, err = indexer.NewIndexerEVM()
		if err != nil {
			logger.Errorf("Failed to create indexer: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to create indexer", nil)
			return
		}
	}

	// Index provider address
	eventCounts, err := indexerInstance.IndexProviderAddress(ctx, network, providerOrderToken.Address, request.FromBlock, request.ToBlock, request.TxHash)
	if err != nil {
		logger.Errorf("Failed to index provider address: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to index provider address", nil)
		return
	}

	response := types.IndexTransactionResponse{
		Events: *eventCounts,
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Provider address indexed successfully", response)
}
