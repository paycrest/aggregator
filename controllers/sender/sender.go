package sender

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/paymentorderfulfillment"
	"github.com/paycrest/aggregator/ent/predicate"
	"github.com/paycrest/aggregator/ent/senderordertoken"
	"github.com/paycrest/aggregator/ent/senderprofile"
	tokenEnt "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/transactionlog"
	svc "github.com/paycrest/aggregator/services"
	orderSvc "github.com/paycrest/aggregator/services/order"
	"github.com/paycrest/aggregator/services/starknet"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	u "github.com/paycrest/aggregator/utils"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"

	"github.com/gin-gonic/gin"
)

// SenderController is a controller type for sender endpoints
type SenderController struct {
	receiveAddressService *svc.ReceiveAddressService
	orderService          types.OrderService
	starknetClient        *starknet.Client
}

// NewSenderController creates a new instance of SenderController
func NewSenderController() *SenderController {
	starknetClient, err := starknet.NewClient()
	if err != nil {
		starknetClient = nil
	}

	return &SenderController{
		receiveAddressService: svc.NewReceiveAddressService(),
		orderService:          orderSvc.NewOrderEVM(),
		starknetClient:        starknetClient,
	}
}

var (
	serverConf = config.ServerConfig()
	orderConf  = config.OrderConfig()
)

// InitiatePaymentOrder controller creates a payment order
func (ctrl *SenderController) InitiatePaymentOrder(ctx *gin.Context) {
	var payload types.NewPaymentOrderPayload

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	// Validate amount is greater than zero
	if payload.Amount.LessThanOrEqual(decimal.Zero) {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Amount",
			Message: "Amount must be greater than zero",
		})
		return
	}

	// Validate rate is greater than zero
	if payload.Rate.LessThanOrEqual(decimal.Zero) {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Rate",
			Message: "Rate must be greater than zero",
		})
		return
	}

	// Get sender profile from the context
	senderCtx, ok := ctx.Get("sender")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	sender := senderCtx.(*ent.SenderProfile)

	// Get API key from context and add to metadata
	apiKeyFromCtx, exists := ctx.Get("apiKey")
	if !exists {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}

	// Initialize metadata if nil and add API key
	if payload.Recipient.Metadata == nil {
		payload.Recipient.Metadata = make(map[string]interface{})
	}
	if apiKey, ok := apiKeyFromCtx.(string); ok {
		payload.Recipient.Metadata["apiKey"] = apiKey
	}

	// Get token from DB
	token, err := storage.Client.Token.
		Query().
		Where(
			tokenEnt.SymbolEQ(payload.Token),
			tokenEnt.HasNetworkWith(network.IdentifierEQ(payload.Network)),
			tokenEnt.IsEnabledEQ(true),
		).
		WithNetwork().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Token",
				Message: "Provided token is not supported",
			})
		} else {
			logger.Errorf("Failed to fetch token: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch token", nil)
		}
		return
	}

	// Handle sender profile overrides
	senderOrderToken, err := storage.Client.SenderOrderToken.
		Query().
		Where(
			senderordertoken.HasTokenWith(
				tokenEnt.IDEQ(token.ID),
			),
			senderordertoken.HasSenderWith(
				senderprofile.IDEQ(sender.ID),
			),
		).
		Only(ctx)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Token",
			Message: "Provided token is not configured",
		})
		return
	}

	if senderOrderToken.FeeAddress == "" || senderOrderToken.RefundAddress == "" {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Token",
			Message: "Fee address or refund address is not configured",
		})
		return
	}

	feePercent := senderOrderToken.FeePercent
	feeAddress := senderOrderToken.FeeAddress
	returnAddress := senderOrderToken.RefundAddress

	if payload.FeeAddress != "" {
		if !sender.IsPartner {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "FeeAddress",
				Message: "FeeAddress is not allowed",
			})
			return
		}

		if payload.FeePercent.IsZero() {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "FeePercent",
				Message: "FeePercent must be greater than zero",
			})
			return
		}

		if !strings.HasPrefix(payload.Network, "tron") {
			if !u.IsValidEthereumAddress(payload.FeeAddress) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "FeeAddress",
					Message: "Invalid Ethereum address",
				})
				return
			}
		} else {
			if !u.IsValidTronAddress(payload.FeeAddress) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "FeeAddress",
					Message: "Invalid Tron address",
				})
				return
			}
		}

		feePercent = payload.FeePercent
		feeAddress = payload.FeeAddress
	}

	if payload.ReturnAddress != "" {
		if !strings.HasPrefix(payload.Network, "tron") {
			if !u.IsValidEthereumAddress(payload.ReturnAddress) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "ReturnAddress",
					Message: "Invalid Ethereum address",
				})
				return
			}
		} else {
			if !u.IsValidTronAddress(payload.ReturnAddress) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "ReturnAddress",
					Message: "Invalid Tron address",
				})
				return
			}
		}
		returnAddress = payload.ReturnAddress
	}

	if payload.Reference != "" {
		if !regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`).MatchString(payload.Reference) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Reference",
				Message: "Reference must be alphanumeric",
			})
			return
		}

		referenceExists, err := storage.Client.PaymentOrder.
			Query().
			Where(
				paymentorder.ReferenceEQ(payload.Reference),
			).
			Exist(ctx)
		if err != nil {
			logger.Errorf("Reference check error: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", map[string]interface{}{
				"context": "reference_check",
			})
			return
		}

		if referenceExists {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Reference",
				Message: "Reference already exists",
			})
			return
		}
	}

	// Validate if institution exists
	institutionObj, err := storage.Client.Institution.
		Query().
		Where(
			institution.CodeEQ(payload.Recipient.Institution),
		).
		WithFiatCurrency(
			func(q *ent.FiatCurrencyQuery) {
				q.Where(fiatcurrency.IsEnabledEQ(true))
			},
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Recipient",
				Message: "Provided institution is not supported",
			})
		} else {
			logger.Errorf("Failed to fetch institution: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to validate institution", map[string]interface{}{
				"context": "institution_fetch",
			})
		}
		return
	}

	if !strings.EqualFold(token.BaseCurrency, institutionObj.Edges.FiatCurrency.Code) && !strings.EqualFold(token.BaseCurrency, "USD") {
		u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("%s can only be converted to %s", token.Symbol, token.BaseCurrency), nil)
		return
	}

	isLocalTransfer := strings.EqualFold(token.BaseCurrency, institutionObj.Edges.FiatCurrency.Code)
	if isLocalTransfer && feePercent.IsZero() {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "FeePercent",
			Message: fmt.Sprintf("Sender fee must be greater than zero for local currency order from (%s to %s)", token.Symbol, institutionObj.Edges.FiatCurrency.Code),
		})
		return
	}

	// Validate account and rate in parallel with fail fast logic before proceeding with order creation
	type AccountResult struct {
		accountName string
		err         error
	}

	type RateResult struct {
		rateResult u.RateValidationResult
		err        error
	}

	accountChan := make(chan AccountResult, 1)
	rateChan := make(chan RateResult, 1)

	go func() {
		accountName, err := u.ValidateAccount(ctx, payload.Recipient.Institution, payload.Recipient.AccountIdentifier)
		accountChan <- AccountResult{accountName, err}
	}()

	go func() {
		rateResult, err := u.ValidateRate(ctx, token, institutionObj.Edges.FiatCurrency, payload.Amount, payload.Recipient.ProviderID, payload.Network)
		rateChan <- RateResult{rateResult, err}
	}()

	var accountResult AccountResult
	var rateResult RateResult
	var completedCount int

	for completedCount < 2 {
		select {
		case accountResult = <-accountChan:
			completedCount++
			if accountResult.err != nil {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Recipient",
					Message: fmt.Sprintf("Account validation failed: %s", accountResult.err.Error()),
				})
				return
			}
		case rateResult = <-rateChan:
			completedCount++
			if rateResult.err != nil {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: fmt.Sprintf("Rate validation failed: %s", rateResult.err.Error()),
				})
				return
			}
		}
	}

	// Both validations successful
	payload.Recipient.AccountName = accountResult.accountName
	rateValidationResult := rateResult.rateResult
	achievableRate := rateValidationResult.Rate

	// Validate that the provided rate is achievable
	// Allow for a small tolerance (0.1%) to account for minor rate fluctuations
	tolerance := achievableRate.Mul(decimal.NewFromFloat(0.001)) // 0.1% tolerance
	if payload.Rate.LessThan(achievableRate.Sub(tolerance)) {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Rate",
			Message: fmt.Sprintf("Provided rate %s is not achievable. Available rate is %s", payload.Rate, achievableRate),
		})
		return
	}

	amountInUSD := u.CalculatePaymentOrderAmountInUSD(payload.Amount, token, institutionObj)

	// Use order type from ValidateRate result (already determined based on OTC limits)
	orderType := rateValidationResult.OrderType

	// Generate receive address
	var receiveAddress string
	var receiveAddressSalt []byte
	var receiveAddressExpiry time.Time

	if strings.HasPrefix(payload.Network, "tron") {
		address, salt, err := ctrl.receiveAddressService.CreateTronAddress(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"error":   err,
				"network": payload.Network,
			}).Errorf("Failed to create receive address")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", types.ErrorData{
				Field:   "Network",
				Message: "Tron currently not available",
			})
			return
		}

		receiveAddress = address
		receiveAddressSalt = salt
		receiveAddressExpiry = time.Now().Add(orderConf.ReceiveAddressValidity)
	} else if strings.HasPrefix(payload.Network, "starknet") {
		if ctrl.starknetClient == nil {
			logger.WithFields(logger.Fields{
				"error":   "Starknet client not initialized -- disable Starknet tokens if not in use",
				"network": payload.Network,
			}).Errorf("Failed to create receive address")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", types.ErrorData{
				Field:   "Network",
				Message: "Starknet currently not available",
			})
			return
		}

		address, salt, err := ctrl.receiveAddressService.CreateStarknetAddress(ctrl.starknetClient)
		if err != nil {
			logger.WithFields(logger.Fields{
				"error":   err,
				"network": payload.Network,
			}).Errorf("Failed to create receive address")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", types.ErrorData{
				Field:   "Network",
				Message: "Starknet currently not available",
			})
			return
		}
		receiveAddress = address
		receiveAddressSalt = salt
		receiveAddressExpiry = time.Now().Add(orderConf.ReceiveAddressValidity)
	} else {
		// Generate unique label for smart address
		uniqueLabel := fmt.Sprintf("payment_order_%d_%s", time.Now().UnixNano(), uuid.New().String()[:8])
		address, err := ctrl.receiveAddressService.CreateSmartAddress(ctx, uniqueLabel)
		if err != nil {
			logger.WithFields(logger.Fields{
				"error":   err,
				"network": payload.Network,
			}).Errorf("Failed to create receive address")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", types.ErrorData{
				Field:   "Network",
				Message: fmt.Sprintf("%s currently not available", payload.Network),
			})
			return
		}
		receiveAddress = address
		receiveAddressExpiry = time.Now().Add(orderConf.ReceiveAddressValidity)
	}

	// Set extended expiry for private orders (10x normal validity)
	if strings.HasPrefix(payload.Recipient.Memo, "P#P") {
		receiveAddressExpiry = time.Now().Add(10 * orderConf.ReceiveAddressValidity)
	}

	if serverConf.Environment == "production" || serverConf.Environment == "staging" {
		// Validate encrypted recipient size before creating order
		if err := cryptoUtils.ValidateRecipientEncryptionSize(&payload.Recipient); err != nil {
			logger.WithFields(logger.Fields{
				"error":       err,
				"institution": payload.Recipient.Institution,
			}).Errorf("Recipient encryption size validation failed")
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Recipient",
				Message: fmt.Sprintf("Recipient data too large: %s", err.Error()),
			})
			return
		}
	}

	// Create payment order and recipient in a transaction
	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		return
	}

	// Calculate fee based on percentage
	calculatedFee := feePercent.Mul(payload.Amount).Div(decimal.NewFromInt(100)).Round(4)

	// Apply max fee cap if configured (zero means no cap)
	senderFee := calculatedFee
	if senderOrderToken.MaxFeeCap.GreaterThan(decimal.Zero) {
		if calculatedFee.GreaterThan(senderOrderToken.MaxFeeCap) {
			senderFee = senderOrderToken.MaxFeeCap
		}
	}

	// Create transaction Log
	transactionLog, err := tx.TransactionLog.
		Create().
		SetStatus(transactionlog.StatusOrderInitiated).
		SetNetwork(token.Edges.Network.Identifier).
		Save(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		_ = tx.Rollback()
		return
	}

	// Create payment order with inlined recipient and receive address fields
	paymentOrderBuilder := tx.PaymentOrder.
		Create().
		SetSenderProfile(sender).
		SetAmount(payload.Amount).
		SetAmountInUsd(amountInUSD).
		SetNetworkFee(token.Edges.Network.Fee).
		SetSenderFee(senderFee).
		SetToken(token).
		SetRate(payload.Rate).
		SetReceiveAddress(receiveAddress).
		SetReceiveAddressExpiry(receiveAddressExpiry).
		SetFeePercent(feePercent).
		SetFeeAddress(feeAddress).
		SetReturnAddress(returnAddress).
		SetReference(payload.Reference).
		SetOrderType(orderType).
		SetInstitution(payload.Recipient.Institution).
		SetAccountIdentifier(payload.Recipient.AccountIdentifier).
		SetAccountName(payload.Recipient.AccountName).
		SetMemo(payload.Recipient.Memo).
		SetMetadata(payload.Recipient.Metadata).
		AddTransactions(transactionLog)

	// Set salt for Tron addresses
	if receiveAddressSalt != nil {
		paymentOrderBuilder = paymentOrderBuilder.SetReceiveAddressSalt(receiveAddressSalt)
	}

	paymentOrder, err := paymentOrderBuilder.Save(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		_ = tx.Rollback()
		return
	}

	// Create webhook for the smart address to monitor transfers (only for EVM networks)
	if !strings.HasPrefix(payload.Network, "tron") && !strings.HasPrefix(payload.Network, "starknet") {
		engineService := svc.NewEngineService()
		webhookID, webhookSecret, err := engineService.CreateTransferWebhook(
			ctx,
			token.Edges.Network.ChainID,
			token.ContractAddress,    // Token contract address
			receiveAddress,           // Smart address to monitor
			paymentOrder.ID.String(), // Order ID for webhook name
		)
		if err != nil {
			// Check if this is BNB Smart Chain (chain ID 56) or Lisk (chain ID 1135) which is not supported by Thirdweb
			if token.Edges.Network.ChainID != 56 && token.Edges.Network.ChainID != 1135 {
				logger.WithFields(logger.Fields{
					"ChainID": token.Edges.Network.ChainID,
					"Network": token.Edges.Network.Identifier,
					"Error":   err.Error(),
				}).Errorf("Failed to create transfer webhook: %v", err)
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
				_ = tx.Rollback()
				return
			}
		} else {
			// Create PaymentWebhook record in database only if webhook was created successfully
			_, err = tx.PaymentWebhook.
				Create().
				SetWebhookID(webhookID).
				SetWebhookSecret(webhookSecret).
				SetCallbackURL(fmt.Sprintf("%s/v1/insight/webhook", serverConf.ServerURL)).
				SetPaymentOrder(paymentOrder).
				Save(ctx)
			if err != nil {
				logger.Errorf("Failed to save payment webhook record: %v", err)
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
				_ = tx.Rollback()
				return
			}
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		return
	}

	u.APIResponse(ctx, http.StatusCreated, "success", "Payment order initiated successfully",
		&types.ReceiveAddressResponse{
			ID:             paymentOrder.ID,
			Amount:         paymentOrder.Amount,
			Token:          payload.Token,
			Network:        token.Edges.Network.Identifier,
			ReceiveAddress: receiveAddress,
			ValidUntil:     receiveAddressExpiry,
			SenderFee:      senderFee,
			TransactionFee: token.Edges.Network.Fee,
			Reference:      paymentOrder.Reference,
			OrderType:      string(orderType),
		})
}

// GetPaymentOrderByID controller fetches a payment order by ID
func (ctrl *SenderController) GetPaymentOrderByID(ctx *gin.Context) {
	// Get order ID from the URL
	orderID := ctx.Param("id")
	isUUID := true

	// Convert order ID to UUID
	id, err := uuid.Parse(orderID)
	if err != nil {
		isUUID = false
	}

	// Get sender profile from the context
	senderCtx, ok := ctx.Get("sender")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	sender := senderCtx.(*ent.SenderProfile)

	// Fetch payment order from the database

	paymentOrderQuery := storage.Client.PaymentOrder.Query()

	if isUUID {
		paymentOrderQuery = paymentOrderQuery.Where(paymentorder.IDEQ(id))
	} else {
		paymentOrderQuery = paymentOrderQuery.Where(paymentorder.ReferenceEQ(orderID))
	}

	paymentOrder, err := paymentOrderQuery.
		Where(paymentorder.HasSenderProfileWith(senderprofile.IDEQ(sender.ID))).
		WithProvider().
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithTransactions().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusNotFound, "error",
				"Payment order not found", nil)
		} else {
			logger.Errorf("error: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error",
				"Failed to fetch payment order", nil)
		}
		return
	}

	var transactions []types.TransactionLog
	for _, transaction := range paymentOrder.Edges.Transactions {
		transactions = append(transactions, types.TransactionLog{
			ID:        transaction.ID,
			GatewayId: transaction.GatewayID,
			Status:    transaction.Status,
			TxHash:    transaction.TxHash,
			CreatedAt: transaction.CreatedAt,
		})
	}

	institution, err := storage.Client.Institution.
		Query().
		Where(institution.CodeEQ(paymentOrder.Institution)).
		WithFiatCurrency().
		Only(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch payment order", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "The order has been successfully retrieved", &types.SenderOrderResponse{
		ID:             paymentOrder.ID,
		Amount:         paymentOrder.Amount,
		AmountInUSD:    paymentOrder.AmountInUsd,
		AmountPaid:     paymentOrder.AmountPaid,
		AmountReturned: paymentOrder.AmountReturned,
		Token:          paymentOrder.Edges.Token.Symbol,
		SenderFee:      paymentOrder.SenderFee,
		TransactionFee: paymentOrder.NetworkFee,
		Rate:           paymentOrder.Rate,
		Network:        paymentOrder.Edges.Token.Edges.Network.Identifier,
		Recipient: types.PaymentOrderRecipient{
			Currency:          institution.Edges.FiatCurrency.Code,
			Institution:       institution.Name,
			AccountIdentifier: paymentOrder.AccountIdentifier,
			AccountName:       paymentOrder.AccountName,
			ProviderID: func() string {
				if paymentOrder.Edges.Provider != nil {
					return paymentOrder.Edges.Provider.ID
				}
				return ""
			}(),
			Memo: paymentOrder.Memo,
		},
		Transactions:   transactions,
		FromAddress:    paymentOrder.FromAddress,
		ReturnAddress:  paymentOrder.ReturnAddress,
		ReceiveAddress: paymentOrder.ReceiveAddress,
		FeeAddress:     paymentOrder.FeeAddress,
		Reference:      paymentOrder.Reference,
		GatewayID:      paymentOrder.GatewayID,
		CreatedAt:      paymentOrder.CreatedAt,
		UpdatedAt:      paymentOrder.UpdatedAt,
		TxHash:         paymentOrder.TxHash,
		Status:         paymentOrder.Status,
		OrderType:      paymentOrder.OrderType,
	})
}

// GetPaymentOrders controller fetches all payment orders with support for search and export
func (ctrl *SenderController) GetPaymentOrders(ctx *gin.Context) {
	// Get sender profile from the context
	senderCtx, ok := ctx.Get("sender")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	sender := senderCtx.(*ent.SenderProfile)

	// Check if this is an export request
	export := ctx.Query("export")
	isExport := export == "csv" || export == "true"

	fromDateStr := ctx.Query("from")
	toDateStr := ctx.Query("to")

	// Check if this is a search request
	searchParam := ctx.Query("search")
	searchText := strings.TrimSpace(searchParam)
	hasSearchParam := ctx.Request.URL.Query().Has("search")
	isSearch := searchText != ""

	// Handle empty search query error
	if hasSearchParam && !isSearch {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Search query is required", nil)
		return
	}

	// Handle export request
	if isExport {
		if fromDateStr == "" || toDateStr == "" {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Both 'from' and 'to' date parameters are required for export", nil)
			return
		}
		ctrl.handleExportPaymentOrders(ctx, sender)
		return
	}

	// Handle search request
	if isSearch {
		ctrl.handleSearchPaymentOrders(ctx, sender, searchText)
		return
	}

	// Handle normal listing
	ctrl.handleListPaymentOrders(ctx, sender)
}

// handleListPaymentOrders handles normal payment order listing with pagination
func (ctrl *SenderController) handleListPaymentOrders(ctx *gin.Context, sender *ent.SenderProfile) {
	// Get ordering query param
	ordering := ctx.Query("ordering")
	order := ent.Desc(paymentorder.FieldCreatedAt)
	if ordering == "asc" {
		order = ent.Asc(paymentorder.FieldCreatedAt)
	}

	// Get page and pageSize query params
	page, offset, pageSize := u.Paginate(ctx)

	paymentOrderQuery := storage.Client.PaymentOrder.Query()

	// Filter by sender
	paymentOrderQuery = paymentOrderQuery.Where(
		paymentorder.HasSenderProfileWith(senderprofile.IDEQ(sender.ID)),
	)

	// Apply filters from query parameters
	paymentOrderQuery = ctrl.applyFilters(ctx, paymentOrderQuery)

	count, err := paymentOrderQuery.Count(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch payment orders", nil)
		return
	}

	// Fetch payment orders
	paymentOrders, err := paymentOrderQuery.
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		Limit(pageSize).
		Offset(offset).
		Order(order).
		All(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error",
			"Failed to fetch payment orders", nil)
		return
	}

	orders, err := ctrl.buildPaymentOrderResponses(ctx, paymentOrders)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch payment orders", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Payment orders retrieved successfully", types.SenderPaymentOrderList{
		Page:         page,
		PageSize:     pageSize,
		TotalRecords: count,
		Orders:       orders,
	})
}

// handleSearchPaymentOrders handles text search functionality for payment orders
func (ctrl *SenderController) handleSearchPaymentOrders(ctx *gin.Context, sender *ent.SenderProfile, searchText string) {
	// Build base query
	paymentOrderQuery := storage.Client.PaymentOrder.Query().Where(
		paymentorder.HasSenderProfileWith(senderprofile.IDEQ(sender.ID)),
	)

	// Apply text search across all relevant fields
	var searchPredicates []predicate.PaymentOrder

	// Try to parse search text as UUID for exact ID match
	if searchUUID, err := uuid.Parse(searchText); err == nil {
		searchPredicates = append(searchPredicates, paymentorder.IDEQ(searchUUID))
	}

	searchPredicates = append(searchPredicates,
		paymentorder.ReceiveAddressContainsFold(searchText),
		paymentorder.FromAddressContainsFold(searchText),
		paymentorder.ReturnAddressContainsFold(searchText),
		paymentorder.Or(
			paymentorder.AccountIdentifierContainsFold(searchText),
			paymentorder.AccountNameContainsFold(searchText),
			paymentorder.MemoContainsFold(searchText),
			paymentorder.InstitutionContainsFold(searchText),
		),
	)

	paymentOrderQuery = paymentOrderQuery.Where(
		paymentorder.Or(searchPredicates...),
	)

	// Get total count
	count, err := paymentOrderQuery.Count(ctx)
	if err != nil {
		logger.Errorf("Failed to count payment orders: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to search payment orders", nil)
		return
	}

	// Set reasonable limit to prevent memory issues
	maxSearchResults := 10000
	if count > maxSearchResults {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			fmt.Sprintf("Search returned too many results (%d). Maximum allowed is %d. Please use a more specific search term.",
				count, maxSearchResults), nil)
		return
	}

	// Execute query with default ordering (most recent first)
	paymentOrders, err := paymentOrderQuery.
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		Limit(maxSearchResults).
		Order(ent.Desc(paymentorder.FieldCreatedAt), ent.Desc(paymentorder.FieldID)).
		All(ctx)
	if err != nil {
		logger.Errorf("Failed to fetch payment orders: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to search payment orders", nil)
		return
	}

	orders, err := ctrl.buildPaymentOrderResponses(ctx, paymentOrders)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to search payment orders", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Payment orders found successfully", types.SenderPaymentOrderSearchList{
		TotalRecords: count,
		Orders:       orders,
	})
}

// handleExportPaymentOrders handles CSV export functionality
func (ctrl *SenderController) handleExportPaymentOrders(ctx *gin.Context, sender *ent.SenderProfile) {
	// Parse date range parameters
	fromDateStr := ctx.Query("from")
	toDateStr := ctx.Query("to")

	var fromDate, toDate *time.Time

	// Parse from date
	if fromDateStr != "" {
		parsedFromDate, err := time.Parse("2006-01-02", fromDateStr)
		if err != nil {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid from date format", types.ErrorData{
				Field:   "from",
				Message: "Expected format: YYYY-MM-DD",
			})
			return
		}
		fromDate = &parsedFromDate
	}

	// Parse to date
	if toDateStr != "" {
		parsedToDate, err := time.Parse("2006-01-02", toDateStr)
		if err != nil {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid to date format", types.ErrorData{
				Field:   "to",
				Message: "Expected format: YYYY-MM-DD",
			})
			return
		}
		// Set to end of day
		parsedToDate = parsedToDate.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
		toDate = &parsedToDate
	}

	// Validate date range - ensure fromDate is not after toDate
	if fromDate != nil && toDate != nil && fromDate.After(*toDate) {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid date range", types.ErrorData{
			Field:   "from",
			Message: "From date cannot be after to date",
		})
		return
	}

	// Build query
	paymentOrderQuery := storage.Client.PaymentOrder.Query().Where(
		paymentorder.HasSenderProfileWith(senderprofile.IDEQ(sender.ID)),
	)

	// Apply date filters if provided
	if fromDate != nil {
		paymentOrderQuery = paymentOrderQuery.Where(paymentorder.CreatedAtGTE(*fromDate))
	}
	if toDate != nil {
		paymentOrderQuery = paymentOrderQuery.Where(paymentorder.CreatedAtLTE(*toDate))
	}

	// Apply other filters from query parameters
	paymentOrderQuery = ctrl.applyFilters(ctx, paymentOrderQuery)

	// Parse and validate limit parameter for export
	limitStr := ctx.Query("limit")
	var limit int
	if limitStr != "" {
		parsedLimit, err := strconv.Atoi(limitStr)
		if err != nil || parsedLimit <= 0 {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid limit", types.ErrorData{
				Field:   "limit",
				Message: "Limit must be a positive integer",
			})
			return
		}
		limit = parsedLimit
	}

	// Get total count to validate export size
	count, err := paymentOrderQuery.Count(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to count payment orders", nil)
		return
	}

	// Check if no orders found in date range
	if count == 0 {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "No orders found in the specified date range", nil)
		return
	}

	// Validate export size against limit
	if limit > 0 && count > limit {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			fmt.Sprintf("Export too large. Found %d orders but limit is %d", count, limit), nil)
		return
	}

	// Fetch orders for export (no limit since we're exporting)
	paymentOrders, err := paymentOrderQuery.
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		Order(ent.Desc(paymentorder.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to export payment orders", nil)
		return
	}

	// Generate CSV and return as file download
	ctrl.generateCSVResponse(ctx, paymentOrders)
}

// applyFilters applies common filters to payment order query
func (ctrl *SenderController) applyFilters(ctx *gin.Context, query *ent.PaymentOrderQuery) *ent.PaymentOrderQuery {
	// Filter by status
	statusQueryParam := ctx.Query("status")
	statusMap := map[string]paymentorder.Status{
		"initiated": paymentorder.StatusInitiated,
		"pending":   paymentorder.StatusPending,
		"expired":   paymentorder.StatusExpired,
		"settled":   paymentorder.StatusSettled,
		"refunded":  paymentorder.StatusRefunded,
	}

	if status, ok := statusMap[statusQueryParam]; ok {
		query = query.Where(paymentorder.StatusEQ(status))
	}

	// Filter by token
	tokenQueryParam := ctx.Query("token")
	if tokenQueryParam != "" {
		tokenExists, err := storage.Client.Token.
			Query().
			Where(tokenEnt.SymbolEQ(tokenQueryParam)).
			Exist(ctx)
		if err != nil {
			logger.Errorf("error checking token existence: %v", err)
		} else if tokenExists {
			query = query.Where(
				paymentorder.HasTokenWith(tokenEnt.SymbolEQ(tokenQueryParam)),
			)
		}
	}

	// Filter by network
	networkQueryParam := ctx.Query("network")
	if networkQueryParam != "" {
		networkExists, err := storage.Client.Network.
			Query().
			Where(network.IdentifierEQ(networkQueryParam)).
			Exist(ctx)
		if err != nil {
			logger.Errorf("error checking network existence: %v", err)
		} else if networkExists {
			query = query.Where(
				paymentorder.HasTokenWith(
					tokenEnt.HasNetworkWith(network.IdentifierEQ(networkQueryParam)),
				),
			)
		}
	}

	return query
}

// buildPaymentOrderResponses converts ent PaymentOrder entities to API response format
func (ctrl *SenderController) buildPaymentOrderResponses(ctx *gin.Context, paymentOrders []*ent.PaymentOrder) ([]types.SenderOrderResponse, error) {
	// Batch fetch institutions to avoid N+1 queries
	institutionCodes := make(map[string]bool)
	for _, paymentOrder := range paymentOrders {
		institutionCodes[paymentOrder.Institution] = true
	}

	// Convert map keys to slice
	codes := make([]string, 0, len(institutionCodes))
	for code := range institutionCodes {
		codes = append(codes, code)
	}

	// Fetch all institutions in one query
	institutions, err := storage.Client.Institution.
		Query().
		Where(institution.CodeIn(codes...)).
		WithFiatCurrency().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch institutions: %v", err)
	}

	// Create institution lookup map
	institutionMap := make(map[string]*ent.Institution)
	for _, inst := range institutions {
		institutionMap[inst.Code] = inst
	}

	var orders []types.SenderOrderResponse
	for _, paymentOrder := range paymentOrders {
		institution, ok := institutionMap[paymentOrder.Institution]
		if !ok {
			logger.Errorf("Institution not found for code: %s", paymentOrder.Institution)
			continue
		}

		orders = append(orders, types.SenderOrderResponse{
			ID:             paymentOrder.ID,
			Amount:         paymentOrder.Amount,
			AmountInUSD:    paymentOrder.AmountInUsd,
			AmountPaid:     paymentOrder.AmountPaid,
			AmountReturned: paymentOrder.AmountReturned,
			Token:          paymentOrder.Edges.Token.Symbol,
			SenderFee:      paymentOrder.SenderFee,
			TransactionFee: paymentOrder.NetworkFee,
			Rate:           paymentOrder.Rate,
			Network:        paymentOrder.Edges.Token.Edges.Network.Identifier,
			Recipient: types.PaymentOrderRecipient{
				Currency:          institution.Edges.FiatCurrency.Code,
				Institution:       institution.Name,
				AccountIdentifier: paymentOrder.AccountIdentifier,
				AccountName:       paymentOrder.AccountName,
				ProviderID: func() string {
					if paymentOrder.Edges.Provider != nil {
						return paymentOrder.Edges.Provider.ID
					}
					return ""
				}(),
				Memo: paymentOrder.Memo,
			},
			FromAddress:    paymentOrder.FromAddress,
			ReturnAddress:  paymentOrder.ReturnAddress,
			ReceiveAddress: paymentOrder.ReceiveAddress,
			FeeAddress:     paymentOrder.FeeAddress,
			Reference:      paymentOrder.Reference,
			GatewayID:      paymentOrder.GatewayID,
			CreatedAt:      paymentOrder.CreatedAt,
			UpdatedAt:      paymentOrder.UpdatedAt,
			TxHash:         paymentOrder.TxHash,
			Status:         paymentOrder.Status,
			OrderType:      paymentOrder.OrderType,
		})
	}

	return orders, nil
}

// generateCSVResponse generates and sends CSV response for payment orders export
func (ctrl *SenderController) generateCSVResponse(ctx *gin.Context, paymentOrders []*ent.PaymentOrder) {
	// Batch fetch institutions to avoid N+1 queries
	institutionCodes := make(map[string]bool)
	for _, paymentOrder := range paymentOrders {
		institutionCodes[paymentOrder.Institution] = true
	}

	// Convert map keys to slice
	codes := make([]string, 0, len(institutionCodes))
	for code := range institutionCodes {
		codes = append(codes, code)
	}

	// Fetch all institutions in one query
	institutions, err := storage.Client.Institution.
		Query().
		Where(institution.CodeIn(codes...)).
		WithFiatCurrency().
		All(ctx)
	if err != nil {
		logger.Errorf("Failed to fetch institutions for export: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to export payment orders", nil)
		return
	}

	// Create institution lookup map
	institutionMap := make(map[string]*ent.Institution)
	for _, inst := range institutions {
		institutionMap[inst.Code] = inst
	}

	// Set CSV headers
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("payment_orders_%s.csv", timestamp)

	ctx.Header("Content-Type", "text/csv")
	ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	ctx.Header("X-Total-Count", strconv.Itoa(len(paymentOrders)))

	// Create CSV writer
	writer := csv.NewWriter(ctx.Writer)
	defer writer.Flush()

	// Write CSV header
	csvHeaders := []string{
		"Order ID",
		"Reference",
		"Token Amount",
		"Token",
		"Network",
		"Amount (USD)",
		"Rate",
		"Sender Fee",
		"Transaction Fee",
		"Status",
		"Recipient Institution",
		"Recipient Currency",
		"Recipient Account",
		"Recipient Name",
		"From Address",
		"Receive Address",
		"Return Address",
		"Fee Address",
		"Transaction Hash",
		"Created At",
		"Updated At",
	}

	if err := writer.Write(csvHeaders); err != nil {
		logger.Errorf("Failed to write CSV headers: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to export payment orders", nil)
		return
	}

	// Write data rows
	for _, paymentOrder := range paymentOrders {
		// Get institution from pre-fetched map
		institution := institutionMap[paymentOrder.Institution]
		if institution == nil {
			logger.Errorf("Institution not found for code: %s", paymentOrder.Institution)
			continue // Skip this row but continue with others
		}

		row := []string{
			paymentOrder.ID.String(),
			paymentOrder.Reference,
			paymentOrder.Amount.String(),
			paymentOrder.Edges.Token.Symbol,
			paymentOrder.Edges.Token.Edges.Network.Identifier,
			paymentOrder.AmountInUsd.String(),
			paymentOrder.Rate.String(),
			paymentOrder.SenderFee.String(),
			paymentOrder.NetworkFee.String(),
			string(paymentOrder.Status),
			institution.Name,
			institution.Edges.FiatCurrency.Code,
			paymentOrder.AccountIdentifier,
			paymentOrder.AccountName,
			paymentOrder.FromAddress,
			paymentOrder.ReceiveAddress,
			paymentOrder.ReturnAddress,
			paymentOrder.FeeAddress,
			paymentOrder.TxHash,
			paymentOrder.CreatedAt.Format("2006-01-02 15:04:05"),
			paymentOrder.UpdatedAt.Format("2006-01-02 15:04:05"),
		}

		if err := writer.Write(row); err != nil {
			logger.Errorf("Failed to write CSV row: %v", err)
			// Continue writing other rows
		}
	}

	// CSV is automatically sent as response through ctx.Writer
	logger.Infof("Successfully exported %d payment orders", len(paymentOrders))
}

// Stats controller fetches sender stats
func (ctrl *SenderController) Stats(ctx *gin.Context) {
	// Get sender profile from the context
	senderCtx, ok := ctx.Get("sender")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	sender := senderCtx.(*ent.SenderProfile)

	// Aggregate sender stats from db

	// Get USD volume
	var w []struct {
		Sum               decimal.Decimal
		SumFieldSenderFee decimal.Decimal
	}
	err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.HasSenderProfileWith(senderprofile.IDEQ(sender.ID)),
			paymentorder.HasTokenWith(tokenEnt.BaseCurrencyEQ("USD")),
			paymentorder.StatusEQ(paymentorder.StatusSettled),
		).
		Aggregate(
			ent.Sum(paymentorder.FieldAmount),
			ent.As(ent.Sum(paymentorder.FieldSenderFee), "SumFieldSenderFee"),
		).
		Scan(ctx, &w)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch sender stats", nil)
		return
	}

	// Get local stablecoin volume
	paymentOrders, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.HasSenderProfileWith(senderprofile.IDEQ(sender.ID)),
			paymentorder.HasTokenWith(tokenEnt.BaseCurrencyNEQ("USD")),
			paymentorder.StatusEQ(paymentorder.StatusSettled),
		).
		All(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch sender stats", nil)
		return
	}

	var localStablecoinSum decimal.Decimal
	var localStablecoinSenderFee decimal.Decimal

	// Convert local stablecoin volume to USD
	for _, paymentOrder := range paymentOrders {
		institution, err := u.GetInstitutionByCode(ctx, paymentOrder.Institution, false)
		if err != nil {
			logger.Errorf("error: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch sender stats", nil)
			return
		}

		paymentOrder.Amount = paymentOrder.Amount.Div(institution.Edges.FiatCurrency.MarketRate)
		if paymentOrder.SenderFee.GreaterThan(decimal.Zero) {
			paymentOrder.SenderFee = paymentOrder.SenderFee.Div(institution.Edges.FiatCurrency.MarketRate)
		}

		localStablecoinSum = localStablecoinSum.Add(paymentOrder.Amount)
		localStablecoinSenderFee = localStablecoinSenderFee.Add(paymentOrder.SenderFee)
	}

	count, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.HasSenderProfileWith(senderprofile.IDEQ(sender.ID)),
		).
		Count(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch sender stats", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Sender stats retrieved successfully", types.SenderStatsResponse{
		TotalOrders:      count,
		TotalOrderVolume: w[0].Sum.Add(localStablecoinSum),
		TotalFeeEarnings: w[0].SumFieldSenderFee.Add(localStablecoinSenderFee),
	})
}

// ValidateOrder controller validates an order (allows sender to validate fulfilled orders when they've received value)
func (ctrl *SenderController) ValidateOrder(ctx *gin.Context) {
	// Get sender profile from the context
	senderCtx, ok := ctx.Get("sender")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	sender := senderCtx.(*ent.SenderProfile)

	// Parse the PaymentOrder ID string into a UUID
	paymentOrderID, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Order ID": ctx.Param("id"),
		}).Errorf("Error parsing order ID: %v", err)
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid Order ID", nil)
		return
	}

	// Fetch payment order and verify it belongs to sender
	paymentOrder, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.IDEQ(paymentOrderID),
			paymentorder.HasSenderProfileWith(senderprofile.IDEQ(sender.ID)),
			paymentorder.StatusIn(paymentorder.StatusFulfilled, paymentorder.StatusValidated),
			paymentorder.OrderTypeEQ(paymentorder.OrderTypeOtc),
		).
		WithSenderProfile().
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithFulfillments(func(fq *ent.PaymentOrderFulfillmentQuery) {
			fq.Where(paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusSuccess))
		}).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusNotFound, "error", "Order not found or not eligible for validation", nil)
			return
		}
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Order ID": paymentOrderID.String(),
		}).Errorf("Failed to fetch payment order: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch order", nil)
		return
	}

	// Verify payment order has message hash
	if paymentOrder.MessageHash == "" {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Order message hash not found", nil)
		return
	}

	// Verify fulfillment exists and has success status
	if len(paymentOrder.Edges.Fulfillments) == 0 {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Order fulfillment not found or not successful", nil)
		return
	}

	fulfillment := paymentOrder.Edges.Fulfillments[0]
	if fulfillment.ValidationStatus != paymentorderfulfillment.ValidationStatusSuccess {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Order fulfillment must have success status", nil)
		return
	}

	// Check if order is already validated
	if paymentOrder.Status == paymentorder.StatusValidated {
		u.APIResponse(ctx, http.StatusOK, "success", "Order already validated", nil)
		return
	}

	// Start a database transaction to ensure consistency
	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":          fmt.Sprintf("%v", err),
			"PaymentOrderID": paymentOrderID.String(),
		}).Errorf("Failed to start transaction: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to validate order", nil)
		return
	}

	// Create transaction log within transaction
	transactionLog, err := tx.TransactionLog.Create().
		SetStatus(transactionlog.StatusOrderValidated).
		SetNetwork(paymentOrder.Edges.Token.Edges.Network.Identifier).
		Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":          fmt.Sprintf("%v", err),
			"PaymentOrderID": paymentOrderID.String(),
			"Network":        paymentOrder.Edges.Token.Edges.Network.Identifier,
		}).Errorf("Failed to create transaction log: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to validate order", nil)
		_ = tx.Rollback()
		return
	}

	// Update payment order status within transaction
	_, err = tx.PaymentOrder.
		Update().
		Where(paymentorder.IDEQ(paymentOrder.ID)).
		SetStatus(paymentorder.StatusValidated).
		AddTransactions(transactionLog).
		Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":          fmt.Sprintf("%v", err),
			"PaymentOrderID": paymentOrderID.String(),
		}).Errorf("Failed to update lock order status: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to validate order", nil)
		_ = tx.Rollback()
		return
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		logger.WithFields(logger.Fields{
			"Error":          fmt.Sprintf("%v", err),
			"PaymentOrderID": paymentOrderID.String(),
		}).Errorf("Failed to commit transaction: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to validate order", nil)
		return
	}

	// Clean up order exclude list from Redis (best effort, don't fail if it errors)
	orderKey := fmt.Sprintf("order_exclude_list_%s", paymentOrder.ID)
	_ = storage.RedisClient.Del(ctx, orderKey).Err()

	// Send webhook notification to sender
	err = u.SendPaymentOrderWebhook(ctx, paymentOrder)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":          fmt.Sprintf("%v", err),
			"PaymentOrderID": paymentOrderID.String(),
		}).Errorf("Failed to send webhook notification to sender: %v", err)
		// Don't fail the request if webhook fails
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Order validated successfully", nil)
}
