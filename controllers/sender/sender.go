package sender

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/storage"

	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	providerprofile "github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/receiveaddress"
	"github.com/paycrest/aggregator/ent/senderordertoken"
	"github.com/paycrest/aggregator/ent/senderprofile"
	tokenEnt "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/transactionlog"
	svc "github.com/paycrest/aggregator/services"
	orderSvc "github.com/paycrest/aggregator/services/order"
	"github.com/paycrest/aggregator/types"
	u "github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"

	"github.com/gin-gonic/gin"
)

// SenderController is a controller type for sender endpoints
type SenderController struct {
	receiveAddressService *svc.ReceiveAddressService
	orderService          types.OrderService
}

// NewSenderController creates a new instance of SenderController
func NewSenderController() *SenderController {

	return &SenderController{
		receiveAddressService: svc.NewReceiveAddressService(),
		orderService:          orderSvc.NewOrderEVM(),
	}
}

var serverConf = config.ServerConfig()
var orderConf = config.OrderConfig()

// InitiatePaymentOrder controller creates a payment order
func (ctrl *SenderController) InitiatePaymentOrder(ctx *gin.Context) {
	var payload types.NewPaymentOrderPayload

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	// Get sender profile from the context
	senderCtx, ok := ctx.Get("sender")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	sender := senderCtx.(*ent.SenderProfile)

	if !sender.IsActive && !serverConf.Debug {
		u.APIResponse(ctx, http.StatusForbidden, "error", "Your account is not active", nil)
		return
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
			logger.Errorf("error: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
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
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to validate institution", nil)
		}
		return
	}

	if !strings.EqualFold(token.BaseCurrency, institutionObj.Edges.FiatCurrency.Code) && !strings.EqualFold(token.BaseCurrency, "USD") {
		u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("%s can only be converted to %s", token.Symbol, token.BaseCurrency), nil)
		return
	}

	if payload.Recipient.ProviderID != "" {
		orderToken, err := storage.Client.ProviderOrderToken.
			Query().
			Where(
				providerordertoken.NetworkEQ(token.Edges.Network.Identifier),
				providerordertoken.HasProviderWith(
					providerprofile.IDEQ(payload.Recipient.ProviderID),
				),
				providerordertoken.HasTokenWith(
					tokenEnt.IDEQ(token.ID),
				),
				providerordertoken.HasCurrencyWith(
					fiatcurrency.CodeEQ(institutionObj.Edges.FiatCurrency.Code),
				),
			).
			WithProvider().
			Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Recipient",
					Message: "The specified provider does not support the selected token",
				})
			} else {
				logger.Errorf("Failed to fetch provider settings: %v", err)
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch provider settings", nil)
			}
			return
		}

		// Validate amount for private orders
		if orderToken.Edges.Provider.VisibilityMode == providerprofile.VisibilityModePrivate {
			normalizedAmount := payload.Amount
			if strings.EqualFold(token.BaseCurrency, institutionObj.Edges.FiatCurrency.Code) && token.BaseCurrency != "USD" {
				rateResponse, err := u.GetTokenRateFromQueue("USDT", normalizedAmount, institutionObj.Edges.FiatCurrency.Code, institutionObj.Edges.FiatCurrency.MarketRate)
				if err != nil {
					logger.Errorf("InitiatePaymentOrder.GetTokenRateFromQueue: %v", err)
					u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
					return
				}
				normalizedAmount = payload.Amount.Div(rateResponse)
			}

			if normalizedAmount.LessThan(orderToken.MinOrderAmount) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "The amount is below the minimum order amount for the specified provider", nil)
				return
			} else if normalizedAmount.GreaterThan(orderToken.MaxOrderAmount) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "The amount is beyond the maximum order amount for the specified provider", nil)
				return
			}
		}
	}

	// Generate receive address
	var receiveAddress *ent.ReceiveAddress
	if strings.HasPrefix(payload.Network, "tron") {
		address, salt, err := ctrl.receiveAddressService.CreateTronAddress(ctx)
		if err != nil {
			logger.Errorf("error: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
			return
		}

		receiveAddress, err = storage.Client.ReceiveAddress.
			Create().
			SetAddress(address).
			SetSalt(salt).
			SetStatus(receiveaddress.StatusUnused).
			SetValidUntil(time.Now().Add(orderConf.ReceiveAddressValidity)).
			Save(ctx)
		if err != nil {
			logger.Errorf("error: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
			return
		}
	} else {
		address, err := ctrl.receiveAddressService.CreateSmartAddress(ctx, "")
		if err != nil {
			logger.Errorf("error: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
			return
		}

		receiveAddress, err = storage.Client.ReceiveAddress.
			Create().
			SetAddress(address).
			SetStatus(receiveaddress.StatusUnused).
			SetValidUntil(time.Now().Add(orderConf.ReceiveAddressValidity)).
			Save(ctx)
		if err != nil {
			logger.Errorf("error: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
			return
		}

	}

	// Prevent receive address expiry for private orders
	if strings.HasPrefix(payload.Recipient.Memo, "P#P") {
		receiveAddress.ValidUntil = time.Time{}
	}

	// Create payment order and recipient in a transaction
	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		return
	}

	senderFee := feePercent.Mul(payload.Amount).Div(decimal.NewFromInt(100)).Round(4)
	protocolFee := decimal.NewFromFloat(0)

	// Create transaction Log
	transactionLog, err := tx.TransactionLog.
		Create().
		SetStatus(transactionlog.StatusOrderInitiated).
		SetMetadata(
			map[string]interface{}{
				"ReceiveAddress": receiveAddress.Address,
				"SenderID":       sender.ID.String(),
			},
		).SetNetwork(token.Edges.Network.Identifier).
		Save(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		_ = tx.Rollback()
		return
	}

	// Create payment order
	paymentOrder, err := tx.PaymentOrder.
		Create().
		SetSenderProfile(sender).
		SetAmount(payload.Amount).
		SetAmountPaid(decimal.NewFromInt(0)).
		SetAmountReturned(decimal.NewFromInt(0)).
		SetPercentSettled(decimal.NewFromInt(0)).
		SetNetworkFee(token.Edges.Network.Fee).
		SetProtocolFee(protocolFee).
		SetSenderFee(senderFee).
		SetToken(token).
		SetRate(payload.Rate).
		SetReceiveAddress(receiveAddress).
		SetReceiveAddressText(receiveAddress.Address).
		SetFeePercent(feePercent).
		SetFeeAddress(feeAddress).
		SetReturnAddress(returnAddress).
		SetReference(payload.Reference).
		AddTransactions(transactionLog).
		Save(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		_ = tx.Rollback()
		return
	}

	// Create webhook for the smart address to monitor transfers (only for EVM networks)
	if !strings.HasPrefix(payload.Network, "tron") {
		engineService := svc.NewEngineService()
		webhookID, webhookSecret, err := engineService.CreateTransferWebhook(
			ctx,
			token.Edges.Network.ChainID,
			token.ContractAddress,    // Token contract address
			receiveAddress.Address,   // Smart address to monitor
			paymentOrder.ID.String(), // Order ID for webhook name
		)
		if err != nil {
			logger.Errorf("Failed to create transfer webhook: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
			_ = tx.Rollback()
			return
		}

		// Create PaymentWebhook record in database
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

	// Create payment order recipient
	_, err = tx.PaymentOrderRecipient.
		Create().
		SetInstitution(payload.Recipient.Institution).
		SetAccountIdentifier(payload.Recipient.AccountIdentifier).
		SetAccountName(payload.Recipient.AccountName).
		SetProviderID(payload.Recipient.ProviderID).
		SetMemo(payload.Recipient.Memo).
		SetMetadata(payload.Recipient.Metadata).
		SetPaymentOrder(paymentOrder).
		Save(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		_ = tx.Rollback()
		return
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
			ReceiveAddress: receiveAddress.Address,
			ValidUntil:     receiveAddress.ValidUntil,
			SenderFee:      senderFee,
			TransactionFee: protocolFee.Add(token.Edges.Network.Fee),
			Reference:      paymentOrder.Reference,
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
		WithRecipient().
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
		Where(institution.CodeEQ(paymentOrder.Edges.Recipient.Institution)).
		WithFiatCurrency().
		Only(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch payment order", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "The order has been successfully retrieved", &types.PaymentOrderResponse{
		ID:             paymentOrder.ID,
		Amount:         paymentOrder.Amount,
		AmountPaid:     paymentOrder.AmountPaid,
		AmountReturned: paymentOrder.AmountReturned,
		Token:          paymentOrder.Edges.Token.Symbol,
		SenderFee:      paymentOrder.SenderFee,
		TransactionFee: paymentOrder.NetworkFee.Add(paymentOrder.ProtocolFee),
		Rate:           paymentOrder.Rate,
		Network:        paymentOrder.Edges.Token.Edges.Network.Identifier,
		Recipient: types.PaymentOrderRecipient{
			Currency:          institution.Edges.FiatCurrency.Code,
			Institution:       institution.Name,
			AccountIdentifier: paymentOrder.Edges.Recipient.AccountIdentifier,
			AccountName:       paymentOrder.Edges.Recipient.AccountName,
			ProviderID:        paymentOrder.Edges.Recipient.ProviderID,
			Memo:              paymentOrder.Edges.Recipient.Memo,
		},
		Transactions:   transactions,
		FromAddress:    paymentOrder.FromAddress,
		ReturnAddress:  paymentOrder.ReturnAddress,
		ReceiveAddress: paymentOrder.ReceiveAddressText,
		FeeAddress:     paymentOrder.FeeAddress,
		Reference:      paymentOrder.Reference,
		GatewayID:      paymentOrder.GatewayID,
		CreatedAt:      paymentOrder.CreatedAt,
		UpdatedAt:      paymentOrder.UpdatedAt,
		TxHash:         paymentOrder.TxHash,
		Status:         paymentOrder.Status,
	})
}

// GetPaymentOrders controller fetches all payment orders
func (ctrl *SenderController) GetPaymentOrders(ctx *gin.Context) {
	// Get sender profile from the context
	senderCtx, ok := ctx.Get("sender")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	sender := senderCtx.(*ent.SenderProfile)

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
		paymentOrderQuery = paymentOrderQuery.Where(
			paymentorder.StatusEQ(status),
		)
	}

	// Filter by token
	tokenQueryParam := ctx.Query("token")

	if tokenQueryParam != "" {
		tokenExists, err := storage.Client.Token.
			Query().
			Where(
				tokenEnt.SymbolEQ(tokenQueryParam),
			).
			Exist(ctx)
		if err != nil {
			logger.Errorf("error: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error",
				"Failed to fetch payment orders", nil)
			return
		}

		if tokenExists {
			paymentOrderQuery = paymentOrderQuery.Where(
				paymentorder.HasTokenWith(
					tokenEnt.SymbolEQ(tokenQueryParam),
				),
			)
		}
	}

	// Filter by network
	networkQueryParam := ctx.Query("network")

	if networkQueryParam != "" {
		networkExists, err := storage.Client.Network.
			Query().
			Where(
				network.IdentifierEQ(networkQueryParam),
			).
			Exist(ctx)
		if err != nil {
			logger.Errorf("error: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error",
				"Failed to fetch payment orders", nil)
			return
		}

		if networkExists {
			paymentOrderQuery = paymentOrderQuery.Where(
				paymentorder.HasTokenWith(
					tokenEnt.HasNetworkWith(
						network.IdentifierEQ(networkQueryParam),
					),
				),
			)
		}
	}

	count, err := paymentOrderQuery.Count(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch payment orders", nil)
		return
	}

	// Fetch payment orders
	paymentOrders, err := paymentOrderQuery.
		WithRecipient().
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

	var orders []types.PaymentOrderResponse

	for _, paymentOrder := range paymentOrders {
		institution, err := storage.Client.Institution.
			Query().
			Where(institution.CodeEQ(paymentOrder.Edges.Recipient.Institution)).
			WithFiatCurrency().
			Only(ctx)
		if err != nil {
			logger.Errorf("error: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch payment orders", nil)
			return
		}

		orders = append(orders, types.PaymentOrderResponse{
			ID:             paymentOrder.ID,
			Amount:         paymentOrder.Amount,
			AmountPaid:     paymentOrder.AmountPaid,
			AmountReturned: paymentOrder.AmountReturned,
			Token:          paymentOrder.Edges.Token.Symbol,
			SenderFee:      paymentOrder.SenderFee,
			TransactionFee: paymentOrder.NetworkFee.Add(paymentOrder.ProtocolFee),
			Rate:           paymentOrder.Rate,
			Network:        paymentOrder.Edges.Token.Edges.Network.Identifier,
			Recipient: types.PaymentOrderRecipient{
				Currency:          institution.Edges.FiatCurrency.Code,
				Institution:       institution.Name,
				AccountIdentifier: paymentOrder.Edges.Recipient.AccountIdentifier,
				AccountName:       paymentOrder.Edges.Recipient.AccountName,
				ProviderID:        paymentOrder.Edges.Recipient.ProviderID,
				Memo:              paymentOrder.Edges.Recipient.Memo,
			},
			FromAddress:    paymentOrder.FromAddress,
			ReturnAddress:  paymentOrder.ReturnAddress,
			ReceiveAddress: paymentOrder.ReceiveAddressText,
			FeeAddress:     paymentOrder.FeeAddress,
			Reference:      paymentOrder.Reference,
			GatewayID:      paymentOrder.GatewayID,
			CreatedAt:      paymentOrder.CreatedAt,
			UpdatedAt:      paymentOrder.UpdatedAt,
			TxHash:         paymentOrder.TxHash,
			Status:         paymentOrder.Status,
		})
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Payment orders retrieved successfully", types.SenderPaymentOrderList{
		Page:         page,
		PageSize:     pageSize,
		TotalRecords: count,
		Orders:       orders,
	})
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
		WithRecipient().
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
		institution, err := u.GetInstitutionByCode(ctx, paymentOrder.Edges.Recipient.Institution, false)
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
