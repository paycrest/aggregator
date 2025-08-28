package sender

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/receiveaddress"
	"github.com/paycrest/aggregator/ent/senderordertoken"
	"github.com/paycrest/aggregator/ent/senderprofile"
	tokenEnt "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/transactionlog"

	svc "github.com/paycrest/aggregator/services"
	orderSvc "github.com/paycrest/aggregator/services/order"
	"github.com/paycrest/aggregator/storage"
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

	// Validate and normalize payload
	orderType, err := ctrl.validateAndNormalizePayload(&payload)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", err)
		return
	}

	// Validate reference if provided
	if err := ctrl.validateReference(ctx, payload.Reference); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", err)
		return
	}

	// Get token information
	token, ErrorData := ctrl.getTokenInfo(ctx, &payload)
	if err != nil {
		if ent.IsNotFound(ErrorData) {
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

	// Get institution information
	institutionObj, ErrorData := ctrl.getInstitutionInfo(ctx, &payload)
	if err != nil {
		if ent.IsNotFound(ErrorData) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Institution",
				Message: "Provided institution is not supported",
			})
		} else {
			logger.Errorf("Failed to fetch institution: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to validate institution", nil)
		}
		return
	}

	// Validate provider configuration if specified
	if err := ctrl.validateProviderConfiguration(ctx, token, institutionObj, &payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", err)
		return
	}

	// Route to appropriate handler based on order type
	switch orderType {
	case "onramp":
		ctrl.handleOnrampOrder(ctx, payload, sender, token, institutionObj)
	case "offramp":
		ctrl.handleOfframpOrder(ctx, payload, sender, token, institutionObj)
	default:
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid order type", nil)
	}
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
		TransactionFee: paymentOrder.NetworkFee,
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
			TransactionFee: paymentOrder.NetworkFee,
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


// validateAndNormalizePayload validates the payload and determines order type
func (ctrl *SenderController) validateAndNormalizePayload(payload *types.NewPaymentOrderPayload) (string, *types.ErrorData) {
	// Determine order type
	if payload.Source.Type != "" && payload.Destination.Type != "" {
		// New unified format
		if payload.Source.Type == "fiat" && payload.Destination.Type == "crypto" {
			return "onramp", nil
		} else if payload.Source.Type == "crypto" && payload.Destination.Type == "fiat" {
			return "offramp", nil
		} else {
			return "", &types.ErrorData{
				Field:   "Source/Destination",
				Message: "Invalid order type combination",
			}
		}
	} else if payload.Token != "" && payload.Network != "" {
		// Legacy offramp format
		return "offramp", nil
	} else {
		return "", &types.ErrorData{
			Field:   "Payload",
			Message: "Missing required fields for order type determination",
		}
	}
}

// validateReference validates the reference field
func (ctrl *SenderController) validateReference(ctx *gin.Context, reference string) *types.ErrorData {
	if reference == "" {
		return nil
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`).MatchString(reference) {
		return &types.ErrorData{
			Field:   "Reference",
			Message: "Reference must be alphanumeric",
		}
	}

	referenceExists, err := storage.Client.PaymentOrder.
		Query().
		Where(paymentorder.ReferenceEQ(reference)).
		Exist(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		return &types.ErrorData{
			Field:   "Reference",
			Message: "Failed to validate reference",
		}
	}

	if referenceExists {
		return &types.ErrorData{
			Field:   "Reference",
			Message: "Reference already exists",
		}
	}

	return nil
}

// validateOnrampFields validates onramp-specific payload fields
func (ctrl *SenderController) validateOnrampFields(payload types.NewPaymentOrderPayload) *types.ErrorData {
	if payload.Source.Type != "fiat" || payload.Destination.Type != "crypto" {
		return &types.ErrorData{
			Field:   "Source/Destination",
			Message: "Invalid onramp order types",
		}
	}

	if payload.Source.Currency == "" {
		return &types.ErrorData{
			Field:   "Source.Currency",
			Message: "Source currency is required for onramp orders",
		}
	}

	if payload.Destination.Currency == "" {
		return &types.ErrorData{
			Field:   "Destination.Currency",
			Message: "Destination currency is required for onramp orders",
		}
	}

	if payload.Destination.Recipient.Address == "" {
		return &types.ErrorData{
			Field:   "Destination.Recipient.Address",
			Message: "Destination address is required for onramp orders",
		}
	}

	if payload.Amount.IsZero() || payload.Amount.IsNegative() {
		return &types.ErrorData{
			Field:   "Amount",
			Message: "Amount must be greater than zero",
		}
	}

	// Validate destination address format
	network := payload.Destination.Recipient.PaymentRail
	if !ctrl.validateCryptoAddress(payload.Destination.Recipient.Address, network) {
		return &types.ErrorData{
			Field:   "Destination.Recipient.Address",
			Message: "Invalid destination address format",
		}
	}

	return nil
}

// getTokenInfo retrieves token information based on payload
func (ctrl *SenderController) getTokenInfo(ctx *gin.Context, payload *types.NewPaymentOrderPayload) (*ent.Token, error) {
	var tokenSymbol, networkIdentifier string

	if payload.Source.Type == "crypto" {
		tokenSymbol = payload.Source.Currency
		networkIdentifier = payload.Source.PaymentRail
	} else if payload.Destination.Type == "crypto" {
		tokenSymbol = payload.Destination.Currency
		networkIdentifier = payload.Destination.Recipient.PaymentRail
	} else {
		// Legacy format
		tokenSymbol = payload.Token
		networkIdentifier = payload.Network
	}

	return storage.Client.Token.
		Query().
		Where(
			tokenEnt.SymbolEQ(tokenSymbol),
			tokenEnt.HasNetworkWith(network.IdentifierEQ(networkIdentifier)),
			tokenEnt.IsEnabledEQ(true),
		).
		WithNetwork().
		Only(ctx)
}

// getInstitutionInfo retrieves institution information
func (ctrl *SenderController) getInstitutionInfo(ctx *gin.Context, payload *types.NewPaymentOrderPayload) (*ent.Institution, error) {
	var institutionCode string

	if payload.Source.Type == "fiat" {
		institutionCode = payload.Source.RefundAccount.Institution
	} else if payload.Destination.Type == "fiat" {
		institutionCode = payload.Destination.Recipient.Institution
	} else {
		// Legacy format
		institutionCode = payload.Recipient.Institution
	}

	return storage.Client.Institution.
		Query().
		Where(institution.CodeEQ(institutionCode)).
		WithFiatCurrency(func(q *ent.FiatCurrencyQuery) {
			q.Where(fiatcurrency.IsEnabledEQ(true))
		}).
		First(ctx)
}

// validateProviderConfiguration validates provider settings
func (ctrl *SenderController) validateProviderConfiguration(ctx *gin.Context, token *ent.Token, institutionObj *ent.Institution, payload *types.NewPaymentOrderPayload) *types.ErrorData {
	var providerID string

	if payload.Source.Type == "crypto" {
		providerID = payload.Destination.ProviderID
	} else if payload.Destination.Type == "crypto" {
		providerID = payload.Destination.ProviderID
	} else {
		// Legacy format
		providerID = payload.Recipient.ProviderID
	}

	if providerID == "" {
		return nil
	}

	orderToken, err := storage.Client.ProviderOrderToken.
		Query().
		Where(
			providerordertoken.NetworkEQ(token.Edges.Network.Identifier),
			providerordertoken.HasProviderWith(providerprofile.IDEQ(providerID)),
			providerordertoken.HasTokenWith(tokenEnt.IDEQ(token.ID)),
			providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(institutionObj.Edges.FiatCurrency.Code)),
		).
		WithProvider().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return &types.ErrorData{
				Field:   "Provider",
				Message: "The specified provider does not support the selected token",
			}
		} else {
			logger.Errorf("Failed to fetch provider settings: %v", err)
			return &types.ErrorData{
				Field:   "Provider",
				Message: "Failed to validate provider settings",
			}
		}
	}

	// Validate amount limits for private providers
	if orderToken.Edges.Provider.VisibilityMode == providerprofile.VisibilityModePrivate {
		normalizedAmount := payload.Amount
		if strings.EqualFold(token.BaseCurrency, institutionObj.Edges.FiatCurrency.Code) && token.BaseCurrency != "USD" {
			rateResponse, err := u.GetTokenRateFromQueue("USDT", normalizedAmount, institutionObj.Edges.FiatCurrency.Code, institutionObj.Edges.FiatCurrency.MarketRate)
			if err != nil {
				logger.Errorf("GetTokenRateFromQueue error: %v", err)
				return &types.ErrorData{
					Field:   "Amount",
					Message: "Failed to validate amount",
				}
			}
			normalizedAmount = payload.Amount.Div(rateResponse)
		}

		if normalizedAmount.LessThan(orderToken.MinOrderAmount) {
			return &types.ErrorData{
				Field:   "Amount",
				Message: "Amount is below the minimum order amount for the specified provider",
			}
		}
		if normalizedAmount.GreaterThan(orderToken.MaxOrderAmount) {
			return &types.ErrorData{
				Field:   "Amount",
				Message: "Amount exceeds the maximum order amount for the specified provider",
			}
		}
	}

	return nil
}

type AccountResult struct {
	accountName string
	err         error
}

type RateResult struct {
	achievableRate decimal.Decimal
	err            error
}
// validateAccountAndRate performs parallel validation of account and rate
func (ctrl *SenderController) validateAccountAndRate(ctx *gin.Context, token *ent.Token, institutionObj *ent.Institution, payload types.NewPaymentOrderPayload) (AccountResult, RateResult, *types.ErrorData) {

	accountChan := make(chan AccountResult, 1)
	rateChan := make(chan RateResult, 1)

	go func() {
		accountName, err := u.ValidateAccount(ctx, payload.Recipient.Institution, payload.Recipient.AccountIdentifier)
		accountChan <- AccountResult{accountName, err}
	}()

	go func() {
		achievableRate, _, err := u.ValidateRate(ctx, token, institutionObj.Edges.FiatCurrency, payload.Amount, payload.Recipient.ProviderID, payload.Network)
		rateChan <- RateResult{achievableRate, err}
	}()

	var accountResult AccountResult
	var rateResult RateResult
	var completedCount int

	for completedCount < 2 {
		select {
		case accountResult = <-accountChan:
			completedCount++
			if accountResult.err != nil {
				return AccountResult{}, RateResult{}, &types.ErrorData{
					Field:   "Recipient",
					Message: fmt.Sprintf("Account validation failed: %s", accountResult.err.Error()),
				}
			}
		case rateResult = <-rateChan:
			completedCount++
			if rateResult.err != nil {
				return AccountResult{}, RateResult{}, &types.ErrorData{
					Field:   "Rate",
					Message: fmt.Sprintf("Rate validation failed: %s", rateResult.err.Error()),
				}
			}
		}
	}

	return accountResult, rateResult, nil
}

// createReceiveAddress creates receive address for offramp orders
func (ctrl *SenderController) createReceiveAddress(ctx *gin.Context, payload types.NewPaymentOrderPayload) (*ent.ReceiveAddress, error) {
	var receiveAddress *ent.ReceiveAddress
	var networkIdentifier string
	
	if payload.Source.PaymentRail != "" {
		networkIdentifier = payload.Source.PaymentRail
	} else {
		networkIdentifier = payload.Network
	}

	if strings.HasPrefix(networkIdentifier, "tron") {
		address, salt, err := ctrl.receiveAddressService.CreateTronAddress(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create tron address: %w", err)
		}

		receiveAddress, err = storage.Client.ReceiveAddress.
			Create().
			SetAddress(address).
			SetSalt(salt).
			SetStatus(receiveaddress.StatusUnused).
			SetValidUntil(time.Now().Add(orderConf.ReceiveAddressValidity)).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to save receive address: %w", err)
		}
	} else {
		uniqueLabel := fmt.Sprintf("payment_order_%d_%s", time.Now().UnixNano(), uuid.New().String()[:8])
		address, err := ctrl.receiveAddressService.CreateSmartAddress(ctx, uniqueLabel)
		if err != nil {
			return nil, fmt.Errorf("failed to create smart address: %w", err)
		}

		receiveAddress, err = storage.Client.ReceiveAddress.
			Create().
			SetAddress(address).
			SetStatus(receiveaddress.StatusUnused).
			SetValidUntil(time.Now().Add(orderConf.ReceiveAddressValidity)).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to save receive address: %w", err)
		}
	}

	// Prevent receive address expiry for private orders
	if strings.HasPrefix(payload.Recipient.Memo, "P#P") {
		receiveAddress.ValidUntil = time.Time{}
	}

	return receiveAddress, nil
}

// createVirtualAccountWithProvider creates virtual account with provider
func (ctrl *SenderController) createVirtualAccountWithProvider(ctx *gin.Context, paymentOrder *ent.PaymentOrder, payload types.NewPaymentOrderPayload, selectedProvider *ent.ProviderProfile) (*types.NewOrderResponse, error) {
	providerPayload := map[string]interface{}{
		"orderId":  paymentOrder.ID.String(),
		"type":     "onramp",
		"amount":   paymentOrder.Amount,
		"currency": payload.Source.Currency,
		"providerDetails": map[string]interface{}{
			"firstname": selectedProvider.Edges.User.FirstName,
			"lastname":  selectedProvider.Edges.User.LastName,
		},
	}

	data, err := u.CallProviderWithHMAC(ctx, selectedProvider.ID, "POST", "/create_virtual_account", providerPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to call provider create virtual account endpoint: %w", err)
	}

	responseData, ok := data["data"]
	if !ok {
		return nil, fmt.Errorf("missing 'data' field in provider response")
	}

	jsonBytes, err := json.Marshal(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}

	var virtualAccount types.NewOrderResponse
	if err := json.Unmarshal(jsonBytes, &virtualAccount); err != nil {
		return nil, fmt.Errorf("failed to decode virtual account response: %w", err)
	}

	if virtualAccount.OrderID == "" || virtualAccount.Type == "" || virtualAccount.AccountIdentifier == "" {
		return nil, fmt.Errorf("invalid virtual account response: missing required fields")
	}

	return &virtualAccount, nil
}

// createOfframpPaymentOrder creates complete offramp payment order with transaction
func (ctrl *SenderController) createOfframpPaymentOrder(ctx *gin.Context, payload types.NewPaymentOrderPayload, sender *ent.SenderProfile, token *ent.Token, receiveAddress *ent.ReceiveAddress, feePercent decimal.Decimal, feeAddress string, returnAddress string, accountName string) (*ent.PaymentOrder, error) {
	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	senderFee := feePercent.Mul(payload.Amount).Div(decimal.NewFromInt(100)).Round(4)

	// Create transaction log
	transactionLog, err := tx.TransactionLog.
		Create().
		SetStatus(transactionlog.StatusOrderInitiated).
		SetMetadata(map[string]interface{}{
			"ReceiveAddress": receiveAddress.Address,
			"SenderID":       sender.ID.String(),
			"OrderType":      "offramp",
		}).
		SetNetwork(token.Edges.Network.Identifier).
		Save(ctx)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create transaction log: %w", err)
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
		tx.Rollback()
		return nil, fmt.Errorf("failed to create payment order: %w", err)
	}

	// Create webhook for EVM networks
	if !strings.HasPrefix(token.Edges.Network.Identifier, "tron") {
		err = ctrl.createTransferWebhook(ctx, tx, token, receiveAddress, paymentOrder)
		if err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("failed to create webhook: %w", err)
		}
	}

	// Create payment order recipient
	recipientInstitution := payload.Recipient.Institution
	if payload.Destination.Type == "fiat" {
		recipientInstitution = payload.Destination.Recipient.Institution
	}

	recipientAccountId := payload.Recipient.AccountIdentifier
	if payload.Destination.Type == "fiat" {
		recipientAccountId = payload.Destination.Recipient.AccountIdentifier
	}

	recipientProviderId := payload.Recipient.ProviderID
	if payload.Destination.ProviderID != "" {
		recipientProviderId = payload.Destination.ProviderID
	}

	_, err = tx.PaymentOrderRecipient.
		Create().
		SetInstitution(recipientInstitution).
		SetAccountIdentifier(recipientAccountId).
		SetAccountName(accountName).
		SetProviderID(recipientProviderId).
		SetMemo(payload.Recipient.Memo).
		SetMetadata(payload.Recipient.Metadata).
		SetPaymentOrder(paymentOrder).
		Save(ctx)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to create payment order recipient: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return paymentOrder, nil
}

// createTransferWebhook creates transfer webhook for EVM networks
func (ctrl *SenderController) createTransferWebhook(ctx *gin.Context, tx *ent.Tx, token *ent.Token, receiveAddress *ent.ReceiveAddress, paymentOrder *ent.PaymentOrder) error {
	engineService := svc.NewEngineService()
	webhookID, webhookSecret, err := engineService.CreateTransferWebhook(
		ctx,
		token.Edges.Network.ChainID,
		token.ContractAddress,
		receiveAddress.Address,
		paymentOrder.ID.String(),
	)
	if err != nil {
		// BNB Smart Chain (chain ID 56) is not supported by Thirdweb
		if token.Edges.Network.ChainID != 56 {
			return fmt.Errorf("failed to create transfer webhook: %w", err)
		}
		return nil
	}

	_, err = tx.PaymentWebhook.
		Create().
		SetWebhookID(webhookID).
		SetWebhookSecret(webhookSecret).
		SetCallbackURL(fmt.Sprintf("%s/v1/insight/webhook", serverConf.ServerURL)).
		SetPaymentOrder(paymentOrder).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to save payment webhook record: %w", err)
	}

	return nil
}

// validateCryptoAddress validates crypto addresses
func (ctrl *SenderController) validateCryptoAddress(address, network string) bool {
	if !strings.HasPrefix(network, "tron") {
		return u.IsValidEthereumAddress(address)
	} else {
		return u.IsValidTronAddress(address)
	}
}

// getSenderOrderTokenConfig gets sender configuration with fee settings
func (ctrl *SenderController) getSenderOrderTokenConfig(ctx *gin.Context, sender *ent.SenderProfile, token *ent.Token, payload types.NewPaymentOrderPayload) (decimal.Decimal, string, error) {
	senderOrderToken, err := storage.Client.SenderOrderToken.
		Query().
		Where(
			senderordertoken.HasTokenWith(tokenEnt.IDEQ(token.ID)),
			senderordertoken.HasSenderWith(senderprofile.IDEQ(sender.ID)),
		).
		Only(ctx)
	if err != nil {
		return decimal.Zero, "", err
	}

	if senderOrderToken.FeeAddress == "" || senderOrderToken.RefundAddress == "" {
		return decimal.Zero, "", fmt.Errorf("invalid sender order token configuration")
	}

	feePercent := senderOrderToken.FeePercent
	feeAddress := senderOrderToken.FeeAddress

	// Handle fee address override for partners
	if payload.FeeAddress != "" {
		if !sender.IsPartner {
			return decimal.Zero, "", fmt.Errorf("fee address override is not allowed for non-partners")
		}

		if payload.FeePercent.IsZero() {
			return decimal.Zero, "", fmt.Errorf("FeePercent must be greater than zero")
		}

		if !ctrl.validateCryptoAddress(payload.FeeAddress, token.Edges.Network.Identifier) {
			return decimal.Zero, "", fmt.Errorf("invalid fee address format")
		}

		feePercent = payload.FeePercent
		feeAddress = payload.FeeAddress
	}

	return feePercent, feeAddress, nil
}

// getSenderOrderTokenConfigWithReturn gets sender configuration with return address
func (ctrl *SenderController) getSenderOrderTokenConfigWithReturn(ctx *gin.Context, sender *ent.SenderProfile, token *ent.Token, payload types.NewPaymentOrderPayload) (decimal.Decimal, string, string, error) {
	feePercent, feeAddress, err := ctrl.getSenderOrderTokenConfig(ctx, sender, token, payload)
	if err != nil {
		return decimal.Zero, "", "", err
	}

	senderOrderToken, err := storage.Client.SenderOrderToken.
		Query().
		Where(
			senderordertoken.HasTokenWith(tokenEnt.IDEQ(token.ID)),
			senderordertoken.HasSenderWith(senderprofile.IDEQ(sender.ID)),
		).
		Only(ctx)
	if err != nil {
		return decimal.Zero, "", "", err
	}

	returnAddress := senderOrderToken.RefundAddress

	// Handle return address override
	if payload.ReturnAddress != "" {
		if !ctrl.validateCryptoAddress(payload.ReturnAddress, token.Edges.Network.Identifier) {
			return decimal.Zero, "", "", fmt.Errorf("invalid return address format")
		}
		returnAddress = payload.ReturnAddress
	}

	return feePercent, feeAddress, returnAddress, nil
}


func (ctrl *SenderController) handleOfframpOrder(ctx *gin.Context, payload types.NewPaymentOrderPayload, sender *ent.SenderProfile, token *ent.Token, institutionObj *ent.Institution) {
	// Get sender configuration
	feePercent, feeAddress, returnAddress, err := ctrl.getSenderOrderTokenConfigWithReturn(ctx, sender, token, payload)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Token",
			Message: err.Error(),
		})
		return
	}

	// Currency compatibility check
	if !strings.EqualFold(token.BaseCurrency, institutionObj.Edges.FiatCurrency.Code) && !strings.EqualFold(token.BaseCurrency, "USD") {
		u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("%s can only be converted to %s", token.Symbol, token.BaseCurrency), nil)
		return
	}

	// Parallel validation of account and rate
	accountResult, rateResult, errorData := ctrl.validateAccountAndRate(ctx, token, institutionObj, payload)
	if errorData != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", errorData)
		return
	}

	// Validate provided rate against achievable rate
	tolerance := rateResult.achievableRate.Mul(decimal.NewFromFloat(0.001)) // 0.1% tolerance
	if payload.Rate.LessThan(rateResult.achievableRate.Sub(tolerance)) {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Rate",
			Message: fmt.Sprintf("Provided rate %s is not achievable. Available rate is %s", payload.Rate, rateResult.achievableRate),
		})
		return
	}

	// Create receive address
	receiveAddress, err := ctrl.createReceiveAddress(ctx, payload)
	if err != nil {
		logger.Errorf("Failed to create receive address: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		return
	}

	// Create payment order in transaction
	paymentOrder, err := ctrl.createOfframpPaymentOrder(ctx, payload, sender, token, receiveAddress, feePercent, feeAddress, returnAddress, accountResult.accountName)
	if err != nil {
		logger.Errorf("Failed to create offramp payment order: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		return
	}

	provider := ""
	if payload.Destination.ProviderID != "" && payload.Recipient.ProviderID != "" {
		provider = payload.Destination.ProviderID
	}

	// Return success response
	senderFee := feePercent.Mul(payload.Amount).Div(decimal.NewFromInt(100)).Round(4)
	response := &types.OrderResponse{
        ID:        paymentOrder.ID.String(),
        Status:    "initiated",
        Timestamp: paymentOrder.CreatedAt.Format(time.RFC3339),
        Amount:    paymentOrder.Amount.String(),
        Rate:      paymentOrder.Rate.String(),
		AmountIn: payload.AmountIn.String(),
        SenderFee: senderFee.String(),
		SenderFeePercent: feePercent.String(),
        Reference: paymentOrder.Reference,
        ProviderAccount: types.ProviderAccount{
            PaymentRail:    token.Edges.Network.Identifier,
            ReceiveAddress: receiveAddress.Address,
            ValidUntil:     receiveAddress.ValidUntil.Format(time.RFC3339),
        },
        Source: types.ResponseSource{
            Type:        "crypto",
            Currency:    token.Symbol,
            PaymentRail: token.Edges.Network.Identifier,
			RefundAddress: returnAddress,
        },
        Destination: types.ResponseDestination{
            Type:     "fiat",
            Currency: institutionObj.Edges.FiatCurrency.Code,
			Country:  payload.Destination.Country,
			ProviderID: provider,
            Recipient: types.ResponseRecipient{
                Institution:       payload.Recipient.Institution,
                AccountIdentifier: payload.Recipient.AccountIdentifier,
                AccountName:       accountResult.accountName,
                Memo:              payload.Recipient.Memo,
            },
        },
    }
	u.APIResponse(ctx, http.StatusCreated, "success", "Payment order initiated successfully", response)
}

// handleOnrampOrder handles onramp order creation
func (ctrl *SenderController) handleOnrampOrder(ctx *gin.Context, payload types.NewPaymentOrderPayload, sender *ent.SenderProfile, token *ent.Token, institutionObj *ent.Institution) {
	// Validate onramp-specific fields
	if err := ctrl.validateOnrampFields(payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", err)
		return
	}

	// Get sender configuration
	feePercent, feeAddress, err := ctrl.getSenderOrderTokenConfig(ctx, sender, token, payload)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Token",
			Message: err.Error(),
		})
		return
	}

	// Get fiat currency for validation
	fiatCurrency, err := storage.Client.FiatCurrency.
		Query().
		Where(fiatcurrency.CodeEQ(payload.Source.Currency)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Source.Currency",
				Message: "Unsupported fiat currency",
			})
		} else {
			logger.Errorf("Failed to fetch fiat currency: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to validate currency", nil)
		}
		return
	}

	// Validate rate and find suitable provider
	achievableRate, suitableProvider, err := u.ValidateRate(ctx, token, fiatCurrency, payload.Amount, payload.Destination.ProviderID, payload.Destination.Recipient.PaymentRail)
	if err != nil {
		logger.Errorf("Failed to validate rate: %v", err)
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate rate", types.ErrorData{
			Field:   "Rate",
			Message: "Rate validation failed",
		})
		return
	}

	// Set rate if not provided or validate if provided
	if payload.Rate.IsZero() {
		payload.Rate = achievableRate
	} else {
		tolerance := achievableRate.Mul(decimal.NewFromFloat(0.001)) // 0.1% tolerance
		if payload.Rate.LessThan(achievableRate.Sub(tolerance)) || payload.Rate.GreaterThan(achievableRate) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Rate",
				Message: fmt.Sprintf("Provided rate %s is not achievable. Available rate is %s", payload.Rate, achievableRate),
			})
			return
		}
	}

	// Create payment order and virtual account in transaction
	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		logger.Errorf("Failed to start transaction: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		return
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	// Create transaction log
	transactionLog, err := tx.TransactionLog.
		Create().
		SetStatus(transactionlog.StatusOrderInitiated).
		SetMetadata(map[string]interface{}{
			"PaymentRail": payload.Destination.Recipient.PaymentRail,
			"Destination": payload.Destination.Recipient.Address,
			"Currency":    payload.Destination.Currency,
			"SenderID":    sender.ID.String(),
			"OrderType":   "onramp",
		}).
		SetNetwork(token.Edges.Network.Identifier).
		Save(ctx)
	if err != nil {
		logger.Errorf("Failed to create transaction log: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		tx.Rollback()
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
		SetToken(token).
		SetRate(payload.Rate).
		SetFeePercent(feePercent).
		SetFeeAddress(feeAddress).
		SetReference(payload.Reference).
		AddTransactions(transactionLog).
		Save(ctx)
	if err != nil {
		logger.Errorf("Failed to create payment order: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		tx.Rollback()
		return
	}

	// Create virtual account with provider
	virtualAccountResp, err := ctrl.createVirtualAccountWithProvider(ctx, paymentOrder, payload, suitableProvider)
	if err != nil {
		logger.Errorf("Failed to create virtual account: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to create virtual account", nil)
		tx.Rollback()
		return
	}

	// @TODO - need to update schema
	_, err = tx.PaymentOrderRecipient.
		Create().
		SetInstitution(virtualAccountResp.InstitutionName).
		SetAccountIdentifier(virtualAccountResp.AccountIdentifier).
		SetAccountName(virtualAccountResp.AccountName).
		SetProviderID(payload.Destination.ProviderID).
		SetMetadata(map[string]interface{}{
			"virtualAccountId": virtualAccountResp.OrderID,
			"validUntil":       virtualAccountResp.ValidUntil,
			"orderType":        virtualAccountResp.Type,
			"destinationAddress": payload.Destination.Recipient.Address,
			"paymentRail":      payload.Destination.Recipient.PaymentRail,
		}).
		SetPaymentOrder(paymentOrder).
		Save(ctx)
	if err != nil {
		logger.Errorf("Failed to create payment order recipient: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		tx.Rollback()
		return
	}

	if err := tx.Commit(); err != nil {
		logger.Errorf("Failed to commit transaction: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		return
	}

	senderFee := decimal.NewFromInt(0)

	response := &types.OrderResponse{
        ID:        paymentOrder.ID.String(),
        Status:    "initiated",
        Timestamp: paymentOrder.CreatedAt.Format(time.RFC3339),
        Amount:    paymentOrder.Amount.String(),
        Rate:      paymentOrder.Rate.String(),
		AmountIn: payload.AmountIn.String(),
        SenderFee: senderFee.String(),
		SenderFeePercent: feePercent.String(),
        Reference: paymentOrder.Reference,
        ProviderAccount: types.ProviderAccount{
            Institution:       virtualAccountResp.InstitutionName,
            AccountIdentifier: virtualAccountResp.AccountIdentifier,
            AccountName:       virtualAccountResp.AccountName,
            ValidUntil:        virtualAccountResp.ValidUntil,
        },
        Source: types.ResponseSource{
            Type:     "fiat",
            Currency: payload.Source.Currency,
            Country:  payload.Source.Country,
			RefundAccount: &types.AccountInfo{
				Institution:       payload.Source.RefundAccount.Institution,
				AccountIdentifier: payload.Source.RefundAccount.AccountIdentifier,
				AccountName:       payload.Source.RefundAccount.AccountName,
			},
        },
        Destination: types.ResponseDestination{
            Type:       "crypto",
            Currency:   payload.Destination.Currency,
            ProviderID: payload.Destination.ProviderID,
            Recipient: types.ResponseRecipient{
                PaymentRail: payload.Destination.Recipient.PaymentRail,
                Address:     payload.Destination.Recipient.Address,
            },
        },
    }

	// Return virtual account response
	u.APIResponse(ctx, http.StatusCreated, "success", "Onramp payment order initiated successfully", response)
}
