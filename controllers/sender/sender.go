package sender

import (
	"context"
	"encoding/csv"
	"encoding/json"
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
	"github.com/paycrest/aggregator/services/balance"
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

// refundOrRecipientForDirection returns RefundOrRecipientAddress for offramp only; onramp returns empty.
func refundOrRecipientForDirection(po *ent.PaymentOrder) string {
	if po.Direction == paymentorder.DirectionOfframp {
		return po.RefundOrRecipientAddress
	}
	return ""
}

// roundCryptoAmount caps precision to the token's on-chain decimals when the value has
// more decimal places than that (e.g. rate math). Sender-supplied amounts with fewer
// places (e.g. 2 dp stablecoin quotes) are left unchanged.
func roundCryptoAmount(d decimal.Decimal, token *ent.Token) decimal.Decimal {
	dec := int32(token.Decimals)
	if d.Exponent() >= -dec {
		return d
	}
	return d.Round(dec)
}

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
	reqCtx := ctx.Request.Context()

	// Get token from DB
	token, err := storage.Client.Token.
		Query().
		Where(
			tokenEnt.SymbolEQ(payload.Token),
			tokenEnt.HasNetworkWith(network.IdentifierEQ(payload.Network)),
			tokenEnt.IsEnabledEQ(true),
		).
		WithNetwork().
		Only(reqCtx)
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

	orderAmount := roundCryptoAmount(payload.Amount, token)
	if orderAmount.LessThanOrEqual(decimal.Zero) {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Amount",
			Message: "Amount is too small for this token's decimal precision",
		})
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
		Only(reqCtx)
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
			Where(
				paymentorder.HasSenderProfileWith(senderprofile.IDEQ(sender.ID)),
			).
			Exist(reqCtx)
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
		First(reqCtx)
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

	// Normalize mobile money account identifier: add country code and strip '+'
	if institutionObj.Type == institution.TypeMobileMoney && institutionObj.Edges.FiatCurrency != nil {
		payload.Recipient.AccountIdentifier = u.NormalizeMobileMoneyAccountIdentifier(
			institutionObj.Edges.FiatCurrency.Code,
			payload.Recipient.AccountIdentifier,
		)
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
		rateResult, err := u.ValidateRate(ctx, token, institutionObj.Edges.FiatCurrency, orderAmount, payload.Recipient.ProviderID, payload.Network, u.RateSideSell)
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
	payload.Recipient.AccountName = u.ResolveAccountNameAfterValidation(accountResult.accountName, payload.Recipient.AccountName)
	rateValidationResult := rateResult.rateResult
	achievableRate := rateValidationResult.Rate

	// Validate provided rate against market rate with same symmetric 0.1% band as blockchain indexer
	// (validateAndPreparePaymentOrderData: abs(event.Rate - validated) <= tolerance).
	tolerance := achievableRate.Mul(decimal.NewFromFloat(0.001)) // 0.1% tolerance
	if payload.Rate.Sub(achievableRate).Abs().GreaterThan(tolerance) {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Rate",
			Message: fmt.Sprintf("Provided rate %s is outside 0.1%% tolerance of market rate %s", payload.Rate, achievableRate),
		})
		return
	}

	// Use order type from ValidateRate result (already determined based on OTC limits)
	orderType := rateValidationResult.OrderType

	// Generate receive address
	var receiveAddress string
	var receiveAddressSalt []byte
	var receiveAddressExpiry time.Time
	var createTransferWebhook bool

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
		uniqueLabel := fmt.Sprintf("payment_order_%d_%s", time.Now().UnixNano(), uuid.New().String()[:8])
		address, salt, err := ctrl.receiveAddressService.CreateEVMAddress(reqCtx, token.Edges.Network.WalletService, uniqueLabel)
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
		receiveAddressSalt = salt
		receiveAddressExpiry = time.Now().Add(orderConf.ReceiveAddressValidity)
		if token.Edges.Network.WalletService == network.WalletServiceEngine {
			createTransferWebhook = true
		}
	}

	// Set extended expiry for private orders (10x normal validity)
	if strings.HasPrefix(payload.Recipient.Memo, "P#P") {
		receiveAddressExpiry = time.Now().Add(10 * orderConf.ReceiveAddressValidity)
	}

	if serverConf.Environment == "production" || serverConf.Environment == "staging" {

		if payload.Recipient.Metadata == nil {
			payload.Recipient.Metadata = make(map[string]interface{})
		}
		// Always remove any user-supplied apiKey to prevent spoofing
		delete(payload.Recipient.Metadata, "apiKey")

		// Only add API key to metadata if sender has an associated API key
		if sender.Edges.APIKey != nil {
			payload.Recipient.Metadata["apiKey"] = sender.Edges.APIKey.ID.String()
		}

		validationErr := cryptoUtils.ValidateRecipientEncryptionSize(&payload.Recipient)

		// Remove internal apiKey after validation (it should not be persisted in clear form)
		delete(payload.Recipient.Metadata, "apiKey")

		// Now check validation result
		if validationErr != nil {
			logger.WithFields(logger.Fields{
				"error":       validationErr,
				"institution": payload.Recipient.Institution,
			}).Errorf("Recipient encryption size validation failed")
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Recipient",
				Message: "Recipient data too large for encryption",
			})
			return
		}
	}

	// Create payment order and recipient in a transaction
	tx, err := storage.Client.Tx(reqCtx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		return
	}

	amountInUSD := u.CalculatePaymentOrderAmountInUSD(orderAmount, token, institutionObj, paymentorder.DirectionOfframp)

	// Calculate fee based on percentage (use rounded order amount)
	calculatedFee := feePercent.Mul(orderAmount).Div(decimal.NewFromInt(100)).Round(4)

	// Apply max fee cap if configured (zero means no cap)
	senderFee := calculatedFee
	if senderOrderToken.MaxFeeCap.GreaterThan(decimal.Zero) {
		if calculatedFee.GreaterThan(senderOrderToken.MaxFeeCap) {
			senderFee = senderOrderToken.MaxFeeCap
		}
	}
	senderFee = roundCryptoAmount(senderFee, token)
	networkFee := roundCryptoAmount(token.Edges.Network.Fee, token)

	// Create payment order first, then transaction log (required edge)
	paymentOrderBuilder := tx.PaymentOrder.
		Create().
		SetSenderProfile(sender).
		SetAmount(orderAmount).
		SetAmountInUsd(amountInUSD).
		SetNetworkFee(networkFee).
		SetSenderFee(senderFee).
		SetToken(token).
		SetRate(payload.Rate).
		SetReceiveAddress(receiveAddress).
		SetReceiveAddressExpiry(receiveAddressExpiry).
		SetFeePercent(feePercent).
		SetFeeAddress(feeAddress).
		SetRefundOrRecipientAddress(returnAddress).
		SetDirection(paymentorder.DirectionOfframp).
		SetReference(payload.Reference).
		SetOrderType(orderType).
		SetInstitution(payload.Recipient.Institution).
		SetAccountIdentifier(payload.Recipient.AccountIdentifier).
		SetAccountName(payload.Recipient.AccountName).
		SetMemo(payload.Recipient.Memo).
		SetMetadata(payload.Recipient.Metadata)

	if receiveAddressSalt != nil {
		paymentOrderBuilder = paymentOrderBuilder.SetReceiveAddressSalt(receiveAddressSalt)
	}

	paymentOrder, err := paymentOrderBuilder.Save(reqCtx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		_ = tx.Rollback()
		return
	}

	// Create transaction log after payment order (required edge)
	transactionLog, err := tx.TransactionLog.
		Create().
		SetStatus(transactionlog.StatusOrderInitiated).
		SetNetwork(token.Edges.Network.Identifier).
		SetPaymentOrderID(paymentOrder.ID).
		Save(reqCtx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		_ = tx.Rollback()
		return
	}
	_ = transactionLog

	if createTransferWebhook {
		engineService := svc.NewEngineService()
		webhookID, webhookSecret, webhookErr := engineService.CreateTransferWebhook(reqCtx, token.Edges.Network.ChainID, token.ContractAddress, receiveAddress, paymentOrder.ID.String())
		if webhookErr != nil {
			// Check if this is BNB Smart Chain (chain ID 56) or Lisk (chain ID 1135) which is not supported by Thirdweb
			if token.Edges.Network.ChainID != 56 && token.Edges.Network.ChainID != 1135 {
				logger.WithFields(logger.Fields{
					"ChainID": token.Edges.Network.ChainID,
					"Network": token.Edges.Network.Identifier,
					"Error":   webhookErr.Error(),
				}).Errorf("Failed to create transfer webhook: %v", webhookErr)
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
				_ = tx.Rollback()
				return
			}
		} else {
			_, err = tx.PaymentWebhook.
				Create().
				SetWebhookID(webhookID).
				SetWebhookSecret(webhookSecret).
				SetCallbackURL(fmt.Sprintf("%s/v1/insight/webhook", serverConf.ServerURL)).
				SetPaymentOrder(paymentOrder).
				SetNetwork(token.Edges.Network).
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
			TransactionFee: networkFee,
			Reference:      paymentOrder.Reference,
			OrderType:      string(orderType),
		})
}

// InitiatePaymentOrderV2 controller creates a payment order using v2 schema
// Supports both offramp (crypto->fiat) and onramp (fiat->crypto) flows
func (ctrl *SenderController) InitiatePaymentOrderV2(ctx *gin.Context) {
	var payload types.V2PaymentOrderPayload

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	// amountIn defaulting is done in flow-specific helpers (offramp -> "crypto", onramp -> "fiat")

	// Detect flow type from source and destination
	var sourceType, destType struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload.Source, &sourceType); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Source",
			Message: "Invalid source format",
		})
		return
	}
	if err := json.Unmarshal(payload.Destination, &destType); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Destination",
			Message: "Invalid destination format",
		})
		return
	}

	// Branch based on flow type
	if sourceType.Type == "crypto" && destType.Type == "fiat" {
		// Offramp flow
		ctrl.initiateOfframpOrderV2(ctx, payload)
	} else if sourceType.Type == "fiat" && destType.Type == "crypto" {
		// Onramp flow
		ctrl.initiateOnrampOrderV2(ctx, payload)
	} else {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Source/Destination",
			Message: fmt.Sprintf("Invalid flow combination: source.type=%s, destination.type=%s. Expected (crypto,fiat) for offramp or (fiat,crypto) for onramp", sourceType.Type, destType.Type),
		})
		return
	}
}

// initiateOfframpOrderV2 handles offramp (crypto->fiat) payment order creation
func (ctrl *SenderController) initiateOfframpOrderV2(ctx *gin.Context, payload types.V2PaymentOrderPayload) {
	// Unmarshal source and destination
	var source types.V2CryptoSource
	var destination types.V2FiatDestination
	if err := json.Unmarshal(payload.Source, &source); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Source",
			Message: "Invalid crypto source format",
		})
		return
	}
	if err := json.Unmarshal(payload.Destination, &destination); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Destination",
			Message: "Invalid fiat destination format",
		})
		return
	}

	// Validate mutually exclusive fields: senderFee and senderFeePercent cannot both be provided
	if payload.SenderFee != "" && payload.SenderFeePercent != "" {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "SenderFee",
			Message: "Cannot provide both senderFee and senderFeePercent",
		})
		return
	}

	// Parse amount from string
	amount, err := decimal.NewFromString(payload.Amount)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Amount",
			Message: "Invalid amount format",
		})
		return
	}

	// Validate amount is greater than zero
	if amount.LessThanOrEqual(decimal.Zero) {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Amount",
			Message: "Amount must be greater than zero",
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
	reqCtx := ctx.Request.Context()

	// Validate source configuration
	token, err := storage.Client.Token.
		Query().
		Where(
			tokenEnt.SymbolEQ(source.Currency),
			tokenEnt.HasNetworkWith(network.IdentifierEQ(source.Network)),
			tokenEnt.IsEnabledEQ(true),
		).
		WithNetwork().
		Only(reqCtx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Source",
				Message: "Provided token or payment rail is not supported",
			})
		} else {
			logger.Errorf("Failed to fetch token: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch token", nil)
		}
		return
	}

	// Validate refund address format
	if strings.HasPrefix(source.Network, "tron") {
		if !u.IsValidTronAddress(source.RefundAddress) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Source",
				Message: "Invalid Tron refund address",
			})
			return
		}
	} else if strings.HasPrefix(source.Network, "starknet") {
		// Starknet addresses are 65 or 66 characters (0x + 63-64 hex characters)
		pattern := `^0x[a-fA-F0-9]{63,64}$`
		matched, _ := regexp.MatchString(pattern, source.RefundAddress)
		if !matched {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Source",
				Message: "Invalid Starknet refund address",
			})
			return
		}
	} else {
		// EVM networks (Ethereum, Base, Polygon, etc.)
		if !u.IsValidEthereumAddress(source.RefundAddress) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Source",
				Message: "Invalid Ethereum refund address",
			})
			return
		}
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
		Only(reqCtx)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Source",
			Message: "Provided token is not configured",
		})
		return
	}

	if senderOrderToken.FeeAddress == "" || senderOrderToken.RefundAddress == "" {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Source",
			Message: "Fee address or refund address is not configured",
		})
		return
	}

	feePercent := senderOrderToken.FeePercent
	feeAddress := senderOrderToken.FeeAddress
	returnAddress := senderOrderToken.RefundAddress

	// Use refund address from source if provided
	returnAddress = source.RefundAddress

	// Validate destination configuration
	// Validate institution exists
	institutionObj, err := storage.Client.Institution.
		Query().
		Where(
			institution.CodeEQ(destination.Recipient.Institution),
		).
		WithFiatCurrency(
			func(q *ent.FiatCurrencyQuery) {
				q.Where(fiatcurrency.IsEnabledEQ(true))
			},
		).
		First(reqCtx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Destination",
				Message: "Provided institution is not supported",
			})
		} else {
			logger.Errorf("Failed to fetch institution: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to validate institution", nil)
		}
		return
	}

	// Validate destination currency matches institution currency (case-insensitive)
	if !strings.EqualFold(institutionObj.Edges.FiatCurrency.Code, destination.Currency) {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Destination",
			Message: "Destination currency does not match institution currency",
		})
		return
	}

	currency := institutionObj.Edges.FiatCurrency

	if !strings.EqualFold(token.BaseCurrency, currency.Code) && !strings.EqualFold(token.BaseCurrency, "USD") {
		u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("%s can only be converted to %s", token.Symbol, token.BaseCurrency), nil)
		return
	}

	// Normalize mobile money account identifier: add country code and strip '+'
	if institutionObj.Type == institution.TypeMobileMoney {
		destination.Recipient.AccountIdentifier = u.NormalizeMobileMoneyAccountIdentifier(
			currency.Code,
			destination.Recipient.AccountIdentifier,
		)
	}

	// Validate reference if provided
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
			Where(
				paymentorder.HasSenderProfileWith(senderprofile.IDEQ(sender.ID)),
			).
			Exist(reqCtx)
		if err != nil {
			logger.Errorf("Reference check error: %v", err)
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

	// Validate account in parallel with other validations
	type AccountResult struct {
		accountName string
		err         error
	}
	accountChan := make(chan AccountResult, 1)
	go func() {
		accountName, err := u.ValidateAccount(ctx, destination.Recipient.Institution, destination.Recipient.AccountIdentifier)
		accountChan <- AccountResult{accountName, err}
	}()

	// Default amountIn to "crypto" for offramp if not provided
	if payload.AmountIn == "" {
		payload.AmountIn = "crypto"
	}

	// Handle rate logic based on amountIn
	var cryptoAmount decimal.Decimal
	var orderRate decimal.Decimal
	var rateValidationResult u.RateValidationResult

	amountIn := payload.AmountIn
	switch amountIn {
	case "fiat":
		// Offramp + amountIn=fiat: user fixes fiat payout. Rate is optional: if provided use it (crypto = fiat/rate); else pick system rate.
		if payload.Rate != "" {
			providedRate, err := decimal.NewFromString(payload.Rate)
			if err != nil {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: "Invalid rate format",
				})
				return
			}
			if providedRate.LessThanOrEqual(decimal.Zero) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: "Rate must be greater than zero",
				})
				return
			}
			cryptoAmount = amount.Div(providedRate)
			cryptoAmount = roundCryptoAmount(cryptoAmount, token)
			if cryptoAmount.LessThanOrEqual(decimal.Zero) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Amount",
					Message: "Amount is too small for this token's decimal precision",
				})
				return
			}
			rateResult, err := u.ValidateRate(ctx, token, currency, cryptoAmount, destination.ProviderID, source.Network, u.RateSideSell)
			if err != nil {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: fmt.Sprintf("Rate validation failed: %s", err.Error()),
				})
				return
			}
			rateValidationResult = rateResult
			achievableRate := rateValidationResult.Rate
			tolerance := achievableRate.Mul(decimal.NewFromFloat(0.001)) // 0.1% — symmetric with indexer
			if providedRate.Sub(achievableRate).Abs().GreaterThan(tolerance) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: fmt.Sprintf("Provided rate %s is outside 0.1%% tolerance of market rate %s", providedRate, achievableRate),
				})
				return
			}
			orderRate = providedRate
			cryptoAmount = amount.Div(orderRate)
			cryptoAmount = roundCryptoAmount(cryptoAmount, token)
			if cryptoAmount.LessThanOrEqual(decimal.Zero) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Amount",
					Message: "Amount is too small for this token's decimal precision",
				})
				return
			}
		} else {
			// No rate provided: pick valid system rate and determine crypto that yields user's fiat amount
			isDirectMatch := strings.EqualFold(token.BaseCurrency, currency.Code)
			if isDirectMatch {
				orderRate = decimal.NewFromInt(1)
			} else {
				if currency.MarketSellRate.IsZero() {
					u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
						Field:   "Rate",
						Message: "Rate not available for this currency",
					})
					return
				}
				orderRate = currency.MarketSellRate
			}
			cryptoAmount = amount.Div(orderRate)
			cryptoAmount = roundCryptoAmount(cryptoAmount, token)
			if cryptoAmount.LessThanOrEqual(decimal.Zero) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Amount",
					Message: "Amount is too small for this token's decimal precision",
				})
				return
			}
			rateResult, err := u.ValidateRate(ctx, token, currency, cryptoAmount, destination.ProviderID, source.Network, u.RateSideSell)
			if err != nil {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: fmt.Sprintf("Rate validation failed: %s", err.Error()),
				})
				return
			}
			rateValidationResult = rateResult
			orderRate = rateValidationResult.Rate
			cryptoAmount = amount.Div(orderRate)
			cryptoAmount = roundCryptoAmount(cryptoAmount, token)
			if cryptoAmount.LessThanOrEqual(decimal.Zero) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Amount",
					Message: "Amount is too small for this token's decimal precision",
				})
				return
			}
		}
	case "crypto":
		cryptoAmount = roundCryptoAmount(amount, token)
		if cryptoAmount.LessThanOrEqual(decimal.Zero) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Amount",
				Message: "Amount is too small for this token's decimal precision",
			})
			return
		}
		if payload.Rate != "" {
			// Use provided rate
			providedRate, err := decimal.NewFromString(payload.Rate)
			if err != nil {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: "Invalid rate format",
				})
				return
			}
			if providedRate.LessThanOrEqual(decimal.Zero) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: "Rate must be greater than zero",
				})
				return
			}

			// Validate rate is achievable
			rateResult, err := u.ValidateRate(ctx, token, currency, cryptoAmount, destination.ProviderID, source.Network, u.RateSideSell)
			if err != nil {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: fmt.Sprintf("Rate validation failed: %s", err.Error()),
				})
				return
			}
			rateValidationResult = rateResult
			achievableRate := rateValidationResult.Rate
			tolerance := achievableRate.Mul(decimal.NewFromFloat(0.001)) // 0.1% — symmetric with indexer
			if providedRate.Sub(achievableRate).Abs().GreaterThan(tolerance) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: fmt.Sprintf("Provided rate %s is outside 0.1%% tolerance of market rate %s", providedRate, achievableRate),
				})
				return
			}
			orderRate = providedRate
		} else {
			// Fetch rate from ValidateRate
			rateResult, err := u.ValidateRate(ctx, token, currency, cryptoAmount, destination.ProviderID, source.Network, u.RateSideSell)
			if err != nil {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: fmt.Sprintf("Rate validation failed: %s", err.Error()),
				})
				return
			}
			rateValidationResult = rateResult
			orderRate = rateValidationResult.Rate
		}
	default:
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "AmountIn",
			Message: "amountIn must be 'crypto' or 'fiat'",
		})
		return
	}

	// Get account validation result
	accountResult := <-accountChan
	if accountResult.err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Destination",
			Message: fmt.Sprintf("Account validation failed: %s", accountResult.err.Error()),
		})
		return
	}

	// Set account name from validation (keep client-supplied real name if verify returned "OK")
	destination.Recipient.AccountName = u.ResolveAccountNameAfterValidation(accountResult.accountName, destination.Recipient.AccountName)

	amountInUSD := u.CalculatePaymentOrderAmountInUSD(cryptoAmount, token, institutionObj, paymentorder.DirectionOfframp)

	// Use order type from ValidateRate result
	orderType := rateValidationResult.OrderType

	// Handle fee calculation (priority: senderFee > senderFeePercent > configured defaults)
	var senderFee decimal.Decimal
	if payload.SenderFee != "" {
		// Use provided fixed fee
		fixedFee, err := decimal.NewFromString(payload.SenderFee)
		if err != nil {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "SenderFee",
				Message: "Invalid sender fee format",
			})
			return
		}
		if fixedFee.LessThanOrEqual(decimal.Zero) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "SenderFee",
				Message: "Sender fee must be greater than zero",
			})
			return
		}
		senderFee = fixedFee
		feePercent = decimal.Zero // Reset fee percent when using fixed fee
	} else if payload.SenderFeePercent != "" {
		// Calculate fee from percentage
		feePercentValue, err := decimal.NewFromString(payload.SenderFeePercent)
		if err != nil {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "SenderFeePercent",
				Message: "Invalid sender fee percent format",
			})
			return
		}
		if feePercentValue.LessThanOrEqual(decimal.Zero) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "SenderFeePercent",
				Message: "Sender fee percent must be greater than zero",
			})
			return
		}
		feePercent = feePercentValue
		calculatedFee := feePercent.Mul(cryptoAmount).Div(decimal.NewFromInt(100)).Round(4)
		senderFee = calculatedFee
		// Apply max fee cap if configured
		if senderOrderToken.MaxFeeCap.GreaterThan(decimal.Zero) {
			if calculatedFee.GreaterThan(senderOrderToken.MaxFeeCap) {
				senderFee = senderOrderToken.MaxFeeCap
			}
		}
	} else {
		// Use configured fee percent from sender order token
		calculatedFee := feePercent.Mul(cryptoAmount).Div(decimal.NewFromInt(100)).Round(4)
		senderFee = calculatedFee
		// Apply max fee cap if configured
		if senderOrderToken.MaxFeeCap.GreaterThan(decimal.Zero) {
			if calculatedFee.GreaterThan(senderOrderToken.MaxFeeCap) {
				senderFee = senderOrderToken.MaxFeeCap
			}
		}
	}

	senderFee = roundCryptoAmount(senderFee, token)
	networkFee := roundCryptoAmount(token.Edges.Network.Fee, token)

	isLocalTransfer := strings.EqualFold(token.BaseCurrency, currency.Code)
	if isLocalTransfer && feePercent.IsZero() && senderFee.IsZero() {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "SenderFee",
			Message: fmt.Sprintf("Sender fee must be greater than zero for local currency order from (%s to %s)", token.Symbol, currency.Code),
		})
		return
	}

	// Generate receive address
	var receiveAddress string
	var receiveAddressSalt []byte
	var receiveAddressExpiry time.Time
	var createTransferWebhook bool

	if strings.HasPrefix(source.Network, "tron") {
		address, salt, err := ctrl.receiveAddressService.CreateTronAddress(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"error":   err,
				"network": source.Network,
			}).Errorf("Failed to create receive address")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", types.ErrorData{
				Field:   "Source",
				Message: "Tron currently not available",
			})
			return
		}
		receiveAddress = address
		receiveAddressSalt = salt
		receiveAddressExpiry = time.Now().Add(orderConf.ReceiveAddressValidity)
	} else if strings.HasPrefix(source.Network, "starknet") {
		if ctrl.starknetClient == nil {
			logger.WithFields(logger.Fields{
				"error":   "Starknet client not initialized -- disable Starknet tokens if not in use",
				"network": source.Network,
			}).Errorf("Failed to create receive address")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", types.ErrorData{
				Field:   "Source",
				Message: "Starknet currently not available",
			})
			return
		}
		address, salt, err := ctrl.receiveAddressService.CreateStarknetAddress(ctrl.starknetClient)
		if err != nil {
			logger.WithFields(logger.Fields{
				"error":   err,
				"network": source.Network,
			}).Errorf("Failed to create receive address")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", types.ErrorData{
				Field:   "Source",
				Message: "Starknet currently not available",
			})
			return
		}
		receiveAddress = address
		receiveAddressSalt = salt
		receiveAddressExpiry = time.Now().Add(orderConf.ReceiveAddressValidity)
	} else {
		uniqueLabel := fmt.Sprintf("payment_order_%d_%s", time.Now().UnixNano(), uuid.New().String()[:8])
		address, salt, err := ctrl.receiveAddressService.CreateEVMAddress(reqCtx, token.Edges.Network.WalletService, uniqueLabel)
		if err != nil {
			logger.WithFields(logger.Fields{
				"error":   err,
				"network": source.Network,
			}).Errorf("Failed to create receive address")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", types.ErrorData{
				Field:   "Source",
				Message: fmt.Sprintf("%s currently not available", source.Network),
			})
			return
		}
		receiveAddress = address
		receiveAddressSalt = salt
		receiveAddressExpiry = time.Now().Add(orderConf.ReceiveAddressValidity)
		if token.Edges.Network.WalletService == network.WalletServiceEngine {
			createTransferWebhook = true
		}
	}

	// Set extended expiry for private orders (10x normal validity)
	if strings.HasPrefix(destination.Recipient.Memo, "P#P") {
		receiveAddressExpiry = time.Now().Add(10 * orderConf.ReceiveAddressValidity)
	}

	// Create payment order in a transaction
	tx, err := storage.Client.Tx(reqCtx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		return
	}

	// Build metadata with KYC and recipient metadata
	metadata := make(map[string]interface{})
	if destination.Recipient.Metadata != nil {
		metadata["recipientMetadata"] = destination.Recipient.Metadata
	}
	// KYC is now nested in source and destination
	if source.KYC != nil {
		metadata["sourceKyc"] = source.KYC
	}
	if destination.KYC != nil {
		metadata["destinationKyc"] = destination.KYC
	}
	if destination.Country != "" {
		metadata["country"] = destination.Country
	}
	if payload.AmountIn != "" {
		metadata["amountIn"] = payload.AmountIn
	}

	// Create payment order first, then transaction log (required edge)
	paymentOrderBuilder := tx.PaymentOrder.
		Create().
		SetSenderProfile(sender).
		SetAmount(cryptoAmount).
		SetAmountInUsd(amountInUSD).
		SetNetworkFee(networkFee).
		SetSenderFee(senderFee).
		SetToken(token).
		SetRate(orderRate).
		SetReceiveAddress(receiveAddress).
		SetReceiveAddressExpiry(receiveAddressExpiry).
		SetFeePercent(feePercent).
		SetFeeAddress(feeAddress).
		SetRefundOrRecipientAddress(returnAddress).
		SetDirection(paymentorder.DirectionOfframp).
		SetReference(payload.Reference).
		SetOrderType(orderType).
		SetInstitution(destination.Recipient.Institution).
		SetAccountIdentifier(destination.Recipient.AccountIdentifier).
		SetAccountName(destination.Recipient.AccountName).
		SetMemo(destination.Recipient.Memo).
		SetMetadata(metadata)

	// Set provider ID if available from rate validation result
	if rateValidationResult.ProviderID != "" {
		paymentOrderBuilder = paymentOrderBuilder.SetProviderID(rateValidationResult.ProviderID)
	}

	if receiveAddressSalt != nil {
		paymentOrderBuilder = paymentOrderBuilder.SetReceiveAddressSalt(receiveAddressSalt)
	}

	paymentOrder, err := paymentOrderBuilder.Save(reqCtx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		_ = tx.Rollback()
		return
	}

	// Create transaction log after payment order (required edge)
	transactionLog, err := tx.TransactionLog.
		Create().
		SetStatus(transactionlog.StatusOrderInitiated).
		SetNetwork(token.Edges.Network.Identifier).
		SetPaymentOrderID(paymentOrder.ID).
		Save(reqCtx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		_ = tx.Rollback()
		return
	}
	_ = transactionLog

	if createTransferWebhook {
		engineService := svc.NewEngineService()
		webhookID, webhookSecret, webhookErr := engineService.CreateTransferWebhook(reqCtx, token.Edges.Network.ChainID, token.ContractAddress, receiveAddress, paymentOrder.ID.String())
		if webhookErr != nil {
			// BNB Smart Chain (56) and Lisk (1135) are not supported by Thirdweb; do not fail the order
			if token.Edges.Network.ChainID != 56 && token.Edges.Network.ChainID != 1135 {
				logger.WithFields(logger.Fields{
					"ChainID": token.Edges.Network.ChainID,
					"Network": token.Edges.Network.Identifier,
					"Error":   webhookErr.Error(),
				}).Errorf("Failed to create transfer webhook: %v", webhookErr)
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
				_ = tx.Rollback()
				return
			}
		} else {
			webhookCallbackURL := fmt.Sprintf("%s/v1/insight/webhook", config.ServerConfig().ServerURL)
			_, err = tx.PaymentWebhook.
				Create().
				SetWebhookID(webhookID).
				SetWebhookSecret(webhookSecret).
				SetCallbackURL(webhookCallbackURL).
				SetPaymentOrder(paymentOrder).
				SetNetwork(token.Edges.Network).
				Save(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"error": err,
				}).Errorf("Failed to save payment webhook record: %s", paymentOrder.ID.String())
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

	// Format sender fee percent for response
	senderFeePercentStr := ""
	if !feePercent.IsZero() {
		senderFeePercentStr = feePercent.String()
	}

	// Build response
	transactionFee := paymentOrder.NetworkFee.Add(paymentOrder.ProtocolFee)
	response := &types.V2PaymentOrderResponse{
		ID:               paymentOrder.ID,
		Status:           string(paymentOrder.Status),
		Timestamp:        paymentOrder.CreatedAt,
		Amount:           cryptoAmount.String(),
		SenderFee:        senderFee.String(),
		SenderFeePercent: senderFeePercentStr,
		TransactionFee:   transactionFee.String(),
		Reference:        paymentOrder.Reference,
		ProviderAccount: types.V2CryptoProviderAccount{
			Network:        source.Network,
			ReceiveAddress: receiveAddress,
			ValidUntil:     receiveAddressExpiry,
		},
		Source:      source,
		Destination: destination,
	}

	// Add rate to response if available
	if !orderRate.IsZero() {
		response.Rate = orderRate.String()
	}

	u.APIResponse(ctx, http.StatusCreated, "success", "Payment order initiated successfully", response)
}

// initiateOnrampOrderV2 handles onramp (fiat->crypto) payment order creation
func (ctrl *SenderController) initiateOnrampOrderV2(ctx *gin.Context, payload types.V2PaymentOrderPayload) {
	// Unmarshal source and destination
	var source types.V2FiatSource
	var destination types.V2CryptoDestination
	if err := json.Unmarshal(payload.Source, &source); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Source",
			Message: "Invalid fiat source format",
		})
		return
	}
	if err := json.Unmarshal(payload.Destination, &destination); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Destination",
			Message: "Invalid crypto destination format",
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

	// Validate mutually exclusive fields: senderFee and senderFeePercent cannot both be provided
	if payload.SenderFee != "" && payload.SenderFeePercent != "" {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "SenderFee",
			Message: "Cannot provide both senderFee and senderFeePercent",
		})
		return
	}

	// Parse amount from string
	amount, err := decimal.NewFromString(payload.Amount)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Amount",
			Message: "Invalid amount format",
		})
		return
	}

	// Validate amount is greater than zero
	if amount.LessThanOrEqual(decimal.Zero) {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Amount",
			Message: "Amount must be greater than zero",
		})
		return
	}

	// Default amountIn to "fiat" for onramp if not provided
	if payload.AmountIn == "" {
		payload.AmountIn = "fiat"
	}

	// Validate fiat source (currency + refund account details)
	currency, err := storage.Client.FiatCurrency.
		Query().
		Where(
			fiatcurrency.CodeEQ(source.Currency),
			fiatcurrency.IsEnabledEQ(true),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Source",
				Message: "Currency not supported",
			})
		} else {
			logger.Errorf("Failed to fetch currency: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch currency", nil)
		}
		return
	}

	// Validate refund account institution
	refundInstitution, err := storage.Client.Institution.
		Query().
		Where(
			institution.CodeEQ(source.RefundAccount.Institution),
		).
		WithFiatCurrency().
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Source",
				Message: "Refund institution not supported",
			})
		} else {
			logger.Errorf("Failed to fetch refund institution: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to validate refund institution", nil)
		}
		return
	}

	// Validate refund account currency matches source currency
	if refundInstitution.Edges.FiatCurrency.Code != source.Currency {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Source",
			Message: "Refund account currency does not match source currency",
		})
		return
	}

	// Validate refund account identifier (same as offramp recipient validation)
	refundAccountName, err := u.ValidateAccount(ctx, source.RefundAccount.Institution, source.RefundAccount.AccountIdentifier)
	if err != nil {
		if strings.Contains(err.Error(), "not supported") || strings.Contains(err.Error(), "verify account") {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Source",
				Message: err.Error(),
			})
		} else {
			logger.Errorf("Failed to validate refund account: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to validate refund account", nil)
		}
		return
	}
	if refundAccountName != "" && refundAccountName != "OK" {
		source.RefundAccount.AccountName = refundAccountName
	}

	// Validate crypto destination (recipient payment rail + address + token/network)
	token, err := storage.Client.Token.
		Query().
		Where(
			tokenEnt.SymbolEQ(destination.Currency),
			tokenEnt.HasNetworkWith(network.IdentifierEQ(destination.Recipient.Network)),
			tokenEnt.IsEnabledEQ(true),
		).
		WithNetwork().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Destination",
				Message: "Provided token or payment rail is not supported",
			})
		} else {
			logger.Errorf("Failed to fetch token: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch token", nil)
		}
		return
	}

	// Validate recipient address format
	if strings.HasPrefix(destination.Recipient.Network, "tron") {
		if !u.IsValidTronAddress(destination.Recipient.Address) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Destination",
				Message: "Invalid Tron recipient address",
			})
			return
		}
	} else if strings.HasPrefix(destination.Recipient.Network, "starknet") {
		pattern := `^0x[a-fA-F0-9]{63,64}$`
		matched, _ := regexp.MatchString(pattern, destination.Recipient.Address)
		if !matched {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Destination",
				Message: "Invalid Starknet recipient address",
			})
			return
		}
	} else {
		if !u.IsValidEthereumAddress(destination.Recipient.Address) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Destination",
				Message: "Invalid Ethereum recipient address",
			})
			return
		}
	}

	// Handle rate logic based on amountIn
	var cryptoAmountOut decimal.Decimal
	var orderRate decimal.Decimal
	var rateValidationResult u.RateValidationResult

	amountIn := payload.AmountIn
	switch amountIn {
	case "fiat":
		// Onramp + amountIn=fiat: user fixes fiat input. Rate is optional: if provided use it (crypto = fiat/rate); else pick system rate.
		if payload.Rate != "" {
			providedRate, err := decimal.NewFromString(payload.Rate)
			if err != nil {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: "Invalid rate format",
				})
				return
			}
			if providedRate.LessThanOrEqual(decimal.Zero) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: "Rate must be greater than zero",
				})
				return
			}
			cryptoAmountOut = amount.Div(providedRate)
			cryptoAmountOut = roundCryptoAmount(cryptoAmountOut, token)
			if cryptoAmountOut.LessThanOrEqual(decimal.Zero) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Amount",
					Message: "Amount is too small for this token's decimal precision",
				})
				return
			}
			rateResult, err := u.ValidateRate(ctx, token, currency, cryptoAmountOut, destination.ProviderID, destination.Recipient.Network, u.RateSideBuy)
			if err != nil {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: fmt.Sprintf("Rate validation failed: %s", err.Error()),
				})
				return
			}
			rateValidationResult = rateResult
			achievableRate := rateValidationResult.Rate
			tolerance := achievableRate.Mul(decimal.NewFromFloat(0.001)) // 0.1% — symmetric with indexer
			if providedRate.Sub(achievableRate).Abs().GreaterThan(tolerance) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: fmt.Sprintf("Provided rate %s is outside 0.1%% tolerance of market rate %s", providedRate, achievableRate),
				})
				return
			}
			orderRate = providedRate
			cryptoAmountOut = amount.Div(orderRate)
			cryptoAmountOut = roundCryptoAmount(cryptoAmountOut, token)
			if cryptoAmountOut.LessThanOrEqual(decimal.Zero) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Amount",
					Message: "Amount is too small for this token's decimal precision",
				})
				return
			}
		} else {
			// No rate provided: pick valid system rate and determine crypto from user's fiat amount
			isDirectMatch := strings.EqualFold(token.BaseCurrency, currency.Code)
			if isDirectMatch {
				orderRate = decimal.NewFromInt(1)
			} else {
				if currency.MarketBuyRate.IsZero() {
					u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
						Field:   "Rate",
						Message: "Rate not available for this currency",
					})
					return
				}
				orderRate = currency.MarketBuyRate
			}
			cryptoAmountOut = amount.Div(orderRate)
			cryptoAmountOut = roundCryptoAmount(cryptoAmountOut, token)
			if cryptoAmountOut.LessThanOrEqual(decimal.Zero) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Amount",
					Message: "Amount is too small for this token's decimal precision",
				})
				return
			}
			rateResult, err := u.ValidateRate(ctx, token, currency, cryptoAmountOut, destination.ProviderID, destination.Recipient.Network, u.RateSideBuy)
			if err != nil {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: fmt.Sprintf("Rate validation failed: %s", err.Error()),
				})
				return
			}
			rateValidationResult = rateResult
			orderRate = rateValidationResult.Rate
			cryptoAmountOut = amount.Div(orderRate)
			cryptoAmountOut = roundCryptoAmount(cryptoAmountOut, token)
			if cryptoAmountOut.LessThanOrEqual(decimal.Zero) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Amount",
					Message: "Amount is too small for this token's decimal precision",
				})
				return
			}
		}
	case "crypto":
		cryptoAmountOut = roundCryptoAmount(amount, token)
		if cryptoAmountOut.LessThanOrEqual(decimal.Zero) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "Amount",
				Message: "Amount is too small for this token's decimal precision",
			})
			return
		}
		if payload.Rate != "" {
			providedRate, err := decimal.NewFromString(payload.Rate)
			if err != nil {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: "Invalid rate format",
				})
				return
			}
			if providedRate.LessThanOrEqual(decimal.Zero) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: "Rate must be greater than zero",
				})
				return
			}

			// Validate rate is achievable (using buy side)
			rateResult, err := u.ValidateRate(ctx, token, currency, cryptoAmountOut, destination.ProviderID, destination.Recipient.Network, u.RateSideBuy)
			if err != nil {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: fmt.Sprintf("Rate validation failed: %s", err.Error()),
				})
				return
			}
			rateValidationResult = rateResult
			achievableRate := rateValidationResult.Rate
			tolerance := achievableRate.Mul(decimal.NewFromFloat(0.001)) // 0.1% — symmetric with indexer
			if providedRate.Sub(achievableRate).Abs().GreaterThan(tolerance) {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: fmt.Sprintf("Provided rate %s is outside 0.1%% tolerance of market rate %s", providedRate, achievableRate),
				})
				return
			}
			orderRate = providedRate
		} else {
			// Fetch rate from ValidateRate (buy side)
			rateResult, err := u.ValidateRate(ctx, token, currency, cryptoAmountOut, destination.ProviderID, destination.Recipient.Network, u.RateSideBuy)
			if err != nil {
				u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
					Field:   "Rate",
					Message: fmt.Sprintf("Rate validation failed: %s", err.Error()),
				})
				return
			}
			rateValidationResult = rateResult
			orderRate = rateValidationResult.Rate
		}
	default:
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "AmountIn",
			Message: "amountIn must be 'crypto' or 'fiat'",
		})
		return
	}

	// Handle fee calculation (priority: senderFee > senderFeePercent > configured defaults)
	// Note: For onramp, we need to get sender order token config for the crypto token
	senderOrderToken, err := storage.Client.SenderOrderToken.
		Query().
		Where(
			senderordertoken.HasTokenWith(tokenEnt.IDEQ(token.ID)),
			senderordertoken.HasSenderWith(senderprofile.IDEQ(sender.ID)),
		).
		Only(ctx)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Destination",
			Message: "Provided token is not configured",
		})
		return
	}

	if senderOrderToken.FeeAddress == "" {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
			Field:   "Destination",
			Message: "Fee address is not configured",
		})
		return
	}

	feePercent := senderOrderToken.FeePercent
	feeAddress := senderOrderToken.FeeAddress

	var senderFeeCrypto decimal.Decimal
	if payload.SenderFee != "" {
		fixedFee, err := decimal.NewFromString(payload.SenderFee)
		if err != nil {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "SenderFee",
				Message: "Invalid sender fee format",
			})
			return
		}
		if fixedFee.LessThanOrEqual(decimal.Zero) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "SenderFee",
				Message: "Sender fee must be greater than zero",
			})
			return
		}
		senderFeeCrypto = fixedFee.Round(4)
		feePercent = decimal.Zero
	} else if payload.SenderFeePercent != "" {
		feePercentValue, err := decimal.NewFromString(payload.SenderFeePercent)
		if err != nil {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "SenderFeePercent",
				Message: "Invalid sender fee percent format",
			})
			return
		}
		if feePercentValue.LessThanOrEqual(decimal.Zero) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", types.ErrorData{
				Field:   "SenderFeePercent",
				Message: "Sender fee percent must be greater than zero",
			})
			return
		}
		feePercent = feePercentValue
		calculatedFee := feePercent.Mul(cryptoAmountOut).Div(decimal.NewFromInt(100)).Round(4)
		senderFeeCrypto = calculatedFee
		if senderOrderToken.MaxFeeCap.GreaterThan(decimal.Zero) {
			if calculatedFee.GreaterThan(senderOrderToken.MaxFeeCap) {
				senderFeeCrypto = senderOrderToken.MaxFeeCap
			}
		}
	} else {
		calculatedFee := feePercent.Mul(cryptoAmountOut).Div(decimal.NewFromInt(100)).Round(4)
		senderFeeCrypto = calculatedFee
		if senderOrderToken.MaxFeeCap.GreaterThan(decimal.Zero) {
			if calculatedFee.GreaterThan(senderOrderToken.MaxFeeCap) {
				senderFeeCrypto = senderOrderToken.MaxFeeCap
			}
		}
	}

	// senderFeeCrypto stays at 4 dp (Round(4) above); do not round to token decimals — preserves fee semantics vs order amount.
	networkFee := roundCryptoAmount(token.Edges.Network.Fee, token)

	// Calculate fiat amounts
	// senderFeeFiat = senderFeeCrypto * buyRate
	senderFeeFiat := senderFeeCrypto.Mul(orderRate).RoundBank(int32(currency.Decimals))
	// fiatOrderAmount: when amountIn=crypto, amount is crypto so convert with rate; when amountIn=fiat, amount is fiat so cryptoAmountOut.Mul(rate) gives fiat
	fiatOrderAmount := cryptoAmountOut.Mul(orderRate).RoundBank(int32(currency.Decimals))
	// totalFiatToPay = fiatOrderAmount + senderFeeFiat
	totalFiatToPay := fiatOrderAmount.Add(senderFeeFiat).RoundBank(int32(currency.Decimals))

	// Validate reference if provided
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
				paymentorder.HasSenderProfileWith(senderprofile.IDEQ(sender.ID)),
			).
			Exist(ctx)
		if err != nil {
			logger.Errorf("Reference check error: %v", err)
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

	// Provider selection: destination.providerId is optional
	providerID := destination.ProviderID
	if providerID == "" {
		providerID = rateValidationResult.ProviderID
	}
	if providerID == "" {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "No provider available for this order", nil)
		return
	}

	// Reserve provider token liquidity at order creation
	balanceService := balance.New()
	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		return
	}

	// Reserve token balance: amount + senderFee (both in crypto)
	totalCryptoToReserve := cryptoAmountOut.Add(senderFeeCrypto)
	err = balanceService.ReserveTokenBalance(ctx, providerID, token.ID, totalCryptoToReserve, tx)
	if err != nil {
		logger.Errorf("Failed to reserve token balance: %v", err)
		_ = tx.Rollback()
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Insufficient provider token balance", types.ErrorData{
			Field:   "Destination",
			Message: fmt.Sprintf("Provider does not have sufficient token balance: %s", err.Error()),
		})
		return
	}

	// Build metadata
	metadata := make(map[string]interface{})
	if source.RefundAccount.Metadata != nil {
		metadata["refundAccountMetadata"] = source.RefundAccount.Metadata
	}
	if source.KYC != nil {
		metadata["sourceKyc"] = source.KYC
	}
	if destination.KYC != nil {
		metadata["destinationKyc"] = destination.KYC
	}
	if source.Country != "" {
		metadata["country"] = source.Country
	}
	if payload.AmountIn != "" {
		metadata["amountIn"] = payload.AmountIn
	}

	// Use order type from ValidateRate result
	orderType := rateValidationResult.OrderType

	// Calculate amount in USD (onramp: use buy rate when available)
	amountInUSD := u.CalculatePaymentOrderAmountInUSD(cryptoAmountOut, token, refundInstitution, paymentorder.DirectionOnramp)

	// Create payment order first, then transaction log (required edge)
	paymentOrderBuilder := tx.PaymentOrder.
		Create().
		SetSenderProfile(sender).
		SetAmount(cryptoAmountOut).
		SetAmountInUsd(amountInUSD).
		SetNetworkFee(networkFee).
		SetSenderFee(senderFeeCrypto).
		SetToken(token).
		SetRate(orderRate).
		SetFeePercent(feePercent).
		SetFeeAddress(feeAddress).
		SetRefundOrRecipientAddress(destination.Recipient.Address). // Onramp: crypto recipient for settleIn
		SetDirection(paymentorder.DirectionOnramp).
		SetReference(payload.Reference).
		SetOrderType(orderType).
		SetInstitution(source.RefundAccount.Institution).
		SetAccountIdentifier(source.RefundAccount.AccountIdentifier).
		SetAccountName(source.RefundAccount.AccountName).
		SetMemo(""). // Onramp doesn't use memo
		SetMetadata(metadata).
		SetProviderID(providerID).
		SetStatus(paymentorder.StatusPending) // VA issued at init; provider already assigned at this point.

	paymentOrder, err := paymentOrderBuilder.Save(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		_ = tx.Rollback()
		return
	}

	// Create transaction log after payment order (required edge)
	transactionLog, err := tx.TransactionLog.
		Create().
		SetStatus(transactionlog.StatusOrderInitiated).
		SetNetwork(token.Edges.Network.Identifier).
		SetPaymentOrderID(paymentOrder.ID).
		Save(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		_ = tx.Rollback()
		return
	}
	_ = transactionLog

	// Commit before any external HTTP call so the DB transaction is not held during network I/O.
	if err := tx.Commit(); err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		return
	}

	// On virtual account step failure: release balance and delete the order.
	deleteFailedOnrampOrder := func() {
		totalCryptoReserved := paymentOrder.Amount.Add(paymentOrder.SenderFee)
		if relErr := balanceService.ReleaseTokenBalance(ctx, providerID, token.ID, totalCryptoReserved, nil); relErr != nil {
			logger.Errorf("Failed to release token balance after onramp init failure (order %s): %v", paymentOrder.ID, relErr)
		}
		if delErr := storage.Client.PaymentOrder.DeleteOneID(paymentOrder.ID).Exec(ctx); delErr != nil {
			logger.Errorf("Failed to delete order after onramp init failure (order %s): %v", paymentOrder.ID, delErr)
		}
	}

	// Generate Gateway order ID now that we have the payment order ID
	// For onramp, Gateway order ID will be generated by the provider when calling settleIn
	// We'll store a placeholder that can be updated later, or generate it deterministically
	// For now, we'll store it in metadata and it will be set when settleIn is called

	// Call provider /new_order with direction=payin to create a virtual account
	orderRequestData := map[string]interface{}{
		"orderId":     paymentOrder.ID.String(),
		"direction":   "payin",
		"amount":      totalFiatToPay.String(),
		"currency":    source.Currency,
		"institution": source.RefundAccount.Institution,
	}
	if source.KYC != nil {
		orderRequestData["kyc"] = source.KYC
	}

	// Call provider new_order endpoint
	logger.Infof("Calling provider new_order endpoint: %v", orderRequestData)
	providerResponse, err := u.CallProviderWithHMAC(ctx, providerID, "POST", "/new_order", orderRequestData)
	if err != nil {
		logger.Errorf("Failed to call provider new_order: %v", err)
		deleteFailedOnrampOrder()
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to create virtual account", nil)
		return
	}
	logger.Infof("Provider new_order response: %v", providerResponse)

	vaData, ok := providerResponse["data"].(map[string]interface{})
	if !ok || vaData == nil {
		logger.Errorf("Invalid provider response: missing data")
		deleteFailedOnrampOrder()
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Invalid provider response", nil)
		return
	}

	accountIdentifier, _ := vaData["accountIdentifier"].(string)
	if accountIdentifier == "" {
		if n, ok := vaData["accountIdentifier"].(float64); ok {
			accountIdentifier = strconv.FormatFloat(n, 'f', 0, 64)
		}
	}
	if accountIdentifier == "" {
		logger.Errorf("Invalid provider response: missing accountIdentifier")
		deleteFailedOnrampOrder()
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Invalid provider response", nil)
		return
	}
	accountName, _ := vaData["accountName"].(string)
	institutionName, _ := vaData["institutionName"].(string)
	reference, _ := vaData["reference"].(string)

	var validUntil time.Time
	if validUntilStr, ok := vaData["validUntil"].(string); ok {
		var err error
		validUntil, err = time.Parse(time.RFC3339, validUntilStr)
		if err != nil {
			validUntil = time.Now().Add(orderConf.OrderFulfillmentValidity)
		}
	} else {
		validUntil = time.Now().Add(orderConf.OrderFulfillmentValidity) // Default validity
	}

	// Update payment order with virtual account details (after commit; use storage.Client)
	orderMetadata := paymentOrder.Metadata
	if orderMetadata == nil {
		orderMetadata = make(map[string]interface{})
	}
	providerAccountMap := map[string]interface{}{
		"institution":       institutionName,
		"accountIdentifier": accountIdentifier,
		"accountName":       accountName,
		"validUntil":        validUntil.Format(time.RFC3339),
		"amountToTransfer":  totalFiatToPay.String(),
		"currency":          source.Currency,
	}
	if reference != "" {
		providerAccountMap["reference"] = reference
	}
	orderMetadata["providerAccount"] = providerAccountMap
	if _, err := storage.Client.PaymentOrder.UpdateOneID(paymentOrder.ID).SetMetadata(orderMetadata).Save(ctx); err != nil {
		logger.Errorf("Failed to save provider account to order metadata: %v", err)
		deleteFailedOnrampOrder()
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		return
	}

	// Seed order_request_%s (same key as offramp) so payin AcceptOrder can validate provider
	orderRequestKey := fmt.Sprintf("order_request_%s", paymentOrder.ID.String())
	if err := storage.RedisClient.HSet(ctx, orderRequestKey,
		"providerId", providerID,
		"direction", "payin",
		"amount", totalFiatToPay.String(),
		"orderId", paymentOrder.ID.String(),
	).Err(); err != nil {
		logger.Errorf("Failed to set order_request for payin: %v", err)
		deleteFailedOnrampOrder()
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to initiate payment order", nil)
		return
	}
	_ = storage.RedisClient.Expire(ctx, orderRequestKey, 24*time.Hour).Err()

	// Format sender fee percent for response
	senderFeePercentStr := ""
	if !feePercent.IsZero() {
		senderFeePercentStr = feePercent.String()
	}

	// Build response
	destOnrampResp := types.V2CryptoDestinationOnrampResponse{
		Type:       destination.Type,
		Currency:   destination.Currency,
		ProviderID: destination.ProviderID,
		Recipient:  types.V2CryptoRecipientOnrampResponse{Address: destination.Recipient.Address},
	}
	transactionFee := paymentOrder.NetworkFee.Add(paymentOrder.ProtocolFee)
	response := &types.V2PaymentOrderResponse{
		ID:               paymentOrder.ID,
		Status:           string(paymentOrder.Status),
		Timestamp:        paymentOrder.CreatedAt,
		Amount:           cryptoAmountOut.String(),
		SenderFee:        senderFeeCrypto.String(),
		SenderFeePercent: senderFeePercentStr,
		TransactionFee:   transactionFee.String(),
		Reference:        paymentOrder.Reference,
		ProviderAccount: types.V2FiatProviderAccount{
			Institution:         institutionName,
			AccountIdentifier:   accountIdentifier,
			AccountName:         accountName,
			ValidUntil:          validUntil,
			AmountToTransfer:    totalFiatToPay.String(),
			Currency:            source.Currency,
		},
		Source:      source,
		Destination: destOnrampResp,
	}

	// Add rate to response if available
	if !orderRate.IsZero() {
		response.Rate = orderRate.String()
	}

	u.APIResponse(ctx, http.StatusCreated, "success", "Payment order initiated successfully", response)
}

// GetPaymentOrderByID controller fetches a payment order by ID
func (ctrl *SenderController) GetPaymentOrderByID(ctx *gin.Context) {
	reqCtx := ctx.Request.Context()
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
		Only(reqCtx)
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
		Only(reqCtx)
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
		TransactionFee: paymentOrder.NetworkFee.Add(paymentOrder.ProtocolFee),
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
		ReturnAddress:  refundOrRecipientForDirection(paymentOrder),
		RefundAddress:  refundOrRecipientForDirection(paymentOrder),
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

// GetPaymentOrderByIDV2 returns a single payment order in v2 API schema (providerAccount, source, destination).
func (ctrl *SenderController) GetPaymentOrderByIDV2(ctx *gin.Context) {
	orderID := ctx.Param("id")
	isUUID := true
	id, err := uuid.Parse(orderID)
	if err != nil {
		isUUID = false
	}
	senderCtx, ok := ctx.Get("sender")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	sender := senderCtx.(*ent.SenderProfile)

	paymentOrderQuery := storage.Client.PaymentOrder.Query()
	if isUUID {
		paymentOrderQuery = paymentOrderQuery.Where(paymentorder.IDEQ(id))
	} else {
		paymentOrderQuery = paymentOrderQuery.Where(paymentorder.ReferenceEQ(orderID))
	}
	paymentOrder, err := paymentOrderQuery.
		Where(paymentorder.HasSenderProfileWith(senderprofile.IDEQ(sender.ID))).
		WithProvider().
		WithToken(func(tq *ent.TokenQuery) { tq.WithNetwork() }).
		WithTransactions().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusNotFound, "error", "Payment order not found", nil)
		} else {
			logger.Errorf("error: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch payment order", nil)
		}
		return
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

	var transactionLogs []types.TransactionLog
	for _, tx := range paymentOrder.Edges.Transactions {
		transactionLogs = append(transactionLogs, types.TransactionLog{
			ID:        tx.ID,
			GatewayId: tx.GatewayID,
			Status:    tx.Status,
			TxHash:    tx.TxHash,
			CreatedAt: tx.CreatedAt,
		})
	}
	resp := u.BuildV2PaymentOrderGetResponse(paymentOrder, institution, transactionLogs, nil, nil)
	u.APIResponse(ctx, http.StatusOK, "success", "The order has been successfully retrieved", resp)
}

// GetPaymentOrdersV2 returns a list of payment orders in v2 API schema (no search/export; list only).
func (ctrl *SenderController) GetPaymentOrdersV2(ctx *gin.Context) {
	senderCtx, ok := ctx.Get("sender")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	sender := senderCtx.(*ent.SenderProfile)
	ctrl.handleListPaymentOrdersV2(ctx, sender)
}

// handleListPaymentOrdersV2 handles v2 payment order listing with pagination and v2 response shape.
func (ctrl *SenderController) handleListPaymentOrdersV2(ctx *gin.Context, sender *ent.SenderProfile) {
	ordering := ctx.Query("ordering")
	order := ent.Desc(paymentorder.FieldCreatedAt)
	if ordering == "asc" {
		order = ent.Asc(paymentorder.FieldCreatedAt)
	}
	page, offset, pageSize := u.Paginate(ctx)

	paymentOrderQuery := storage.Client.PaymentOrder.Query().
		Where(paymentorder.HasSenderProfileWith(senderprofile.IDEQ(sender.ID)))
	paymentOrderQuery = ctrl.applyFilters(ctx, paymentOrderQuery)

	count, err := paymentOrderQuery.Count(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch payment orders", nil)
		return
	}

	paymentOrders, err := paymentOrderQuery.
		WithProvider().
		WithToken(func(tq *ent.TokenQuery) { tq.WithNetwork() }).
		WithTransactions().
		Limit(pageSize).
		Offset(offset).
		Order(order).
		All(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch payment orders", nil)
		return
	}

	orders, err := ctrl.buildV2PaymentOrderGetResponses(ctx, paymentOrders)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch payment orders", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Payment orders retrieved successfully", types.V2PaymentOrderListResponse{
		Page:         page,
		PageSize:     pageSize,
		TotalRecords: count,
		Orders:       orders,
	})
}

// buildV2PaymentOrderGetResponses converts payment orders to v2 get response list (batch-fetches institutions).
func (ctrl *SenderController) buildV2PaymentOrderGetResponses(ctx *gin.Context, paymentOrders []*ent.PaymentOrder) ([]types.V2PaymentOrderGetResponse, error) {
	return u.BuildV2PaymentOrderGetResponseList(ctx.Request.Context(), paymentOrders, nil)
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
	reqCtx := ctx.Request.Context()
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

	count, err := paymentOrderQuery.Count(reqCtx)
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
		All(reqCtx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error",
			"Failed to fetch payment orders", nil)
		return
	}

	orders, err := ctrl.buildPaymentOrderResponses(reqCtx, paymentOrders)
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
	reqCtx := ctx.Request.Context()
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
		paymentorder.RefundOrRecipientAddressContainsFold(searchText),
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
	count, err := paymentOrderQuery.Count(reqCtx)
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
		All(reqCtx)
	if err != nil {
		logger.Errorf("Failed to fetch payment orders: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to search payment orders", nil)
		return
	}

	orders, err := ctrl.buildPaymentOrderResponses(reqCtx, paymentOrders)
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
	reqCtx := ctx.Request.Context()
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
	count, err := paymentOrderQuery.Count(reqCtx)
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
		All(reqCtx)
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
	reqCtx := ctx.Request.Context()
	// Filter by status
	statusQueryParam := ctx.Query("status")
	statusMap := map[string]paymentorder.Status{
		"initiated":  paymentorder.StatusInitiated,
		"expired":    paymentorder.StatusExpired,
		"deposited":  paymentorder.StatusDeposited,
		"pending":    paymentorder.StatusPending,
		"cancelled":  paymentorder.StatusCancelled,
		"fulfilling": paymentorder.StatusFulfilling,
		"fulfilled":  paymentorder.StatusFulfilled,
		"validated":  paymentorder.StatusValidated,
		"settling":   paymentorder.StatusSettling,
		"settled":    paymentorder.StatusSettled,
		"refunding":  paymentorder.StatusRefunding,
		"refunded":   paymentorder.StatusRefunded,
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
			Exist(reqCtx)
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
			Exist(reqCtx)
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
func (ctrl *SenderController) buildPaymentOrderResponses(ctx context.Context, paymentOrders []*ent.PaymentOrder) ([]types.SenderOrderResponse, error) {
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
			TransactionFee: paymentOrder.NetworkFee.Add(paymentOrder.ProtocolFee),
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
			ReturnAddress:  refundOrRecipientForDirection(paymentOrder),
			RefundAddress:  refundOrRecipientForDirection(paymentOrder),
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
			refundOrRecipientForDirection(paymentOrder),
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
	reqCtx := ctx.Request.Context()
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
		Scan(reqCtx, &w)
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
		All(reqCtx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch sender stats", nil)
		return
	}

	var localStablecoinSum decimal.Decimal
	var localStablecoinSenderFee decimal.Decimal

	// Convert local stablecoin volume to USD (direction-aware: onramp use buy rate, offramp use sell rate)
	for _, paymentOrder := range paymentOrders {
		institution, err := u.GetInstitutionByCode(reqCtx, paymentOrder.Institution, true)
		if err != nil {
			logger.Errorf("error: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch sender stats", nil)
			return
		}
		if institution == nil || institution.Edges.FiatCurrency == nil {
			continue
		}
		fiatCurrency := institution.Edges.FiatCurrency
		var rate decimal.Decimal
		if paymentOrder.Direction == paymentorder.DirectionOnramp && !fiatCurrency.MarketBuyRate.IsZero() {
			rate = fiatCurrency.MarketBuyRate
		} else if !fiatCurrency.MarketSellRate.IsZero() {
			rate = fiatCurrency.MarketSellRate
		} else {
			continue
		}
		paymentOrder.Amount = paymentOrder.Amount.Div(rate)
		if paymentOrder.SenderFee.GreaterThan(decimal.Zero) {
			paymentOrder.SenderFee = paymentOrder.SenderFee.Div(rate)
		}

		localStablecoinSum = localStablecoinSum.Add(paymentOrder.Amount)
		localStablecoinSenderFee = localStablecoinSenderFee.Add(paymentOrder.SenderFee)
	}

	count, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.HasSenderProfileWith(senderprofile.IDEQ(sender.ID)),
		).
		Count(reqCtx)
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

	reqCtx := ctx.Request.Context()

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
		Only(reqCtx)
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
	tx, err := storage.Client.Tx(reqCtx)
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
		SetPaymentOrderID(paymentOrder.ID).
		Save(reqCtx)
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
	_ = transactionLog

	_, err = tx.PaymentOrder.
		Update().
		Where(paymentorder.IDEQ(paymentOrder.ID)).
		SetStatus(paymentorder.StatusValidated).
		Save(reqCtx)
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
	_ = storage.RedisClient.Del(reqCtx, orderKey).Err()

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
