package provider

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/lockorderfulfillment"
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providercurrencies"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/transactionlog"
	"github.com/paycrest/aggregator/ent/virtualaccount"
	"github.com/paycrest/aggregator/services"
	orderService "github.com/paycrest/aggregator/services/order"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	u "github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"

	"github.com/gin-gonic/gin"
)

var orderConf = config.OrderConfig()

// ProviderController is a controller type for provider endpoints
type ProviderController struct {
	balanceService *services.BalanceManagementService
}

// NewProviderController creates a new instance of ProviderController with injected services
func NewProviderController() *ProviderController {
	return &ProviderController{
		balanceService: services.NewBalanceManagementService(),
	}
}

// GetLockPaymentOrders controller fetches all assigned orders
func (ctrl *ProviderController) GetLockPaymentOrders(ctx *gin.Context) {
	// get page and pageSize query params
	page, offset, pageSize := u.Paginate(ctx)

	// Set ordering
	ordering := ctx.Query("ordering")
	order := ent.Desc(lockpaymentorder.FieldCreatedAt)
	if ordering == "asc" {
		order = ent.Asc(lockpaymentorder.FieldCreatedAt)
	}

	// Get provider profile from the context
	providerCtx, ok := ctx.Get("provider")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	provider := providerCtx.(*ent.ProviderProfile)

	// Start building the base query filtering by provider only
	lockPaymentOrderQuery := storage.Client.LockPaymentOrder.Query().Where(
		lockpaymentorder.HasProviderWith(providerprofile.IDEQ(provider.ID)),
	)

	// Only filter by currency if the query parameter is provided
	currency := ctx.Query("currency")
	if currency != "" {
		// Check if the provided currency exists in the provider's currencies
		currencyExists, err := provider.QueryProviderCurrencies().
			Where(providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currency))).
			Exist(ctx)
		if err != nil {
			logger.Errorf("error checking provider currency: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to check currency", nil)
			return
		}

		if !currencyExists {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Currency not found", nil)
			return
		}

		// Get all institution codes for the given currency in a single query
		institutionCodes, err := storage.Client.Institution.
			Query().
			Where(
				institution.HasFiatCurrencyWith(
					fiatcurrency.CodeEQ(currency),
				),
			).
			Select(institution.FieldCode).
			Strings(ctx)
		if err != nil {
			logger.Errorf("error fetching institution codes: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch institutions", nil)
			return
		}

		// Add the currency filter to the query using the institution codes
		lockPaymentOrderQuery = lockPaymentOrderQuery.Where(
			lockpaymentorder.InstitutionIn(institutionCodes...),
		)
	} else {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Currency is required", nil)
		return
	}

	// Filter by status if provided
	statusMap := map[string]lockpaymentorder.Status{
		"pending":    lockpaymentorder.StatusPending,
		"validated":  lockpaymentorder.StatusValidated,
		"fulfilled":  lockpaymentorder.StatusFulfilled,
		"cancelled":  lockpaymentorder.StatusCancelled,
		"processing": lockpaymentorder.StatusProcessing,
		"settled":    lockpaymentorder.StatusSettled,
	}

	statusQueryParam := ctx.Query("status")
	if status, ok := statusMap[statusQueryParam]; ok {
		lockPaymentOrderQuery = lockPaymentOrderQuery.Where(
			lockpaymentorder.StatusEQ(status),
		)
	}

	count, err := lockPaymentOrderQuery.Count(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch orders", nil)
		return
	}

	// Fetch all orders assigned to the provider
	lockPaymentOrders, err := lockPaymentOrderQuery.
		Limit(pageSize).
		Offset(offset).
		Order(order).
		WithProvider().
		WithToken(
			func(query *ent.TokenQuery) {
				query.WithNetwork()
			},
		).
		All(ctx)
	if err != nil {
		logger.Errorf("error fetching orders: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch orders", nil)
		return
	}

	var orders []types.LockPaymentOrderResponse
	for _, order := range lockPaymentOrders {
		orders = append(orders, types.LockPaymentOrderResponse{
			ID:                  order.ID,
			Token:               order.Edges.Token.Symbol,
			GatewayID:           order.GatewayID,
			Amount:              order.Amount,
			Rate:                order.Rate,
			Institution:         order.Institution,
			AccountIdentifier:   order.AccountIdentifier,
			AccountName:         order.AccountName,
			TxHash:              order.TxHash,
			Status:              order.Status,
			Memo:                order.Memo,
			Network:             order.Edges.Token.Edges.Network.Identifier,
			CancellationReasons: order.CancellationReasons,
			UpdatedAt:           order.UpdatedAt,
			CreatedAt:           order.CreatedAt,
		})
	}

	// return paginated orders
	u.APIResponse(ctx, http.StatusOK, "success", "Orders successfully retrieved", types.ProviderLockOrderList{
		Page:         page,
		PageSize:     pageSize,
		TotalRecords: count,
		Orders:       orders,
	})
}

// AcceptOrder controller accepts an order
func (ctrl *ProviderController) AcceptOrder(ctx *gin.Context) {
	// Get provider profile from the context
	providerCtx, ok := ctx.Get("provider")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	provider := providerCtx.(*ent.ProviderProfile)

	// Parse the Order ID string into a UUID
	orderID, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		logger.Errorf("error parsing order ID: %v", err)
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid Order ID", nil)
		return
	}

	// Get Order request from Redis
	result, err := storage.RedisClient.HGetAll(ctx, fmt.Sprintf("order_request_%s", orderID)).Result()
	if err != nil {
		logger.Errorf("error getting order request from Redis: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to accept order request", nil)
		return
	}

	if result["providerId"] != provider.ID || len(result) == 0 {
		logger.Errorf("order request not found in Redis: %v", orderID)
		u.APIResponse(ctx, http.StatusNotFound, "error", "Order request not found or is expired", nil)
		return
	}

	// Delete order request from Redis
	_, err = storage.RedisClient.Del(ctx, fmt.Sprintf("order_request_%s", orderID)).Result()
	if err != nil {
		logger.Errorf("error deleting order request from Redis: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to accept order request", nil)
		return
	}

	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
		return
	}

	virtualAccount, err := tx.VirtualAccount.
		Query().
		Where(virtualaccount.HasPaymentOrderWith(paymentorder.IDEQ(orderID))).
		WithPaymentOrder(func(poq *ent.PaymentOrderQuery) {
			poq.WithToken(func(tq *ent.TokenQuery) {
				tq.WithNetwork()
			})
		}).
		WithProvider().
		Only(ctx)

	isOnramp := err == nil && virtualAccount != nil

	// Log transaction status
	var transactionLog *ent.TransactionLog
	_, err = tx.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.IDEQ(orderID),
			lockpaymentorder.HasTransactionsWith(
				transactionlog.StatusEQ(transactionlog.StatusOrderProcessing),
			),
		).
		Only(ctx)
	if err != nil {
		if !ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
			return
		} else {
			transactionLog, err = tx.TransactionLog.
				Create().
				SetStatus(transactionlog.StatusOrderProcessing).
				SetMetadata(
					map[string]interface{}{
						"ProviderId": provider.ID,
					}).
				Save(ctx)
			if err != nil {
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
				return
			}
		}
	}

	var orderBuilder *ent.LockPaymentOrderUpdateOne
	if !isOnramp {
		// Update lock order status to processing
		orderBuilder = tx.LockPaymentOrder.
			UpdateOneID(orderID).
			SetStatus(lockpaymentorder.StatusProcessing).
			SetProviderID(provider.ID)
	} else {
		// @TODO: check the amount transferred in to know if we will update the order amount
		// Update lock order status to processing
		_, err := tx.PaymentOrder.
			UpdateOneID(orderID).
			SetStatus(paymentorder.StatusPending).
			Save(ctx)
		if err != nil {
			logger.Errorf("%s - error.AcceptOrder: %v", orderID, err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
			_ = tx.Rollback()
			return
		}
	}

	if transactionLog != nil {
		orderBuilder = orderBuilder.AddTransactions(transactionLog)
	}

	order, err := orderBuilder.Save(ctx)
	if err != nil {
		logger.Errorf("%s - error.AcceptOrder: %v", orderID, err)
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusNotFound, "error", "Order not found", nil)
		} else {
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
		}
		return
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
		return
	}

	if isOnramp {
		// provider should match
		if virtualAccount.Edges.Provider.ID != provider.ID {
			logger.Errorf("provider ID mismatch for onramp order %s: %s vs %s", orderID, virtualAccount.Edges.Provider.ID, provider.ID)
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Provider ID mismatch", nil)
			return
		}

		// update status
		_, err := tx.VirtualAccount.
			UpdateOneID(virtualAccount.ID).
			SetStatus(virtualaccount.StatusUsed).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"OrderID": orderID.String(),
			}).Errorf("Failed to update virtual account status: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to process onramp order", nil)
			_ = tx.Rollback()
			return
		}

		// check amount type
		var amount decimal.Decimal
		if virtualAccount.Edges.PaymentOrder.AmountIn == "crypto" {
			amount = virtualAccount.Edges.PaymentOrder.Amount.Div(virtualAccount.Edges.PaymentOrder.Rate).RoundBank(0)
		} else {
			amount = virtualAccount.Edges.PaymentOrder.Amount.RoundBank(0)
		}

		// Onramp response with network info
		network := virtualAccount.Edges.PaymentOrder.Edges.Token.Edges.Network
		response := &types.AcceptOrderResponse{
			ID:                orderID,
			Type:              "onramp",
			Amount:            amount,
			Institution:       virtualAccount.InstitutionName,
			AccountIdentifier: virtualAccount.AccountIdentifier,
			AccountName:       virtualAccount.AccountName,
			Rate:              virtualAccount.Edges.PaymentOrder.Rate,
			Metadata:          virtualAccount.Metadata,
			Network: &types.NetworkInfo{
				ChainID:                   uint64(network.ChainID),
				RpcURL:                    network.RPCEndpoint,
				DelegationContractAddress: network.DelegationContractAddress,
				Token: &types.TokenInfo{
					Address:  virtualAccount.Edges.PaymentOrder.Edges.Token.ContractAddress,
					Decimals: fmt.Sprintf("%d", virtualAccount.Edges.PaymentOrder.Edges.Token.Decimals),
				},
			},
		}
		u.APIResponse(ctx, http.StatusCreated, "success", "Onramp order request accepted successfully", response)
	} else {
		// Offramp response (existing format)
		response := &types.AcceptOrderResponse{
			ID:                orderID,
			Type:              "offramp",
			Amount:            order.Amount.Mul(order.Rate).RoundBank(0),
			Institution:       order.Institution,
			AccountIdentifier: order.AccountIdentifier,
			AccountName:       order.AccountName,
			Memo:              order.Memo,
			Metadata:          order.Metadata,
		}
		u.APIResponse(ctx, http.StatusCreated, "success", "Order request accepted successfully", response)
	}
}

// DeclineOrder controller declines an order
func (ctrl *ProviderController) DeclineOrder(ctx *gin.Context) {
	// Get provider profile from the context
	providerCtx, ok := ctx.Get("provider")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	provider := providerCtx.(*ent.ProviderProfile)

	// Parse the Order ID string into a UUID
	orderID, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		logger.Errorf("error parsing order ID: %v", err)
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid Order ID", nil)
		return
	}

	// Get Order request from Redis
	result, err := storage.RedisClient.HGetAll(ctx, fmt.Sprintf("order_request_%s", orderID)).Result()
	if err != nil {
		logger.Errorf("error getting order request from Redis: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to decline order request", nil)
		return
	}

	if result["providerId"] != provider.ID || len(result) == 0 {
		logger.Errorf("order request not found in Redis: %v", orderID)
		u.APIResponse(ctx, http.StatusNotFound, "error", "Order request not found or is expired", nil)
		return
	}

	// Delete order request from Redis
	_, err = storage.RedisClient.Del(ctx, fmt.Sprintf("order_request_%s", orderID)).Result()
	if err != nil {
		logger.Errorf("error deleting order request from Redis: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to decline order request", nil)
		return
	}

	// Push provider ID to order exclude list
	orderKey := fmt.Sprintf("order_exclude_list_%s", orderID)
	_, err = storage.RedisClient.RPush(ctx, orderKey, provider.ID).Result()
	if err != nil {
		logger.Errorf("error pushing provider %s to order %s exclude_list on Redis: %v", provider.ID, orderID, err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to decline order request", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Order request declined successfully", nil)
}

// FulfillOrder controller fulfills an order
func (ctrl *ProviderController) FulfillOrder(ctx *gin.Context) {
	var payload types.FulfillLockOrderPayload

	// Parse the order payload
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		logger.WithFields(logger.Fields{
			"Error":            fmt.Sprintf("%v", err),
			"Trx Id":           payload.TxID,
			"ValidationError":  payload.ValidationError,
			"ValidationStatus": payload.ValidationStatus,
		}).Errorf("Failed to bind payload to Json for TXID %v", payload.TxID)
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	// Get provider profile from the context
	_, ok := ctx.Get("provider")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}

	// Parse the Order ID string into a UUID
	orderID, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":  fmt.Sprintf("%v", err),
			"Trx Id": payload.TxID,
		}).Errorf("Error parsing order ID: %v", err)
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid Order ID", nil)
		return
	}

	// Check if this is an onramp order (authorization field is present)
	isOnramp := payload.Authorization != nil

	if isOnramp {
		// Handle onramp order fulfillment
		ctrl.handleOnrampFulfillment(ctx, payload, orderID)
	} else {
		// Handle offramp order fulfillment (existing logic)
		ctrl.handleOfframpFulfillment(ctx, payload, orderID)
	}
}

// CancelOrder controller cancels an order
func (ctrl *ProviderController) CancelOrder(ctx *gin.Context) {
	var payload types.CancelLockOrderPayload

	// Parse the order payload
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		logger.WithFields(logger.Fields{
			"Error":  fmt.Sprintf("%v", err),
			"Reason": payload.Reason,
		}).Errorf("Failed to validate payload: %v", err)
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

	// Parse the Order ID string into a UUID
	orderID, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Reason":   payload.Reason,
			"Order ID": orderID.String(),
		}).Errorf("Error parsing order ID: %v", err)
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid Order ID", nil)
		return
	}

	// Fetch lock payment order from db
	order, err := storage.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.IDEQ(orderID),
			lockpaymentorder.HasProviderWith(providerprofile.IDEQ(provider.ID)),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithProvider().
		WithProvisionBucket(func(pbq *ent.ProvisionBucketQuery) {
			pbq.WithCurrency()
		}).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Reason":   payload.Reason,
			"Order ID": orderID.String(),
		}).Errorf("Failed to fetch lock payment order: %v", err)
		u.APIResponse(ctx, http.StatusNotFound, "error", "Could not find payment order", nil)
		return
	}

	// Get new cancellation count based on cancel reason
	orderUpdate := storage.Client.LockPaymentOrder.UpdateOneID(orderID)
	cancellationCount := order.CancellationCount
	if payload.Reason == "Invalid recipient bank details" || provider.VisibilityMode == providerprofile.VisibilityModePrivate {
		cancellationCount += orderConf.RefundCancellationCount // Allows us refund immediately for invalid recipient
		orderUpdate.AppendCancellationReasons([]string{payload.Reason})
	} else if payload.Reason != "Insufficient funds" {
		cancellationCount += 1
		orderUpdate.AppendCancellationReasons([]string{payload.Reason})
	} else if payload.Reason == "Insufficient funds" {
		// Search for the specific provider in the queue using a Redis list
		redisKey := fmt.Sprintf("bucket_%s_%s_%s", order.Edges.ProvisionBucket.Edges.Currency.Code, order.Edges.ProvisionBucket.MinAmount, order.Edges.ProvisionBucket.MaxAmount)

		// Check if the provider ID exists in the list
		for index := -1; ; index-- {
			providerData, err := storage.RedisClient.LIndex(ctx, redisKey, int64(index)).Result()
			if err != nil {
				break
			}

			// Extract the id from the data (assuming format "providerID:token:rate:minAmount:maxAmount")
			parts := strings.Split(providerData, ":")
			if len(parts) != 5 {
				logger.WithFields(logger.Fields{
					"Provider Data": providerData,
				}).Error("Invalid provider data format")
				continue // Skip this entry due to invalid format
			}

			if parts[0] == provider.ID {
				// Remove the provider from the list
				placeholder := "DELETED_PROVIDER" // Define a placeholder value
				_, err := storage.RedisClient.LSet(ctx, redisKey, int64(index), placeholder).Result()
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error": fmt.Sprintf("%v", err),
						"Index": index,
					}).Errorf("Failed to set placeholder at index %d: %v", index, err)
				}

				// Remove all occurences of the placeholder from the list
				_, err = storage.RedisClient.LRem(ctx, redisKey, 0, placeholder).Result()
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":       fmt.Sprintf("%v", err),
						"Placeholder": placeholder,
					}).Errorf("Failed to remove placeholder from circular queue: %v", err)
				}

				break
			}
		}
	}

	// Update lock order status to cancelled
	_, err = orderUpdate.
		SetStatus(lockpaymentorder.StatusCancelled).
		SetCancellationCount(cancellationCount).
		Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Reason":   payload.Reason,
			"Order ID": orderID.String(),
		}).Errorf("Failed to update lock order status: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to cancel order", nil)
		return
	}

	order.Status = lockpaymentorder.StatusCancelled
	order.CancellationCount = cancellationCount

	// Release reserved balance for this cancelled order
	providerID := order.Edges.Provider.ID
	currency := order.Edges.ProvisionBucket.Edges.Currency.Code
	amount := order.Amount.Mul(order.Rate).RoundBank(0)

	err = ctrl.balanceService.ReleaseReservedBalance(ctx, providerID, currency, amount, nil)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    orderID.String(),
			"ProviderID": providerID,
			"Currency":   currency,
			"Amount":     amount.String(),
		}).Errorf("failed to release reserved balance for cancelled order")
		// Don't return error here as the order status is already updated
	}

	// Check if order cancellation count is equal or greater than RefundCancellationCount in config,
	// and the order has not been refunded, then trigger refund
	if order.CancellationCount >= orderConf.RefundCancellationCount && order.Status == lockpaymentorder.StatusCancelled {
		go func() {
			var err error
			if strings.HasPrefix(order.Edges.Token.Edges.Network.Identifier, "tron") {
				err = orderService.NewOrderTron().RefundOrder(ctx, order.Edges.Token.Edges.Network, order.GatewayID)
			} else {
				err = orderService.NewOrderEVM().RefundOrder(ctx, order.Edges.Token.Edges.Network, order.GatewayID)
			}
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":    fmt.Sprintf("%v", err),
					"Reason":   "CancelOrder.RefundOrder",
					"Order ID": orderID.String(),
					"Network":  order.Edges.Token.Edges.Network.Identifier,
				}).Errorf("Failed to refund order: %v", err)
			}
		}()
	}

	// Push provider ID to order exclude list
	orderKey := fmt.Sprintf("order_exclude_list_%s", orderID)
	_, err = storage.RedisClient.RPush(ctx, orderKey, provider.ID).Result()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Provider": provider.ID,
			"Order ID": orderID.String(),
		}).Errorf("Failed to push provider %s to order %s exclude_list on Redis: %v", provider.ID, orderID, err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to decline order request", nil)
		return
	}

	// TODO: Reassign order to another provider in background

	u.APIResponse(ctx, http.StatusOK, "success", "Order cancelled successfully", nil)
}

// GetMarketRate controller fetches the median rate of the cryptocurrency token against the fiat currency
func (ctrl *ProviderController) GetMarketRate(ctx *gin.Context) {
	// Parse path parameters
	tokenObj, err := storage.Client.Token.
		Query().
		Where(
			token.SymbolEQ(strings.ToUpper(ctx.Param("token"))),
			token.IsEnabledEQ(true),
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("Token %s is not supported", strings.ToUpper(ctx.Param("token"))), nil)
			return
		}
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
		}).Errorf("Failed to get market rate: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to get market rate", nil)
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
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Token": tokenObj.Symbol,
			"Fiat":  ctx.Param("fiat"),
		}).Errorf("Failed to get market rate: %v", err)
		u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("Fiat currency %s is not supported", strings.ToUpper(ctx.Param("fiat"))), nil)
		return
	}

	if !strings.EqualFold(tokenObj.BaseCurrency, currency.Code) && !strings.EqualFold(tokenObj.BaseCurrency, "USD") {
		u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("%s can only be converted to %s", tokenObj.Symbol, tokenObj.BaseCurrency), nil)
		return
	}

	var response *types.MarketRateResponse
	if !strings.EqualFold(tokenObj.BaseCurrency, currency.Code) {
		deviation := currency.MarketRate.Mul(orderConf.PercentDeviationFromMarketRate.Div(decimal.NewFromInt(100)))

		response = &types.MarketRateResponse{
			MarketRate:  currency.MarketRate,
			MinimumRate: currency.MarketRate.Sub(deviation),
			MaximumRate: currency.MarketRate.Add(deviation),
		}
	} else {
		response = &types.MarketRateResponse{
			MarketRate:  decimal.NewFromInt(1),
			MinimumRate: decimal.NewFromInt(1),
			MaximumRate: decimal.NewFromInt(1),
		}
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Rate fetched successfully", response)
}

// Stats controller fetches provider stats
func (ctrl *ProviderController) Stats(ctx *gin.Context) {
	// Get provider profile from the context
	providerCtx, ok := ctx.Get("provider")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	provider := providerCtx.(*ent.ProviderProfile)

	// Check if currency in query is present in provider currencies
	currency := ctx.Query("currency")
	if currency != "" {
		currencyExists, err := provider.QueryProviderCurrencies().
			Where(providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currency))).
			Exist(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":    fmt.Sprintf("%v", err),
				"Provider": provider.ID,
				"Currency": currency,
			}).Errorf("Failed to check provider currency: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to check currency", nil)
			return
		}

		if !currencyExists {
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Currency not found", nil)
			return
		}
	} else {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Currency is required", nil)
		return
	}

	// Get all institution codes for the given currency in a single query
	institutionCodes, err := storage.Client.Institution.
		Query().
		Where(
			institution.HasFiatCurrencyWith(
				fiatcurrency.CodeEQ(currency),
			),
		).
		Select(institution.FieldCode).
		Strings(ctx)
	if err != nil {
		logger.Errorf("error fetching institution codes: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch institutions", nil)
		return
	}

	// Fetch provider stats
	query := storage.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.HasProviderWith(providerprofile.IDEQ(provider.ID)),
			lockpaymentorder.StatusEQ(lockpaymentorder.StatusSettled),
			lockpaymentorder.InstitutionIn(institutionCodes...),
		)

	// Get USD volume
	var usdVolume []struct {
		Sum decimal.Decimal
	}
	err = query.
		Where(lockpaymentorder.HasTokenWith(token.BaseCurrencyEQ("USD"))).
		Aggregate(
			ent.Sum(lockpaymentorder.FieldAmount),
		).
		Scan(ctx, &usdVolume)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Provider": provider.ID,
			"Currency": currency,
		}).Errorf("Failed to fetch provider stats: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch provider stats", nil)
		return
	}

	// Get local stablecoin volume
	var localStablecoinVolume []struct {
		Sum decimal.Decimal
	}
	err = query.
		Where(
			lockpaymentorder.HasTokenWith(token.BaseCurrencyEQ(currency)),
			lockpaymentorder.HasTokenWith(token.BaseCurrencyNEQ("USD")),
		).
		Aggregate(
			ent.Sum(lockpaymentorder.FieldAmount),
		).
		Scan(ctx, &localStablecoinVolume)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Provider": provider.ID,
			"Currency": currency,
		}).Errorf("Failed to fetch provider stats: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch provider stats", nil)
		return
	}
	if localStablecoinVolume[0].Sum.GreaterThan(decimal.NewFromInt(0)) {
		// Divide local stablecoin volume by market rate of the currency
		fiatCurrency, err := storage.Client.FiatCurrency.
			Query().
			Where(fiatcurrency.CodeEQ(currency)).
			Only(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":    fmt.Sprintf("%v", err),
				"Provider": provider.ID,
				"Currency": currency,
			}).Errorf("Failed to fetch provider fiat currency: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch provider stats", nil)
			return
		}
		localStablecoinVolume[0].Sum = localStablecoinVolume[0].Sum.Div(fiatCurrency.MarketRate)
	}

	var totalFiatVolume decimal.Decimal
	settledOrders, err := storage.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.HasProviderWith(providerprofile.IDEQ(provider.ID)),
			lockpaymentorder.StatusEQ(lockpaymentorder.StatusSettled),
			lockpaymentorder.InstitutionIn(institutionCodes...),
		).
		All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Provider": provider.ID,
			"Currency": currency,
		}).Errorf("Failed to fetch settled orders: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch provider stats", nil)
		return
	}
	for _, order := range settledOrders {
		totalFiatVolume = totalFiatVolume.Add(order.Amount.Mul(order.Rate).RoundBank(2))
	}

	count, err := storage.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.HasProviderWith(providerprofile.IDEQ(provider.ID)),
			lockpaymentorder.InstitutionIn(institutionCodes...),
		).
		Count(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Provider": provider.ID,
			"Currency": currency,
		}).Errorf("Failed to fetch provider counts with institution codes: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch provider stats", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Provider stats fetched successfully", &types.ProviderStatsResponse{
		TotalOrders:       count,
		TotalFiatVolume:   totalFiatVolume,
		TotalCryptoVolume: usdVolume[0].Sum.Add(localStablecoinVolume[0].Sum),
	})
}

// NodeInfo controller fetches the provision node info
func (ctrl *ProviderController) NodeInfo(ctx *gin.Context) {
	// Get provider profile from the context
	providerCtx, ok := ctx.Get("provider")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}

	provider, err := storage.Client.ProviderProfile.
		Query().
		Where(providerprofile.IDEQ(providerCtx.(*ent.ProviderProfile).ID)).
		WithAPIKey().
		WithProviderCurrencies(
			func(query *ent.ProviderCurrenciesQuery) {
				query.WithCurrency()
			},
		).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
		}).Errorf("Failed to fetch provider: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch node info", nil)
		return
	}

	// Try to fetch from /info endpoint first (for new providers)
	var data map[string]interface{}
	var currencyCodes []string

	res, err := fastshot.NewClient(provider.HostIdentifier).
		Config().SetTimeout(30 * time.Second).
		Build().GET("/info").
		Send()

	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Provider": provider.ID,
			"Host":     provider.HostIdentifier,
		}).Errorf("Failed to fetch node info from /info endpoint: %v", err)
		u.APIResponse(ctx, http.StatusServiceUnavailable, "error", "Failed to fetch node info", nil)
		return
	}

	data, err = u.ParseJSONResponse(res.RawResponse)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
		}).Errorf("failed to parse node info: %v", err)
		u.APIResponse(ctx, http.StatusServiceUnavailable, "error", "Failed to fetch node info", nil)
		return
	}

	// Handle new provider response format with serviceInfo
	dataMap, ok := data["data"].(map[string]interface{})
	if !ok {
		logger.WithFields(logger.Fields{
			"Error": "data field is not a map",
		}).Errorf("failed to parse node info: data field is not a map")
		u.APIResponse(ctx, http.StatusServiceUnavailable, "error", "Invalid data format", nil)
		return
	}

	serviceInfo, ok := dataMap["serviceInfo"].(map[string]interface{})
	if !ok {
		logger.WithFields(logger.Fields{
			"Error": "serviceInfo field is not a map",
		}).Errorf("failed to parse node info: serviceInfo field is not a map")
		u.APIResponse(ctx, http.StatusServiceUnavailable, "error", "Invalid service info format", nil)
		return
	}

	currenciesData, ok := serviceInfo["currencies"].([]interface{})
	if !ok {
		logger.WithFields(logger.Fields{
			"Error": "currencies field is not an array",
		}).Errorf("failed to parse node info: currencies field is not an array")
		u.APIResponse(ctx, http.StatusServiceUnavailable, "error", "Currencies data is not in expected format", nil)
		return
	}

	// Convert []interface{} to []string
	for _, currency := range currenciesData {
		if code, ok := currency.(string); ok {
			currencyCodes = append(currencyCodes, code)
		}
	}

	for _, pc := range provider.Edges.ProviderCurrencies {
		if !u.ContainsString(currencyCodes, pc.Edges.Currency.Code) {
			logger.WithFields(logger.Fields{
				"Error":    "currency not found in node response",
				"Currency": pc.Edges.Currency.Code,
			}).Errorf("failed to parse node info: currency %s not found in node response", pc.Edges.Currency.Code)
			u.APIResponse(ctx, http.StatusServiceUnavailable, "error", "Failed to fetch node info", nil)
			return
		}
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Node info fetched successfully", data)
}

// GetLockPaymentOrderByID controller fetches a payment order by ID
func (ctrl *ProviderController) GetLockPaymentOrderByID(ctx *gin.Context) {
	// Get order ID from the URL
	orderID := ctx.Param("id")

	// Convert order ID to UUID
	id, err := uuid.Parse(orderID)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Order ID": orderID,
		}).Errorf("Failed to parse order ID: %v", err)
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Invalid order ID", nil)
		return
	}

	// Get provider profile from the context
	providerCtx, ok := ctx.Get("provider")

	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	provider := providerCtx.(*ent.ProviderProfile)

	// Fetch payment order from the database
	lockPaymentOrder, err := storage.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.IDEQ(id),
			lockpaymentorder.HasProviderWith(providerprofile.IDEQ(provider.ID)),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithTransactions().
		Only(ctx)

	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Order ID": orderID,
		}).Errorf("Failed to fetch locked payment order: %v", err)
		u.APIResponse(ctx, http.StatusNotFound, "error",
			"Payment order not found", nil)
		return
	}
	var transactions []types.TransactionLog
	for _, transaction := range lockPaymentOrder.Edges.Transactions {
		transactions = append(transactions, types.TransactionLog{
			ID:        transaction.ID,
			GatewayId: transaction.GatewayID,
			Status:    transaction.Status,
			TxHash:    transaction.TxHash,
			CreatedAt: transaction.CreatedAt,
		})

	}

	u.APIResponse(ctx, http.StatusOK, "success", "The order has been successfully retrieved", &types.LockPaymentOrderResponse{
		ID:                  lockPaymentOrder.ID,
		Token:               lockPaymentOrder.Edges.Token.Symbol,
		GatewayID:           lockPaymentOrder.GatewayID,
		Amount:              lockPaymentOrder.Amount,
		Rate:                lockPaymentOrder.Rate,
		Institution:         lockPaymentOrder.Institution,
		AccountIdentifier:   lockPaymentOrder.AccountIdentifier,
		AccountName:         lockPaymentOrder.AccountName,
		TxHash:              lockPaymentOrder.TxHash,
		Status:              lockPaymentOrder.Status,
		Memo:                lockPaymentOrder.Memo,
		Network:             lockPaymentOrder.Edges.Token.Edges.Network.Identifier,
		UpdatedAt:           lockPaymentOrder.UpdatedAt,
		CreatedAt:           lockPaymentOrder.CreatedAt,
		Transactions:        transactions,
		CancellationReasons: lockPaymentOrder.CancellationReasons,
	})
}

// UpdateProviderBalance handles the update of provider balance
func (ctrl *ProviderController) UpdateProviderBalance(ctx *gin.Context) {
	// Extract provider from HMAC middleware context
	providerInterface, exists := ctx.Get("provider")
	if !exists {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Provider not found in context", nil)
		return
	}

	provider, ok := providerInterface.(*ent.ProviderProfile)
	if !ok {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Invalid provider type in context", nil)
		return
	}

	// Parse the request payload
	var payload struct {
		Currency         string `json:"currency" binding:"required,min=3,max=7"`
		AvailableBalance string `json:"availableBalance" binding:"required,numeric"`
		TotalBalance     string `json:"totalBalance" binding:"required,numeric"`
		ReservedBalance  string `json:"reservedBalance" binding:"required,numeric"`
	}

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	// Parse balance amounts
	availableBalance, err := decimal.NewFromString(payload.AvailableBalance)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid available balance format", []types.ErrorData{{
			Field:   "AvailableBalance",
			Message: "Invalid available balance format",
		}})
		return
	}

	totalBalance, err := decimal.NewFromString(payload.TotalBalance)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid total balance format", []types.ErrorData{{
			Field:   "TotalBalance",
			Message: "Invalid total balance format",
		}})
		return
	}

	reservedBalance, err := decimal.NewFromString(payload.ReservedBalance)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid reserved balance format", []types.ErrorData{{
			Field:   "ReservedBalance",
			Message: "Invalid reserved balance format",
		}})
		return
	}

	// Update the balance using the provider ID from context
	err = ctrl.balanceService.UpdateProviderBalance(ctx, provider.ID, payload.Currency, availableBalance, totalBalance, reservedBalance)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": provider.ID,
			"Currency":   payload.Currency,
		}).Errorf("Failed to update provider balance")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update balance", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Balance updated successfully", nil)
}

func (ctrl *ProviderController) handleOfframpFulfillment(ctx *gin.Context, payload types.FulfillLockOrderPayload, orderID uuid.UUID) {
	// Existing offramp logic (unchanged)
	updateLockOrder := storage.Client.LockPaymentOrder.
		Update().
		Where(
			lockpaymentorder.IDEQ(orderID),
			lockpaymentorder.Or(
				lockpaymentorder.StatusEQ(lockpaymentorder.StatusProcessing),
				lockpaymentorder.StatusEQ(lockpaymentorder.StatusFulfilled),
			),
		)

	// Query or create lock order fulfillment
	fulfillment, err := storage.Client.LockOrderFulfillment.
		Query().
		Where(lockorderfulfillment.TxIDEQ(payload.TxID)).
		WithOrder(func(poq *ent.LockPaymentOrderQuery) {
			poq.WithToken(func(tq *ent.TokenQuery) {
				tq.WithNetwork()
			})
			poq.WithProvider()
			poq.WithProvisionBucket(func(pbq *ent.ProvisionBucketQuery) {
				pbq.WithCurrency()
			})
		}).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			_, err = storage.Client.LockOrderFulfillment.
				Create().
				SetOrderID(orderID).
				SetTxID(payload.TxID).
				SetPsp(payload.PSP).
				Save(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":  fmt.Sprintf("%v", err),
					"Trx Id": payload.TxID,
				}).Errorf("Failed to create lock order fulfillment: %v", err)
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
				return
			}

			fulfillment, err = storage.Client.LockOrderFulfillment.
				Query().
				Where(lockorderfulfillment.TxIDEQ(payload.TxID)).
				WithOrder(func(poq *ent.LockPaymentOrderQuery) {
					poq.WithToken(func(tq *ent.TokenQuery) {
						tq.WithNetwork()
					})
				}).
				Only(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   fmt.Sprintf("%v", err),
					"Trx Id":  payload.TxID,
					"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
				}).Errorf("Failed to fetch lock order fulfillment: %v", err)
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
				return
			}
		} else {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to fetch lock order fulfillment when order is found: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
			return
		}
	}

	switch payload.ValidationStatus {
	case lockorderfulfillment.ValidationStatusSuccess:
		if fulfillment.Edges.Order.Status == lockpaymentorder.StatusValidated {
			u.APIResponse(ctx, http.StatusOK, "success", "Order already validated", nil)
			return
		}

		// Start a database transaction to ensure consistency
		tx, err := storage.Client.Tx(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to start transaction: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
			return
		}

		// Update fulfillment status within transaction
		_, err = tx.LockOrderFulfillment.
			UpdateOneID(fulfillment.ID).
			SetValidationStatus(lockorderfulfillment.ValidationStatusSuccess).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to update lock order fulfillment: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
			_ = tx.Rollback()
			return
		}

		// Create transaction log within transaction
		transactionLog, err := tx.TransactionLog.Create().
			SetStatus(transactionlog.StatusOrderValidated).
			SetNetwork(fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier).
			SetMetadata(map[string]interface{}{
				"TransactionID": payload.TxID,
				"PSP":           payload.PSP,
			}).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to create transaction log: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
			_ = tx.Rollback()
			return
		}

		// Update lock order status within transaction
		_, err = tx.LockPaymentOrder.
			Update().
			Where(lockpaymentorder.IDEQ(orderID)).
			SetStatus(lockpaymentorder.StatusValidated).
			AddTransactions(transactionLog).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to update lock order status: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
			_ = tx.Rollback()
			return
		}

		// Release reserved balance within the same transaction
		providerID := fulfillment.Edges.Order.Edges.Provider.ID
		currency := fulfillment.Edges.Order.Edges.ProvisionBucket.Edges.Currency.Code
		amount := fulfillment.Edges.Order.Amount.Mul(fulfillment.Edges.Order.Rate).RoundBank(0)

		err = ctrl.balanceService.ReleaseReservedBalance(ctx, providerID, currency, amount, tx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"OrderID":    orderID.String(),
				"ProviderID": providerID,
				"Currency":   currency,
				"Amount":     amount.String(),
			}).Errorf("failed to release reserved balance for fulfilled order")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
			_ = tx.Rollback()
			return
		}

		// Commit the transaction
		if err := tx.Commit(); err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to commit transaction: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
			return
		}

		// Mark payment order as validated and send webhook notification to sender
		paymentOrder, err := storage.Client.PaymentOrder.
			Query().
			Where(paymentorder.MessageHashEQ(fulfillment.Edges.Order.MessageHash)).
			WithSenderProfile().
			WithRecipient().
			WithToken(func(tq *ent.TokenQuery) {
				tq.WithNetwork()
			}).
			Only(ctx)
		if err == nil && paymentOrder != nil {
			_, err = paymentOrder.Update().
				SetStatus(paymentorder.StatusValidated).
				Save(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   fmt.Sprintf("%v", err),
					"Trx Id":  payload.TxID,
					"Network": paymentOrder.Edges.Token.Edges.Network.Identifier,
				}).Errorf("Failed to update payment order status: %v", err)
			}

			err = u.SendPaymentOrderWebhook(ctx, paymentOrder)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   fmt.Sprintf("%v", err),
					"Trx Id":  payload.TxID,
					"Network": paymentOrder.Edges.Token.Edges.Network.Identifier,
				}).Errorf("Failed to send webhook notification to sender: %v", err)
			}
		}

		// Settle order or fail silently
		go func() {
			var err error
			if strings.HasPrefix(fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier, "tron") {
				err = orderService.NewOrderTron().SettleOrder(ctx, orderID)
			} else {
				err = orderService.NewOrderEVM().SettleOrder(ctx, orderID)
			}
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   fmt.Sprintf("%v", err),
					"Trx Id":  payload.TxID,
					"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
				}).Errorf("Failed to settle order: %v", err)
			}
		}()

	case lockorderfulfillment.ValidationStatusFailed:
		_, err = fulfillment.Update().
			SetValidationStatus(lockorderfulfillment.ValidationStatusFailed).
			SetValidationError(payload.ValidationError).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to update lock order fulfillment: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
			return
		}

		_, err = updateLockOrder.
			SetStatus(lockpaymentorder.StatusFulfilled).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to update lock order status: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
			return
		}

		// Release reserved balance for failed validation
		providerID := fulfillment.Edges.Order.Edges.Provider.ID
		currency := fulfillment.Edges.Order.Edges.ProvisionBucket.Edges.Currency.Code
		amount := fulfillment.Edges.Order.Amount.Mul(fulfillment.Edges.Order.Rate).RoundBank(0)

		err = ctrl.balanceService.ReleaseReservedBalance(ctx, providerID, currency, amount, nil)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"OrderID":    orderID.String(),
				"ProviderID": providerID,
				"Currency":   currency,
				"Amount":     amount.String(),
			}).Errorf("failed to release reserved balance for failed validation")
			// Don't return error here as the order status is already updated
		}

	default:
		transactionLog, err := storage.Client.TransactionLog.Create().
			SetStatus(transactionlog.StatusOrderFulfilled).
			SetNetwork(fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier).
			SetMetadata(map[string]interface{}{
				"TransactionID": payload.TxID,
				"PSP":           payload.PSP,
			}).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to create transaction log: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
			return
		}

		_, err = updateLockOrder.
			SetStatus(lockpaymentorder.StatusFulfilled).
			AddTransactions(transactionLog).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to update lock order status: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update lock order status", nil)
			return
		}
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Order fulfilled successfully", nil)
}

func (ctrl *ProviderController) handleOnrampFulfillment(ctx *gin.Context, payload types.FulfillLockOrderPayload, orderID uuid.UUID) {
	// For onramp orders, we work with PaymentOrder and VirtualAccount
	virtualAccount, err := storage.Client.VirtualAccount.
		Query().
		Where(
			virtualaccount.HasPaymentOrderWith(paymentorder.IDEQ(orderID)),
			virtualaccount.StatusEQ(virtualaccount.StatusUsed),
		).
		WithPaymentOrder(func(poq *ent.PaymentOrderQuery) {
			poq.WithToken(func(tq *ent.TokenQuery) {
				tq.WithNetwork()
			}).WithSenderProfile()
		}).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":   fmt.Sprintf("%v", err),
			"OrderID": orderID.String(),
		}).Errorf("Failed to fetch virtual account for onramp order: %v", err)
		u.APIResponse(ctx, http.StatusNotFound, "error", "Onramp order not found", nil)
		return
	}

	_ = storage.Client.VirtualAccount.
		UpdateOneID(virtualAccount.ID).
		SetProviderAddress(payload.ProviderAddress).
		Save(ctx)

	paymentOrder := virtualAccount.Edges.PaymentOrder

	switch payload.ValidationStatus {
	case lockorderfulfillment.ValidationStatusSuccess:
		tx, err := storage.Client.Tx(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"OrderID": orderID.String(),
			}).Errorf("Failed to start transaction for onramp fulfillment: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to process onramp order", nil)
			return
		}

		// Create transaction log for onramp validation
		transactionLog, err := tx.TransactionLog.Create().
			SetStatus(transactionlog.StatusOrderValidated).
			SetNetwork(paymentOrder.Edges.Token.Edges.Network.Identifier).
			SetMetadata(map[string]interface{}{
				"TransactionID": payload.TxID,
				"PSP":           payload.PSP,
				"OrderType":     "onramp",
				"Authorization": payload.Authorization,
			}).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"OrderID": orderID.String(),
			}).Errorf("Failed to create transaction log for onramp: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to process onramp order", nil)
			_ = tx.Rollback()
			return
		}

		// Update payment order status to validated
		_, err = tx.PaymentOrder.
			UpdateOneID(orderID).
			SetStatus(paymentorder.StatusValidated).
			AddTransactions(transactionLog).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"OrderID": orderID.String(),
			}).Errorf("Failed to update onramp payment order status: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to process onramp order", nil)
			_ = tx.Rollback()
			return
		}

		// Commit the transaction
		if err := tx.Commit(); err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"OrderID": orderID.String(),
			}).Errorf("Failed to commit onramp transaction: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to process onramp order", nil)
			return
		}

		// Send webhook notification to sender
		// err = u.SendPaymentOrderWebhook(ctx, paymentOrder)
		// if err != nil {
		// 	logger.WithFields(logger.Fields{
		// 		"Error":   fmt.Sprintf("%v", err),
		// 		"OrderID": orderID.String(),
		// 	}).Errorf("Failed to send webhook notification for onramp order: %v", err)
		// }

		// Settle onramp order
		go func() {
			var err error
			if strings.HasPrefix(paymentOrder.Edges.Token.Edges.Network.Identifier, "tron") {
				err = orderService.NewOrderTron().SettleOrder(ctx, orderID)
			} else {
				err = orderService.NewOrderEVM().SettleOrder(ctx, orderID)
			}
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   fmt.Sprintf("%v", err),
					"OrderID": orderID.String(),
				}).Errorf("Failed to settle onramp order: %v", err)
			}
		}()

	case lockorderfulfillment.ValidationStatusFailed:
		// Update payment order status to failed
		_, err = storage.Client.PaymentOrder.
			UpdateOneID(orderID).
			SetStatus(paymentorder.StatusRefunded).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"OrderID": orderID.String(),
			}).Errorf("Failed to update onramp payment order to failed: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to process onramp order", nil)
			return
		}

		u.APIResponse(ctx, http.StatusOK, "success", "Onramp order processed successfully", nil)
	}
}
