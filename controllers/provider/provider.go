package provider

import (
	"context"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/paymentorderfulfillment"
	"github.com/paycrest/aggregator/ent/predicate"
	"github.com/paycrest/aggregator/ent/providerbalances"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/senderordertoken"
	"github.com/paycrest/aggregator/ent/senderprofile"
	"github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/transactionlog"
	"github.com/paycrest/aggregator/services/balance"
	"github.com/paycrest/aggregator/services/contracts"
	orderService "github.com/paycrest/aggregator/services/order"
	starknetService "github.com/paycrest/aggregator/services/starknet"
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
	balanceService *balance.Service
}

// NewProviderController creates a new instance of ProviderController with injected services
func NewProviderController() *ProviderController {
	return &ProviderController{
		balanceService: balance.New(),
	}
}

// GetPaymentOrders controller fetches all assigned orders
func (ctrl *ProviderController) GetPaymentOrders(ctx *gin.Context) {
	// Get provider profile from the context
	providerCtx, ok := ctx.Get("provider")
	if !ok {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		return
	}
	provider := providerCtx.(*ent.ProviderProfile)

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
		ctrl.handleExportPaymentOrders(ctx, provider)
		return
	}

	// Handle search request
	if isSearch {
		ctrl.handleSearchPaymentOrders(ctx, provider, searchText)
		return
	}

	// Handle normal listing
	ctrl.handleListPaymentOrders(ctx, provider)
}

// handleListPaymentOrders handles normal payment order listing with pagination
func (ctrl *ProviderController) handleListPaymentOrders(ctx *gin.Context, provider *ent.ProviderProfile) {
	// get page and pageSize query params
	page, offset, pageSize := u.Paginate(ctx)

	// Set ordering
	ordering := ctx.Query("ordering")
	order := ent.Desc(paymentorder.FieldCreatedAt)
	if ordering == "asc" {
		order = ent.Asc(paymentorder.FieldCreatedAt)
	}

	// Start building the base query filtering by provider only
	paymentOrderQuery := storage.Client.PaymentOrder.Query().Where(
		paymentorder.HasProviderWith(providerprofile.IDEQ(provider.ID)),
	)

	// Only filter by currency if the query parameter is provided
	currency := ctx.Query("currency")
	if currency != "" {
		// Check if the provided currency exists in the provider's currencies
		currencyExists, err := provider.QueryProviderBalances().
			Where(providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currency))).
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
		paymentOrderQuery = paymentOrderQuery.Where(
			paymentorder.InstitutionIn(institutionCodes...),
		)
	} else {
		// Currency is required for normal listing
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Currency is required", nil)
		return
	}

	// Filter by status if provided
	statusMap := map[string]paymentorder.Status{
		"pending":    paymentorder.StatusPending,
		"validated":  paymentorder.StatusValidated,
		"fulfilled":  paymentorder.StatusFulfilled,
		"cancelled":  paymentorder.StatusCancelled,
		"processing": paymentorder.StatusFulfilling, // Backward compatibility
		"settled":    paymentorder.StatusSettled,
	}

	statusQueryParam := ctx.Query("status")
	if status, ok := statusMap[statusQueryParam]; ok {
		paymentOrderQuery = paymentOrderQuery.Where(
			paymentorder.StatusEQ(status),
		)
	}

	count, err := paymentOrderQuery.Count(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch orders", nil)
		return
	}

	// Apply pagination limits for normal listing

	// Fetch all orders assigned to the provider
	paymentOrders, err := paymentOrderQuery.
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

	var orders []types.ProviderOrderResponse
	for _, order := range paymentOrders {
		orders = append(orders, func(order *ent.PaymentOrder) types.ProviderOrderResponse {
			response := types.ProviderOrderResponse{
				ID:                  order.ID,
				Token:               order.Edges.Token.Symbol,
				GatewayID:           order.GatewayID,
				Amount:              order.Amount,
				AmountInUSD:         order.AmountInUsd,
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
				OrderType:           order.OrderType,
			}

			if order.OrderType == paymentorder.OrderTypeOtc && order.Edges.Provider != nil {
				switch order.Status {
				case paymentorder.StatusPending:
					response.OTCExpiry = order.UpdatedAt.Add(orderConf.OrderRequestValidityOtc)
				case paymentorder.StatusFulfilling:
					response.OTCExpiry = order.UpdatedAt.Add(orderConf.OrderFulfillmentValidityOtc)
				}
			}

			return response
		}(order))
	}

	// return paginated orders (consistent format for both search and regular queries)
	u.APIResponse(ctx, http.StatusOK, "success", "Orders successfully retrieved", types.ProviderOrderList{
		Page:         page,
		PageSize:     pageSize,
		TotalRecords: count,
		Orders:       orders,
	})
}

// handleSearchPaymentOrders handles search functionality for payment orders
func (ctrl *ProviderController) handleSearchPaymentOrders(ctx *gin.Context, provider *ent.ProviderProfile, searchText string) {
	// Build base query
	paymentOrderQuery := storage.Client.PaymentOrder.Query().Where(
		paymentorder.HasProviderWith(providerprofile.IDEQ(provider.ID)),
	)

	// Apply text search across all relevant fields
	var searchPredicates []predicate.PaymentOrder

	// Try to parse search text as UUID for exact ID match
	if searchUUID, err := uuid.Parse(searchText); err == nil {
		searchPredicates = append(searchPredicates, paymentorder.IDEQ(searchUUID))
	}

	searchPredicates = append(searchPredicates,
		paymentorder.AccountIdentifierContainsFold(searchText),
		paymentorder.AccountNameContainsFold(searchText),
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

	// Transform to response format
	var orders []types.ProviderOrderResponse
	for _, order := range paymentOrders {
		orders = append(orders, types.ProviderOrderResponse{
			ID:                  order.ID,
			Token:               order.Edges.Token.Symbol,
			GatewayID:           order.GatewayID,
			Amount:              order.Amount,
			AmountInUSD:         order.AmountInUsd,
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
			OrderType:           order.OrderType,
		})
	}

	// Return search results using standard response format
	u.APIResponse(ctx, http.StatusOK, "success", "Orders successfully retrieved", types.ProviderOrderList{
		Page:         1,
		PageSize:     len(orders),
		TotalRecords: count,
		Orders:       orders,
	})
}

// handleExportPaymentOrders handles CSV export functionality for payment orders
func (ctrl *ProviderController) handleExportPaymentOrders(ctx *gin.Context, provider *ent.ProviderProfile) {
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

	// Set export limit
	maxExportLimit := 10000
	if limit := ctx.Query("limit"); limit != "" {
		if parsedLimit, err := strconv.Atoi(limit); err == nil && parsedLimit > 0 && parsedLimit <= maxExportLimit {
			maxExportLimit = parsedLimit
		}
	}

	// Build query for provider's orders with date range filter
	paymentOrderQuery := storage.Client.PaymentOrder.Query().Where(
		paymentorder.HasProviderWith(providerprofile.IDEQ(provider.ID)),
	)

	// Apply date range filters
	if fromDate != nil {
		paymentOrderQuery = paymentOrderQuery.Where(paymentorder.CreatedAtGTE(*fromDate))
	}
	if toDate != nil {
		paymentOrderQuery = paymentOrderQuery.Where(paymentorder.CreatedAtLTE(*toDate))
	}

	// Get total count first
	count, err := paymentOrderQuery.Count(ctx)
	if err != nil {
		logger.Errorf("Failed to count payment orders for export: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to export payment orders", nil)
		return
	}

	if count == 0 {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "No orders found in the specified date range", nil)
		return
	}

	// Check if export is too large
	if count > maxExportLimit {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			fmt.Sprintf("Export too large. Found %d orders, maximum allowed is %d. Please use a smaller date range.",
				count, maxExportLimit), nil)
		return
	}

	// Execute query with eager loading
	paymentOrders, err := paymentOrderQuery.
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithProvisionBucket(func(pbq *ent.ProvisionBucketQuery) {
			pbq.WithCurrency()
		}).
		Limit(maxExportLimit).
		Order(ent.Desc(paymentorder.FieldCreatedAt), ent.Desc(paymentorder.FieldID)).
		All(ctx)
	if err != nil {
		logger.Errorf("Failed to fetch lock payment orders for export: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to export payment orders", nil)
		return
	}

	// Set CSV headers
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("lock_payment_orders_%s.csv", timestamp)

	ctx.Header("Content-Type", "text/csv")
	ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	ctx.Header("X-Total-Count", strconv.Itoa(count))

	// Create CSV writer
	writer := csv.NewWriter(ctx.Writer)
	defer writer.Flush()

	// Write CSV header
	csvHeaders := []string{
		"Order ID",
		"Token Amount",
		"Token",
		"Network",
		"Rate",
		"Fiat Amount",
		"Status",
		"Institution",
		"Account Identifier",
		"Account Name",
		"Currency",
		"Memo",
		"Transaction Hash",
		"Created At",
		"Updated At",
	}

	if err := writer.Write(csvHeaders); err != nil {
		logger.Errorf("Failed to write CSV headers: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to export payment orders", nil)
		return
	}

	institutionMap := make(map[string]string)
	uniqueInstitutions := make(map[string]bool)

	for _, order := range paymentOrders {
		if order.Institution != "" {
			uniqueInstitutions[order.Institution] = true
		}
	}

	for code := range uniqueInstitutions {
		institution, err := u.GetInstitutionByCode(ctx, code, false)
		if err != nil {
			// Use raw code as fallback
			institutionMap[code] = code
		} else {
			institutionMap[code] = institution.Name
		}
	}

	// Write data rows
	for _, paymentOrder := range paymentOrders {
		// Look up institution name from pre-fetched map
		institutionName := paymentOrder.Institution
		if name, exists := institutionMap[paymentOrder.Institution]; exists {
			institutionName = name
		}

		var currencyCode string
		if paymentOrder.Edges.ProvisionBucket != nil && paymentOrder.Edges.ProvisionBucket.Edges.Currency != nil {
			currencyCode = paymentOrder.Edges.ProvisionBucket.Edges.Currency.Code
		}

		row := []string{
			paymentOrder.ID.String(),
			paymentOrder.Amount.String(),
			paymentOrder.Edges.Token.Symbol,
			paymentOrder.Edges.Token.Edges.Network.Identifier,
			paymentOrder.Rate.String(),
			paymentOrder.Rate.Mul(paymentOrder.Amount).String(),
			string(paymentOrder.Status),
			institutionName,
			paymentOrder.AccountIdentifier,
			paymentOrder.AccountName,
			currencyCode,
			paymentOrder.Memo,
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
	logger.Infof("Successfully exported %d provider orders for provider %s", len(paymentOrders), provider.ID)
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

	// Parse request body for direction and amount (for payin orders)
	var acceptRequest types.AcceptOrderRequest
	if err := ctx.ShouldBindJSON(&acceptRequest); err != nil {
		// For backward compatibility, if no body is provided, default to payout
		acceptRequest.Direction = "payout"
	}

	// Get order request from Redis (offramp: set by assignment; payin: set by sender at creation)
	orderRequestKey := fmt.Sprintf("order_request_%s", orderID)
	result, err := storage.RedisClient.HGetAll(ctx, orderRequestKey).Result()
	if err != nil {
		logger.Errorf("error getting order request from Redis: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to accept order request", nil)
		return
	}
	if len(result) == 0 || result["providerId"] != provider.ID {
		logger.Errorf("order request not found in Redis: %v", orderID)
		u.APIResponse(ctx, http.StatusNotFound, "error", "Order request not found or is expired", nil)
		return
	}

	// Payin vs payout: payin has direction=payin in order_request
	isPayin := result["direction"] == "payin"

	// Best-effort cleanup of metadata key used for timeout recovery.
	_, _ = storage.RedisClient.Del(ctx, fmt.Sprintf("order_request_meta_%s", orderID)).Result()

	// Delete order request from Redis after validation (both payin and offramp)
	_, err = storage.RedisClient.Del(ctx, orderRequestKey).Result()
	if err != nil {
		logger.Errorf("error deleting order request from Redis: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to accept order request", nil)
		return
	}

	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
		return
	}

	// Fetch the order to check its current status before accepting
	// For payin, we need token and network info
	var currentOrder *ent.PaymentOrder
	if isPayin {
		currentOrder, err = tx.PaymentOrder.
			Query().
			Where(paymentorder.IDEQ(orderID)).
			WithToken(func(tq *ent.TokenQuery) {
				tq.WithNetwork()
			}).
			Only(ctx)
	} else {
		currentOrder, err = tx.PaymentOrder.Get(ctx, orderID)
	}
	if err != nil {
		_ = tx.Rollback()
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusNotFound, "error", "Order not found", nil)
		} else {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"OrderID": orderID.String(),
			}).Errorf("error fetching order: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch order", nil)
		}
		return
	}

	// For payin orders, confirm it's an onramp order and check token balance reservation
	if isPayin {
		// Confirm order is onramp (check metadata)
		orderDirection, _ := currentOrder.Metadata["direction"].(string)
		if orderDirection != "payin" {
			_ = tx.Rollback()
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Order is not an onramp order", nil)
			return
		}

		// Ensure reserved token liquidity exists / is sufficient
		// Total crypto needed: amount + senderFee
		totalCryptoNeeded := currentOrder.Amount.Add(currentOrder.SenderFee)

		// Check provider token balance reservation
		providerBalance, err := storage.Client.ProviderBalances.
			Query().
			Where(
				providerbalances.HasProviderWith(providerprofile.IDEQ(provider.ID)),
				providerbalances.HasTokenWith(token.IDEQ(currentOrder.Edges.Token.ID)),
			).
			Only(ctx)
		if err != nil {
			_ = tx.Rollback()
			logger.Errorf("Failed to get provider token balance: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to check provider balance", nil)
			return
		}

		// Check if reserved balance is sufficient
		if providerBalance.ReservedBalance.LessThan(totalCryptoNeeded) {
			_ = tx.Rollback()
			// Set order to REFUNDING status
			_, _ = storage.Client.PaymentOrder.
				UpdateOneID(orderID).
				SetStatus(paymentorder.StatusRefunding).
				Save(ctx)

			// Return 4XX with refund details
			refundDetails := map[string]interface{}{
				"accountIdentifier": currentOrder.AccountIdentifier,
				"accountName":       currentOrder.AccountName,
				"institution":       currentOrder.Institution,
			}
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Insufficient reserved token balance", refundDetails)
			return
		}
	}

	// Check if order is already in a finalized state
	// Prevent accepting orders that are refunded, fulfilled, validated, settled, cancelled, or processing
	if currentOrder.Status != paymentorder.StatusPending {
		_ = tx.Rollback()
		logger.WithFields(logger.Fields{
			"OrderID":    orderID.String(),
			"Status":     currentOrder.Status,
			"ProviderID": provider.ID,
		}).Warnf("Rejecting accept request for order in final/processing state")
		u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("Order cannot be accepted: order is already %s", currentOrder.Status), nil)
		return
	}

	// Log transaction status
	var transactionLog *ent.TransactionLog
	_, err = tx.PaymentOrder.
		Query().
		Where(
			paymentorder.IDEQ(orderID),
			paymentorder.HasTransactionsWith(
				transactionlog.StatusEQ(transactionlog.StatusOrderFulfilling),
			),
		).
		Only(ctx)
	if err != nil {
		if !ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
			return
		} else {
			transactionLog, err = tx.TransactionLog.
				Create().
				SetStatus(transactionlog.StatusOrderFulfilling).
				Save(ctx)
			if err != nil {
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
				return
			}
		}
	}

	// Update order status atomically - only update if still pending
	// This prevents race conditions where multiple providers try to accept the same order
	// The WHERE clause ensures only one update succeeds
	orderBuilder := tx.PaymentOrder.
		Update().
		Where(
			paymentorder.IDEQ(orderID),
			paymentorder.StatusEQ(paymentorder.StatusPending),
		).
		SetStatus(paymentorder.StatusFulfilling).
		SetProviderID(provider.ID)

	if transactionLog != nil {
		orderBuilder = orderBuilder.AddTransactions(transactionLog)
	}

	updatedCount, err := orderBuilder.Save(ctx)
	if err != nil {
		logger.Errorf("%s - error.AcceptOrder: %v", orderID, err)
		_ = tx.Rollback()
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
		return
	}

	// If no rows were updated, the order was already accepted by another process
	if updatedCount == 0 {
		_ = tx.Rollback()
		// Re-fetch to get current status for error message
		currentOrder, _ := storage.Client.PaymentOrder.Get(ctx, orderID)
		statusMsg := "already accepted"
		if currentOrder != nil {
			statusMsg = fmt.Sprintf("already %s", currentOrder.Status)
		}
		logger.WithFields(logger.Fields{
			"OrderID":    orderID.String(),
			"Status":     statusMsg,
			"ProviderID": provider.ID,
		}).Warnf("Rejecting accept request - order was already accepted by another process")
		u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("Order cannot be accepted: order is %s", statusMsg), nil)
		return
	}

	// Fetch the updated order for response
	var order *ent.PaymentOrder
	if isPayin {
		order, err = tx.PaymentOrder.
			Query().
			Where(paymentorder.IDEQ(orderID)).
			WithToken(func(tq *ent.TokenQuery) {
				tq.WithNetwork()
			}).
			Only(ctx)
	} else {
		order, err = tx.PaymentOrder.Get(ctx, orderID)
	}
	if err != nil {
		logger.Errorf("%s - error.AcceptOrder.Get: %v", orderID, err)
		_ = tx.Rollback()
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch updated order", nil)
		return
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
		return
	}

	// Unified AcceptOrder response for both payin and payout
	response := types.AcceptOrderResponse{
		ID:                orderID.String(),
		Institution:       order.Institution,
		AccountIdentifier: order.AccountIdentifier,
		AccountName:       order.AccountName,
		Memo:              order.Memo,
		Metadata:          order.Metadata,
	}
	if isPayin {
		response.Direction = "payin"
		response.Amount = order.Amount.Add(order.SenderFee).Mul(order.Rate).RoundBank(0)
		network := order.Edges.Token.Edges.Network
		response.ChainId = fmt.Sprintf("%d", network.ChainID)
		response.RpcUrl = network.RPCEndpoint
		response.DelegationAddress = network.GatewayContractAddress
	} else {
		response.Direction = "payout"
		response.Amount = order.Amount.Mul(order.Rate).RoundBank(0)
	}

	if order.OrderType == paymentorder.OrderTypeOtc && order.Status == paymentorder.StatusFulfilling {
		orderWithProvider, _ := storage.Client.PaymentOrder.
			Query().
			Where(paymentorder.IDEQ(orderID)).
			WithProvider().
			Only(ctx)
		if orderWithProvider != nil && orderWithProvider.Edges.Provider != nil && orderWithProvider.Edges.Provider.ID == provider.ID {
			if response.Metadata == nil {
				response.Metadata = make(map[string]interface{})
			}
			response.Metadata["otcFulfillmentExpiry"] = time.Now().Add(orderConf.OrderFulfillmentValidityOtc)
		}
	}

	u.APIResponse(ctx, http.StatusCreated, "success", "Order request accepted successfully", &response)
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

	// Best-effort: release reserved balance for declined order requests.
	if currency := result["currency"]; currency != "" {
		if amountStr := result["amount"]; amountStr != "" {
			amt, amtErr := decimal.NewFromString(amountStr)
			if amtErr == nil {
				if relErr := ctrl.balanceService.ReleaseFiatBalance(ctx, provider.ID, currency, amt, nil); relErr != nil {
					logger.WithFields(logger.Fields{
						"Error":      fmt.Sprintf("%v", relErr),
						"OrderID":    orderID.String(),
						"ProviderID": provider.ID,
						"Currency":   currency,
						"Amount":     amountStr,
					}).Warnf("DeclineOrder: failed to release reserved balance (best effort)")
				}
			}
		}
	}

	// Best-effort cleanup of metadata key used for timeout recovery.
	_, _ = storage.RedisClient.Del(ctx, fmt.Sprintf("order_request_meta_%s", orderID)).Result()

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

	// Set TTL for the exclude list (2x order request validity since orders can be reassigned)
	err = storage.RedisClient.ExpireAt(ctx, orderKey, time.Now().Add(orderConf.OrderRequestValidity*2)).Err()
	if err != nil {
		logger.Errorf("error setting TTL for order %s exclude_list on Redis: %v", orderID, err)
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Order request declined successfully", nil)
}

// FulfillOrder controller fulfills an order
func (ctrl *ProviderController) FulfillOrder(ctx *gin.Context) {
	var payload types.FulfillOrderPayload

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
			"Error":  fmt.Sprintf("%v", err),
			"Trx Id": payload.TxID,
		}).Errorf("Error parsing order ID: %v", err)
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid Order ID", nil)
		return
	}

	updateLockOrder := storage.Client.PaymentOrder.
		Update().
		Where(
			paymentorder.IDEQ(orderID),
			paymentorder.Or(
				paymentorder.StatusEQ(paymentorder.StatusFulfilling),
				paymentorder.StatusEQ(paymentorder.StatusFulfilled),
			),
		)

	// Query or create order fulfillment
	fulfillment, err := storage.Client.PaymentOrderFulfillment.
		Query().
		Where(paymentorderfulfillment.TxIDEQ(payload.TxID)).
		WithOrder(func(poq *ent.PaymentOrderQuery) {
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
			// Check if order already has a fulfillment (pending or success) before creating a new one
			// This prevents double disbursal from multiple fulfillment attempts
			// A pending fulfillment means disbursal was already initiated, so we must prevent another one
			existingFulfillment, _ := storage.Client.PaymentOrderFulfillment.
				Query().
				Where(
					paymentorderfulfillment.HasOrderWith(paymentorder.IDEQ(orderID)),
					paymentorderfulfillment.ValidationStatusIn(
						paymentorderfulfillment.ValidationStatusPending,
						paymentorderfulfillment.ValidationStatusSuccess,
					),
				).
				Only(ctx)

			if existingFulfillment != nil {
				logger.WithFields(logger.Fields{
					"OrderID":        orderID.String(),
					"TxID":           payload.TxID,
					"ExistingTxID":   existingFulfillment.TxID,
					"ExistingStatus": existingFulfillment.ValidationStatus,
				}).Warnf("Order %s already has a fulfillment (Status: %s, TxID: %s), rejecting duplicate fulfillment (TxID: %s)",
					orderID, existingFulfillment.ValidationStatus, existingFulfillment.TxID, payload.TxID)
				u.APIResponse(ctx, http.StatusBadRequest, "error",
					fmt.Sprintf("Order already has a fulfillment (Status: %s, TxID: %s)", existingFulfillment.ValidationStatus, existingFulfillment.TxID), nil)
				return
			}

			_, err = storage.Client.PaymentOrderFulfillment.
				Create().
				SetOrderID(orderID).
				SetTxID(payload.TxID).
				SetPsp(payload.PSP).
				Save(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":  fmt.Sprintf("%v", err),
					"Trx Id": payload.TxID,
				}).Errorf("Failed to create order fulfillment: %v", err)
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
				return
			}

			fulfillment, err = storage.Client.PaymentOrderFulfillment.
				Query().
				Where(paymentorderfulfillment.TxIDEQ(payload.TxID)).
				WithOrder(func(poq *ent.PaymentOrderQuery) {
					poq.WithToken(func(tq *ent.TokenQuery) {
						tq.WithNetwork()
					}).WithProvider().WithProvisionBucket(func(pbq *ent.ProvisionBucketQuery) {
						pbq.WithCurrency()
					})
				}).
				Only(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   fmt.Sprintf("%v", err),
					"Trx Id":  payload.TxID,
					"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
				}).Errorf("Failed to fetch order fulfillment: %v", err)
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
				return
			}
		} else {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to fetch order fulfillment when order is found: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
			return
		}
	}

	// Verify the order belongs to the authenticated provider (applies to all validation statuses)
	if fulfillment.Edges.Order.Edges.Provider == nil || fulfillment.Edges.Order.Edges.Provider.ID != provider.ID {
		u.APIResponse(ctx, http.StatusForbidden, "error", "Order does not belong to provider", nil)
		return
	}

	// Check if order is already in a final state before processing
	// This prevents attempting to fulfill already-settled orders and avoids balance release errors
	if fulfillment.Edges.Order != nil {
		orderStatus := fulfillment.Edges.Order.Status
		if orderStatus == paymentorder.StatusSettled ||
			orderStatus == paymentorder.StatusValidated ||
			orderStatus == paymentorder.StatusRefunded {
			logger.WithFields(logger.Fields{
				"OrderID": orderID.String(),
				"Status":  orderStatus,
				"TxID":    payload.TxID,
			}).Warnf("Rejecting fulfill request for order already in final state")
			u.APIResponse(ctx, http.StatusOK, "success", fmt.Sprintf("Order already %s", orderStatus), nil)
			return
		}
	}

	// Check if this is a payin order
	isPayin := false
	if fulfillment.Edges.Order != nil && fulfillment.Edges.Order.Metadata != nil {
		if direction, ok := fulfillment.Edges.Order.Metadata["direction"].(string); ok && direction == "payin" {
			isPayin = true
		}
	}

	// Handle payin orders
	if isPayin {
		ctrl.handlePayinFulfillment(ctx, orderID, payload, fulfillment, provider)
		return
	}

	// Offramp fulfillment (existing logic)
	switch payload.ValidationStatus {
	case paymentorderfulfillment.ValidationStatusSuccess:
		// Double-check order status (race condition protection)
		orderStatus := fulfillment.Edges.Order.Status
		if orderStatus == paymentorder.StatusValidated ||
			orderStatus == paymentorder.StatusSettled ||
			orderStatus == paymentorder.StatusRefunded {
			u.APIResponse(ctx, http.StatusOK, "success", fmt.Sprintf("Order already %s", orderStatus), nil)
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
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
			return
		}

		// Update fulfillment status within transaction
		_, err = tx.PaymentOrderFulfillment.
			UpdateOneID(fulfillment.ID).
			SetValidationStatus(paymentorderfulfillment.ValidationStatusSuccess).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to update order fulfillment: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
			_ = tx.Rollback()
			return
		}

		// Create transaction log within transaction
		transactionLog, err := tx.TransactionLog.Create().
			SetStatus(transactionlog.StatusOrderValidated).
			SetNetwork(fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to create transaction log: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
			_ = tx.Rollback()
			return
		}

		// Check order status again before updating (race condition protection)
		// This prevents updating orders that were settled by another process
		currentOrder, err := tx.PaymentOrder.
			Query().
			Where(paymentorder.IDEQ(orderID)).
			Only(ctx)
		if err == nil && currentOrder != nil {
			if currentOrder.Status == paymentorder.StatusSettled ||
				currentOrder.Status == paymentorder.StatusRefunded {
				logger.WithFields(logger.Fields{
					"OrderID": orderID.String(),
					"Status":  currentOrder.Status,
					"TxID":    payload.TxID,
				}).Warnf("Order already settled/refunded, skipping fulfillment")
				_ = tx.Rollback()
				u.APIResponse(ctx, http.StatusOK, "success", fmt.Sprintf("Order already %s", currentOrder.Status), nil)
				return
			}
		}

		// Update order status within transaction
		_, err = tx.PaymentOrder.
			Update().
			Where(paymentorder.IDEQ(orderID)).
			SetStatus(paymentorder.StatusValidated).
			AddTransactions(transactionLog).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to update order status: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
			_ = tx.Rollback()
			return
		}

		// Release reserved balance within the same transaction
		providerID := fulfillment.Edges.Order.Edges.Provider.ID
		currency := fulfillment.Edges.Order.Edges.ProvisionBucket.Edges.Currency.Code
		amount := fulfillment.Edges.Order.Amount.Mul(fulfillment.Edges.Order.Rate).RoundBank(0)

		err = ctrl.balanceService.ReleaseFiatBalance(ctx, providerID, currency, amount, tx)
		if err != nil {
			// Check if error is due to order already being settled (balance already released)
			// If so, check order status and return success instead of error
			checkOrder, checkErr := tx.PaymentOrder.
				Query().
				Where(paymentorder.IDEQ(orderID)).
				Only(ctx)
			if checkErr == nil && checkOrder != nil {
				if checkOrder.Status == paymentorder.StatusSettled ||
					checkOrder.Status == paymentorder.StatusRefunded {
					logger.WithFields(logger.Fields{
						"OrderID": orderID.String(),
						"Status":  checkOrder.Status,
						"TxID":    payload.TxID,
						"Error":   fmt.Sprintf("%v", err),
					}).Warnf("Balance release failed but order already settled/refunded, treating as success")
					_ = tx.Rollback()
					u.APIResponse(ctx, http.StatusOK, "success", fmt.Sprintf("Order already %s", checkOrder.Status), nil)
					return
				}
			}

			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"OrderID":    orderID.String(),
				"ProviderID": providerID,
				"Currency":   currency,
				"Amount":     amount.String(),
			}).Errorf("failed to release reserved balance for fulfilled order")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
			_ = tx.Rollback()
			return
		}

		// Clean up order exclude list from Redis (best effort, don't fail if it errors)
		orderKey := fmt.Sprintf("order_exclude_list_%s", orderID)
		_ = storage.RedisClient.Del(ctx, orderKey).Err()

		err = u.SendPaymentOrderWebhook(ctx, fulfillment.Edges.Order)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to send webhook notification to sender: %v", err)
		}

		// Settle order or fail silently
		go func() {
			var err error
			if strings.HasPrefix(fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier, "tron") {
				err = orderService.NewOrderTron().SettleOrder(ctx, orderID)
			} else if strings.HasPrefix(fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier, "starknet") {
				client, err := starknetService.NewClient()
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":   fmt.Sprintf("%v", err),
						"OrderID": orderID.String(),
					}).Errorf("FulfillOrder.SettleOrder.NewStarknetClient")
					return
				}
				err = orderService.NewOrderStarknet(client).SettleOrder(ctx, orderID)
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

	case paymentorderfulfillment.ValidationStatusFailed:
		_, err = fulfillment.Update().
			SetValidationStatus(paymentorderfulfillment.ValidationStatusFailed).
			SetValidationError(payload.ValidationError).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to update order fulfillment: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
			return
		}

		_, err = updateLockOrder.
			SetStatus(paymentorder.StatusFulfilled).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to update order status: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
			return
		}

		// Release reserved balance for failed validation
		providerID := fulfillment.Edges.Order.Edges.Provider.ID
		currency := fulfillment.Edges.Order.Edges.ProvisionBucket.Edges.Currency.Code
		amount := fulfillment.Edges.Order.Amount.Mul(fulfillment.Edges.Order.Rate).RoundBank(0)

		err = ctrl.balanceService.ReleaseFiatBalance(ctx, providerID, currency, amount, nil)
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
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to create transaction log: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
			return
		}

		_, err = updateLockOrder.
			SetStatus(paymentorder.StatusFulfilled).
			AddTransactions(transactionLog).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Trx Id":  payload.TxID,
				"Network": fulfillment.Edges.Order.Edges.Token.Edges.Network.Identifier,
			}).Errorf("Failed to update order status: %v", err)
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
			return
		}
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Order fulfilled successfully", nil)
}

// handlePayinFulfillment handles payin (onramp) order fulfillment
func (ctrl *ProviderController) handlePayinFulfillment(ctx *gin.Context, orderID uuid.UUID, payload types.FulfillOrderPayload, fulfillment *ent.PaymentOrderFulfillment, provider *ent.ProviderProfile) {
	// Validate authorization is provided for payin orders
	if payload.Authorization == nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Authorization is required for payin orders", types.ErrorData{
			Field:   "Authorization",
			Message: "EIP-7702 SetCodeAuthorization is required for payin fulfillment",
		})
		return
	}

	// Fetch order with token and network
	orderWithDetails, err := storage.Client.PaymentOrder.
		Query().
		Where(paymentorder.IDEQ(orderID)).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithProvider().
		Only(ctx)
	if err != nil {
		logger.Errorf("Failed to fetch order details: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch order details", nil)
		return
	}

	// Get provider payout address (settlement address for the token)
	providerOrderToken, err := storage.Client.ProviderOrderToken.
		Query().
		Where(
			providerordertoken.HasProviderWith(providerprofile.IDEQ(provider.ID)),
			providerordertoken.HasTokenWith(token.IDEQ(orderWithDetails.Edges.Token.ID)),
			providerordertoken.NetworkEQ(orderWithDetails.Edges.Token.Edges.Network.Identifier),
		).
		Only(ctx)
	if err != nil {
		logger.Errorf("Failed to fetch provider order token: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch provider configuration", nil)
		return
	}

	if providerOrderToken.PayoutAddress == "" {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Provider payout address not configured", nil)
		return
	}

	// Generate Gateway order ID for settleIn
	// Format: keccak256(abi.encode(aggregatorAddress, paymentOrderID, chainID))
	// For onramp, generate deterministically from payment order ID
	// Use payment order ID as base and create a deterministic bytes32
	orderIDStr := strings.ReplaceAll(orderID.String(), "-", "")
	gatewayOrderID := "0x" + orderIDStr[:64] // Use first 64 hex chars of UUID (32 bytes)
	if len(orderIDStr) < 64 {
		// Pad if needed
		gatewayOrderID = "0x" + orderIDStr + strings.Repeat("0", 64-len(orderIDStr))
	}

	// Prepare settleIn call data
	// settleIn(_orderId, _token, _amount, _senderFeeRecipient, _senderFee, _recipient, _rate)
	settleInData, err := ctrl.prepareSettleInCallData(ctx, orderWithDetails, gatewayOrderID, providerOrderToken)
	if err != nil {
		logger.Errorf("Failed to prepare settleIn call data: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to prepare settlement data", nil)
		return
	}

	// Execute EIP-7702 transaction to transfer crypto and call settleIn
	// This requires:
	// 1. Using authorization to enable aggregator-initiated transfer from provider's wallet
	// 2. Transfer amount + senderFee from provider wallet to Gateway contract
	// 3. Call Gateway settleIn with the prepared data
	//
	// Note: Full EIP-7702 implementation requires go-ethereum v1.16.1+ and specific transaction construction
	// For now, this is a placeholder that will need to be implemented with proper EIP-7702 transaction building
	txHash, err := ctrl.executePayinSettlement(ctx, orderWithDetails, payload.Authorization, settleInData, providerOrderToken)
	if err != nil {
		logger.Errorf("Failed to execute payin settlement: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to execute settlement", nil)
		return
	}

	// Start transaction for database updates
	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		logger.Errorf("Failed to start transaction: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
		return
	}

	// Update fulfillment status
	_, err = tx.PaymentOrderFulfillment.
		UpdateOneID(fulfillment.ID).
		SetValidationStatus(paymentorderfulfillment.ValidationStatusSuccess).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		logger.Errorf("Failed to update fulfillment status: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
		return
	}

	// Create transaction log
	transactionLog, err := tx.TransactionLog.
		Create().
		SetStatus(transactionlog.StatusOrderSettled).
		SetNetwork(orderWithDetails.Edges.Token.Edges.Network.Identifier).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		logger.Errorf("Failed to create transaction log: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
		return
	}

	// Update order status to SETTLED
	_, err = tx.PaymentOrder.
		UpdateOneID(orderID).
		SetStatus(paymentorder.StatusSettled).
		SetGatewayID(gatewayOrderID).
		SetTxHash(txHash).
		AddTransactions(transactionLog).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		logger.Errorf("Failed to update order status: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
		return
	}

	// Release reserved token balance
	totalCryptoReserved := orderWithDetails.Amount.Add(orderWithDetails.SenderFee)
	err = ctrl.balanceService.ReleaseTokenBalance(ctx, provider.ID, orderWithDetails.Edges.Token.ID, totalCryptoReserved, tx)
	if err != nil {
		logger.Errorf("Failed to release token balance: %v", err)
		// Don't fail the entire operation if balance release fails - log and continue
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		logger.Errorf("Failed to commit transaction: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update order status", nil)
		return
	}

	// Send webhook notification
	err = u.SendPaymentOrderWebhook(ctx, orderWithDetails)
	if err != nil {
		logger.Errorf("Failed to send webhook: %v", err)
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Payin order fulfilled successfully", nil)
}

// prepareSettleInCallData prepares the call data for Gateway settleIn method
func (ctrl *ProviderController) prepareSettleInCallData(ctx *gin.Context, order *ent.PaymentOrder, gatewayOrderID string, providerOrderToken *ent.ProviderOrderToken) ([]byte, error) {
	// Use current Gateway contract bindings; plan expects regenerated bindings if ABI changes
	gatewayABI, err := abi.JSON(strings.NewReader(contracts.GatewayMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse Gateway ABI: %w", err)
	}

	// Get fee address (sender fee recipient)
	senderOrderToken, err := storage.Client.SenderOrderToken.
		Query().
		Where(
			senderordertoken.HasTokenWith(token.IDEQ(order.Edges.Token.ID)),
			senderordertoken.HasSenderWith(senderprofile.IDEQ(order.Edges.SenderProfile.ID)),
		).
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch sender order token: %w", err)
	}

	// Get recipient address from order metadata (crypto destination)
	var recipientAddress string
	if order.Metadata != nil {
		if addr, ok := order.Metadata["recipientAddress"].(string); ok && addr != "" {
			recipientAddress = addr
		} else {
			return nil, fmt.Errorf("recipient address not found in order metadata")
		}
	} else {
		return nil, fmt.Errorf("order metadata is missing")
	}

	// Convert amounts to big.Int
	amountBig := u.ToSubunit(order.Amount, order.Edges.Token.Decimals)
	senderFeeBig := u.ToSubunit(order.SenderFee, order.Edges.Token.Decimals)

	// Convert rate to uint96 (rate is stored as decimal, need to convert to basis points * 100)
	// Rate format: Gateway expects rate as uint96 where 100 = 1.00 (local transfer)
	// For FX transfers, rate represents the conversion rate scaled appropriately
	rateBig := order.Rate.Mul(decimal.NewFromInt(100)).BigInt()
	if rateBig.Cmp(big.NewInt(0)) == 0 {
		rateBig = big.NewInt(100) // Default to 1.00 (100 basis points)
	}
	// Convert to uint64 (Gateway uses uint96 but we'll use uint64 for now)
	rateUint64 := rateBig.Uint64()
	if rateUint64 > 18446744073709551615 { // max uint64
		return nil, fmt.Errorf("rate exceeds uint64 maximum")
	}

	// Generate Gateway order ID bytes
	orderIDBytes, err := hex.DecodeString(strings.TrimPrefix(gatewayOrderID, "0x"))
	if err != nil {
		return nil, fmt.Errorf("failed to decode gateway order ID: %w", err)
	}
	var orderIDByte32 [32]byte
	copy(orderIDByte32[:], orderIDBytes)

	// Pack settleIn call data
	// settleIn(bytes32 _orderId, address _token, uint256 _amount, address _senderFeeRecipient, uint96 _senderFee, address _recipient, uint96 _rate)
	// Note: uint96 in Go is represented as uint64 for packing
	senderFeeUint64 := senderFeeBig.Uint64()
	if senderFeeUint64 > 18446744073709551615 {
		return nil, fmt.Errorf("sender fee exceeds uint64 maximum")
	}
	data, err := gatewayABI.Pack(
		"settleIn",
		orderIDByte32,
		ethcommon.HexToAddress(order.Edges.Token.ContractAddress),
		amountBig,
		ethcommon.HexToAddress(senderOrderToken.FeeAddress),
		uint64(senderFeeUint64), // uint96 in Solidity, uint64 in Go
		ethcommon.HexToAddress(recipientAddress),
		uint64(rateUint64), // uint96 in Solidity, uint64 in Go
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack settleIn ABI: %w", err)
	}

	return data, nil
}

// executePayinSettlement executes the EIP-7702 transaction for payin settlement
// This is a placeholder that needs full EIP-7702 implementation
func (ctrl *ProviderController) executePayinSettlement(ctx *gin.Context, order *ent.PaymentOrder, authorization *types.SetCodeAuthorization, settleInData []byte, providerOrderToken *ent.ProviderOrderToken) (string, error) {
	// TODO: Implement full EIP-7702 transaction construction and execution
	// This requires:
	// 1. Converting authorization to go-ethereum types.SetCodeAuthorization
	// 2. Building EIP-7702 transaction with SetCodeTx
	// 3. Transferring amount + senderFee from provider wallet to Gateway contract
	// 4. Calling Gateway settleIn
	//
	// Reference: https://gist.github.com/onahprosper/d57857f5bf34f37af8a2236da91463f3
	//
	// For now, return an error indicating this needs to be implemented
	return "", fmt.Errorf("EIP-7702 payin settlement not yet fully implemented - requires go-ethereum v1.16.1+ and SetCodeTx support")
}

// CancelOrder controller cancels an order
func (ctrl *ProviderController) CancelOrder(ctx *gin.Context) {
	var payload types.CancelOrderPayload

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

	// Fetch payment order from db
	order, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.IDEQ(orderID),
			paymentorder.HasProviderWith(providerprofile.IDEQ(provider.ID)),
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
		}).Errorf("Failed to fetch payment order: %v", err)
		u.APIResponse(ctx, http.StatusNotFound, "error", "Could not find payment order", nil)
		return
	}

	// Get new cancellation count based on cancel reason
	orderUpdate := storage.Client.PaymentOrder.UpdateOneID(orderID)
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

			// Extract the id from the data (format "providerID:token:network:rate:minAmount:maxAmount")
			parts := strings.Split(providerData, ":")
			if len(parts) != 6 {
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

	// Update order status to cancelled
	_, err = orderUpdate.
		SetStatus(paymentorder.StatusCancelled).
		SetCancellationCount(cancellationCount).
		Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Reason":   payload.Reason,
			"Order ID": orderID.String(),
		}).Errorf("Failed to update order status: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to cancel order", nil)
		return
	}

	order.Status = paymentorder.StatusCancelled
	order.CancellationCount = cancellationCount

	// Release reserved balance for this cancelled order
	providerID := order.Edges.Provider.ID
	currency := order.Edges.ProvisionBucket.Edges.Currency.Code
	amount := order.Amount.Mul(order.Rate).RoundBank(0)

	err = ctrl.balanceService.ReleaseFiatBalance(ctx, providerID, currency, amount, nil)
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
	if order.CancellationCount >= orderConf.RefundCancellationCount && order.Status == paymentorder.StatusCancelled {
		go func() {
			var service types.OrderService
			if strings.HasPrefix(order.Edges.Token.Edges.Network.Identifier, "tron") {
				service = orderService.NewOrderTron()
			} else if strings.HasPrefix(order.Edges.Token.Edges.Network.Identifier, "starknet") {
				client, err := starknetService.NewClient()
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":   fmt.Sprintf("%v", err),
						"OrderID": order.ID.String(),
					}).Errorf("CancelOrder.RefundOrder.NewStarknetClient")
					return
				}
				service = orderService.NewOrderStarknet(client)
				logger.WithFields(logger.Fields{
					"OrderID":           order.ID.String(),
					"NetworkIdentifier": order.Edges.Token.Edges.Network.Identifier,
					"Status":            order.Status.String(),
					"GatewayID":         order.GatewayID,
				}).Errorf("CancelOrder.RefundOrder.NewStarknetClient")
			} else {
				service = orderService.NewOrderEVM()
			}
			err := service.RefundOrder(ctx, order.Edges.Token.Edges.Network, order.GatewayID)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   fmt.Sprintf("%v", err),
					"OrderID": orderID.String(),
					"Network": order.Edges.Token.Edges.Network.Identifier,
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

	// Set TTL for the exclude list (2x order request validity since orders can be reassigned)
	err = storage.RedisClient.ExpireAt(ctx, orderKey, time.Now().Add(orderConf.OrderRequestValidity*2)).Err()
	if err != nil {
		logger.Errorf("error setting TTL for order %s exclude_list on Redis: %v", orderID, err)
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
		// Use sell rate for deviation calculation (offramp perspective)
		deviation := currency.MarketSellRate.Mul(orderConf.PercentDeviationFromMarketRate.Div(decimal.NewFromInt(100)))

		response = &types.MarketRateResponse{
			MarketBuyRate:  currency.MarketBuyRate,
			MarketSellRate: currency.MarketSellRate,
			MinimumRate:    currency.MarketSellRate.Sub(deviation),
			MaximumRate:    currency.MarketSellRate.Add(deviation),
		}
	} else {
		response = &types.MarketRateResponse{
			MarketBuyRate:  decimal.NewFromInt(1),
			MarketSellRate: decimal.NewFromInt(1),
			MinimumRate:    decimal.NewFromInt(1),
			MaximumRate:    decimal.NewFromInt(1),
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
		currencyExists, err := provider.QueryProviderBalances().
			Where(providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currency))).
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
	query := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.HasProviderWith(providerprofile.IDEQ(provider.ID)),
			paymentorder.StatusEQ(paymentorder.StatusSettled),
			paymentorder.InstitutionIn(institutionCodes...),
		)

	// Get USD volume
	var usdVolume []struct {
		Sum decimal.Decimal
	}
	err = query.
		Where(paymentorder.HasTokenWith(token.BaseCurrencyEQ("USD"))).
		Aggregate(
			ent.Sum(paymentorder.FieldAmount),
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
			paymentorder.HasTokenWith(token.BaseCurrencyEQ(currency)),
			paymentorder.HasTokenWith(token.BaseCurrencyNEQ("USD")),
		).
		Aggregate(
			ent.Sum(paymentorder.FieldAmount),
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
		localStablecoinVolume[0].Sum = localStablecoinVolume[0].Sum.Div(fiatCurrency.MarketSellRate)
	}

	var totalFiatVolume decimal.Decimal
	settledOrders, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.HasProviderWith(providerprofile.IDEQ(provider.ID)),
			paymentorder.StatusEQ(paymentorder.StatusSettled),
			paymentorder.InstitutionIn(institutionCodes...),
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

	count, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.HasProviderWith(providerprofile.IDEQ(provider.ID)),
			paymentorder.InstitutionIn(institutionCodes...),
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
		WithProviderBalances(
			func(query *ent.ProviderBalancesQuery) {
				query.WithFiatCurrency().Where(providerbalances.HasFiatCurrency())
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

	for _, pb := range provider.Edges.ProviderBalances {
		if pb.Edges.FiatCurrency != nil && !u.ContainsString(currencyCodes, pb.Edges.FiatCurrency.Code) {
			logger.WithFields(logger.Fields{
				"Error":    "currency not found in node response",
				"Currency": pb.Edges.FiatCurrency.Code,
			}).Errorf("failed to parse node info: currency %s not found in node response", pb.Edges.FiatCurrency.Code)
			u.APIResponse(ctx, http.StatusServiceUnavailable, "error", "Failed to fetch node info", nil)
			return
		}
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Node info fetched successfully", data)
}

// GetPaymentOrderByID controller fetches a payment order by ID
func (ctrl *ProviderController) GetPaymentOrderByID(ctx *gin.Context) {
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
	paymentOrder, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.IDEQ(id),
			paymentorder.HasProviderWith(providerprofile.IDEQ(provider.ID)),
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
		}).Errorf("Failed to fetch payment order: %v", err)
		u.APIResponse(ctx, http.StatusNotFound, "error",
			"Payment order not found", nil)
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

	u.APIResponse(ctx, http.StatusOK, "success", "The order has been successfully retrieved", &types.ProviderOrderResponse{
		ID:                  paymentOrder.ID,
		Token:               paymentOrder.Edges.Token.Symbol,
		GatewayID:           paymentOrder.GatewayID,
		Amount:              paymentOrder.Amount,
		AmountInUSD:         paymentOrder.AmountInUsd,
		Rate:                paymentOrder.Rate,
		Institution:         paymentOrder.Institution,
		AccountIdentifier:   paymentOrder.AccountIdentifier,
		AccountName:         paymentOrder.AccountName,
		TxHash:              paymentOrder.TxHash,
		Status:              paymentOrder.Status,
		Memo:                paymentOrder.Memo,
		Network:             paymentOrder.Edges.Token.Edges.Network.Identifier,
		UpdatedAt:           paymentOrder.UpdatedAt,
		CreatedAt:           paymentOrder.CreatedAt,
		Transactions:        transactions,
		CancellationReasons: paymentOrder.CancellationReasons,
		OrderType:           paymentOrder.OrderType,
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

	// Provider-reported reservedBalance is ignored; ReservedBalance is managed internally by the aggregator.
	// Keep parsing/validation for backwards compatibility with existing provider payloads.
	if !reservedBalance.Equal(decimal.Zero) {
		logger.WithFields(logger.Fields{
			"ProviderID":      provider.ID,
			"Currency":        payload.Currency,
			"ReservedBalance": reservedBalance.String(),
		}).Debugf("UpdateProviderBalance: ignoring provider-reported reservedBalance")
	}

	// Update the balance using the provider ID from context, preserving internal reservations.
	err = ctrl.balanceService.UpdateProviderFiatBalanceFromProvider(ctx, provider.ID, payload.Currency, availableBalance, totalBalance)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": provider.ID,
			"Currency":   payload.Currency,
		}).Errorf("Failed to update provider balance")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update balance", nil)
		return
	}

	// Trigger async token balance fetch when fiat balance is updated
	// This ensures token balances stay current when providers are actively updating fiat balances
	go func() {
		err := ctrl.balanceService.FetchAndUpdateProviderTokenBalances(context.Background(), provider.ID)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"ProviderID": provider.ID,
			}).Warnf("Failed to fetch token balances after fiat balance update")
		}
	}()

	u.APIResponse(ctx, http.StatusOK, "success", "Balance updated successfully", nil)
}
