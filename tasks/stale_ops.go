package tasks

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/paymentorderfulfillment"
	"github.com/paycrest/aggregator/ent/providerprofile"
	orderService "github.com/paycrest/aggregator/services/order"
	starknetService "github.com/paycrest/aggregator/services/starknet"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils/logger"
)

// RetryStaleUserOperations retries stale user operations
// TODO: Fetch failed orders from a separate db table and process them
func RetryStaleUserOperations() error {
	ctx := context.Background()

	var wg sync.WaitGroup

	// Create deposited orders that haven't been created on-chain yet
	orders, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.StatusEQ(paymentorder.StatusDeposited),
			paymentorder.GatewayIDIsNil(),
			paymentorder.Or(
				paymentorder.UpdatedAtGTE(time.Now().Add(-5*time.Minute)),
				paymentorder.MemoHasPrefix("P#P"),
			),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		All(ctx)
	if err != nil {
		return fmt.Errorf("RetryStaleUserOperations: %w", err)
	}

	wg.Add(1)
	go func(ctx context.Context) {
		defer wg.Done()
		for _, order := range orders {
			orderAmountWithFees := order.Amount.Add(order.NetworkFee).Add(order.SenderFee)
			if order.AmountPaid.GreaterThanOrEqual(orderAmountWithFees) {
				var service types.OrderService
				if strings.HasPrefix(order.Edges.Token.Edges.Network.Identifier, "tron") {
					service = orderService.NewOrderTron()
				} else if strings.HasPrefix(order.Edges.Token.Edges.Network.Identifier, "starknet") {
					client, err := starknetService.NewClient()
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error":   fmt.Sprintf("%v", err),
							"OrderID": order.ID.String(),
						}).Errorf("RetryStaleUserOperations.CreateOrder.NewStarknetClient")
						continue
					}
					service = orderService.NewOrderStarknet(client)
				} else {
					service = orderService.NewOrderEVM()
				}

				// Unset message hash
				_, err = order.Update().
					SetNillableMessageHash(nil).
					SetStatus(paymentorder.StatusPending).
					Save(ctx)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":   fmt.Sprintf("%v", err),
						"OrderID": order.ID.String(),
					}).Errorf("RetryStaleUserOperations.CreateOrder.SetMessageHash")
				}

				_, err = order.Update().
					SetStatus(paymentorder.StatusDeposited).
					Save(ctx)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":   fmt.Sprintf("%v", err),
						"OrderID": order.ID.String(),
					}).Errorf("RetryStaleUserOperations.CreateOrder.SetStatus")
				}

				err = service.CreateOrder(ctx, order.ID)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":             fmt.Sprintf("%v", err),
						"OrderID":           order.ID.String(),
						"AmountPaid":        order.AmountPaid,
						"Amount":            order.Amount,
						"PercentSettled":    order.PercentSettled,
						"GatewayID":         order.GatewayID,
						"NetworkIdentifier": order.Edges.Token.Edges.Network.Identifier,
					}).Errorf("RetryStaleUserOperations.CreateOrder")
				}
			}
		}
	}(ctx)

	// Settle order process: validated orders (5–15 min) or orders stuck in settling (> 10 min)
	lockOrders, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.HasFulfillmentsWith(
				paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusSuccess),
			),
			paymentorder.Or(
				paymentorder.And(
					paymentorder.StatusEQ(paymentorder.StatusValidated),
					paymentorder.UpdatedAtLT(time.Now().Add(-5*time.Minute)),
					paymentorder.UpdatedAtGTE(time.Now().Add(-15*time.Minute)),
				),
				// Stuck settling: updated > 10 min ago
				paymentorder.And(
					paymentorder.StatusEQ(paymentorder.StatusSettling),
					paymentorder.UpdatedAtLT(time.Now().Add(-10*time.Minute)),
				),
			),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		All(ctx)
	if err != nil {
		return fmt.Errorf("RetryStaleUserOperations: %w", err)
	}

	wg.Add(1)
	go func(ctx context.Context) {
		defer wg.Done()
		for _, order := range lockOrders {
			// SettleOrder only accepts StatusValidated; reset stuck settling so it can be retried.
			// Guard on StatusSettling so we never overwrite an order that became settled (or any
			// other status) after the initial query—avoids race and re-submitting settlement.
			if order.Status == paymentorder.StatusSettling {
				affected, err := storage.Client.PaymentOrder.
					Update().
					Where(
						paymentorder.IDEQ(order.ID),
						paymentorder.StatusEQ(paymentorder.StatusSettling),
					).
					SetStatus(paymentorder.StatusValidated).
					Save(ctx)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":   fmt.Sprintf("%v", err),
						"OrderID": order.ID.String(),
					}).Errorf("RetryStaleUserOperations.SettleOrder.resetSettlingStatus")
					continue
				}
				if affected == 0 {
					// Order was no longer settling (e.g. indexer already set to settled), skip
					continue
				}
				// Re-fetch so SettleOrder's query (StatusValidated) will find the order; avoids race
				// where we call SettleOrder before the update is visible.
				orderID := order.ID
				order, err = storage.Client.PaymentOrder.
					Query().
					Where(
						paymentorder.IDEQ(orderID),
						paymentorder.StatusEQ(paymentorder.StatusValidated),
					).
					WithToken(func(tq *ent.TokenQuery) { tq.WithNetwork() }).
					WithProvider().
					Only(ctx)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":   fmt.Sprintf("%v", err),
						"OrderID": orderID.String(),
					}).Errorf("RetryStaleUserOperations.SettleOrder.refetchAfterReset")
					continue
				}
			}
			var service types.OrderService
			if strings.HasPrefix(order.Edges.Token.Edges.Network.Identifier, "tron") {
				service = orderService.NewOrderTron()
			} else if strings.HasPrefix(order.Edges.Token.Edges.Network.Identifier, "starknet") {
				client, err := starknetService.NewClient()
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":   fmt.Sprintf("%v", err),
						"OrderID": order.ID.String(),
					}).Errorf("RetryStaleUserOperations.SettleOrder.NewStarknetClient")
					continue
				}
				service = orderService.NewOrderStarknet(client)
			} else {
				service = orderService.NewOrderEVM()
			}
			err := service.SettleOrder(ctx, order.ID)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":             fmt.Sprintf("%v", err),
					"OrderID":           order.ID.String(),
					"Amount":            order.Amount,
					"GatewayID":         order.GatewayID,
					"NetworkIdentifier": order.Edges.Token.Edges.Network.Identifier,
				}).Errorf("RetryStaleUserOperations.SettleOrder")
			}
		}
	}(ctx)

	// Refund order process
	// OTC orders use separate refund timeout
	otcRefundTimeout := orderConf.OrderRefundTimeoutOtc
	regularRefundTimeout := orderConf.OrderRefundTimeout

	lockOrders, err = storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.GatewayIDNEQ(""),
			paymentorder.UpdatedAtGTE(time.Now().Add(-15*time.Minute)),
			paymentorder.StatusNEQ(paymentorder.StatusValidated),
			paymentorder.StatusNEQ(paymentorder.StatusSettled),
			paymentorder.StatusNEQ(paymentorder.StatusRefunded),
			paymentorder.Or(
				// Regular orders with normal refund timeout
				paymentorder.And(
					paymentorder.OrderTypeEQ(paymentorder.OrderTypeRegular),
					paymentorder.Or(
						paymentorder.StatusEQ(paymentorder.StatusPending),
						paymentorder.StatusEQ(paymentorder.StatusCancelled),
					),
					paymentorder.Or(
						paymentorder.And(
							paymentorder.IndexerCreatedAtNotNil(),
							paymentorder.IndexerCreatedAtLTE(time.Now().Add(-regularRefundTimeout)),
						),
						paymentorder.And(
							paymentorder.IndexerCreatedAtIsNil(),
							paymentorder.CreatedAtLTE(time.Now().Add(-regularRefundTimeout)),
						),
					),
					paymentorder.Or(
						paymentorder.Not(paymentorder.HasFulfillments()),
						paymentorder.HasFulfillmentsWith(
							paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusFailed),
							paymentorderfulfillment.Not(paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusSuccess)),
							paymentorderfulfillment.Not(paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusPending)),
						),
					),
				),
				// Regular orders with status Fulfilled and failed fulfillments
				paymentorder.And(
					paymentorder.OrderTypeEQ(paymentorder.OrderTypeRegular),
					paymentorder.StatusEQ(paymentorder.StatusFulfilled),
					paymentorder.Or(
						paymentorder.And(
							paymentorder.IndexerCreatedAtNotNil(),
							paymentorder.IndexerCreatedAtLTE(time.Now().Add(-regularRefundTimeout)),
						),
						paymentorder.And(
							paymentorder.IndexerCreatedAtIsNil(),
							paymentorder.CreatedAtLTE(time.Now().Add(-regularRefundTimeout)),
						),
					),
					paymentorder.HasFulfillmentsWith(
						paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusFailed),
						paymentorderfulfillment.Not(paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusSuccess)),
						paymentorderfulfillment.Not(paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusPending)),
					),
					// CRITICAL: Don't refund if validation error contains "Failed to get transaction status after"
					// This means we couldn't verify the status, but funds may have been disbursed
					paymentorder.Not(paymentorder.HasFulfillmentsWith(
						paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusFailed),
						paymentorderfulfillment.ValidationErrorContains("Failed to get transaction status after"),
					)),
				),
				// OTC orders with OTC refund timeout
				paymentorder.And(
					paymentorder.OrderTypeEQ(paymentorder.OrderTypeOtc),
					paymentorder.Or(
						paymentorder.StatusEQ(paymentorder.StatusPending),
						paymentorder.StatusEQ(paymentorder.StatusCancelled),
					),
					paymentorder.Or(
						paymentorder.And(
							paymentorder.IndexerCreatedAtNotNil(),
							paymentorder.IndexerCreatedAtLTE(time.Now().Add(-otcRefundTimeout)),
						),
						paymentorder.And(
							paymentorder.IndexerCreatedAtIsNil(),
							paymentorder.CreatedAtLTE(time.Now().Add(-otcRefundTimeout)),
						),
					),
					paymentorder.Or(
						paymentorder.Not(paymentorder.HasFulfillments()),
						paymentorder.HasFulfillmentsWith(
							paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusFailed),
							paymentorderfulfillment.Not(paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusSuccess)),
							paymentorderfulfillment.Not(paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusPending)),
						),
					),
				),
				// OTC orders with status Fulfilled and failed fulfillments
				paymentorder.And(
					paymentorder.OrderTypeEQ(paymentorder.OrderTypeOtc),
					paymentorder.StatusEQ(paymentorder.StatusFulfilled),
					paymentorder.Or(
						paymentorder.And(
							paymentorder.IndexerCreatedAtNotNil(),
							paymentorder.IndexerCreatedAtLTE(time.Now().Add(-otcRefundTimeout)),
						),
						paymentorder.And(
							paymentorder.IndexerCreatedAtIsNil(),
							paymentorder.CreatedAtLTE(time.Now().Add(-otcRefundTimeout)),
						),
					),
					paymentorder.HasFulfillmentsWith(
						paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusFailed),
						paymentorderfulfillment.Not(paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusSuccess)),
						paymentorderfulfillment.Not(paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusPending)),
					),
					// CRITICAL: Don't refund if validation error contains "Failed to get transaction status after"
					// This means we couldn't verify the status, but funds may have been disbursed
					paymentorder.Not(paymentorder.HasFulfillmentsWith(
						paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusFailed),
						paymentorderfulfillment.ValidationErrorContains("Failed to get transaction status after"),
					)),
				),
				// Private provider orders with status Fulfilled and failed fulfillments
				paymentorder.And(
					paymentorder.HasProviderWith(
						providerprofile.VisibilityModeEQ(providerprofile.VisibilityModePrivate),
					),
					paymentorder.StatusEQ(paymentorder.StatusFulfilled),
					paymentorder.HasFulfillmentsWith(
						paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusFailed),
						paymentorderfulfillment.Not(paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusSuccess)),
						paymentorderfulfillment.Not(paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusPending)),
					),
					// CRITICAL: Don't refund if validation error contains "Failed to get transaction status after"
					// This means we couldn't verify the status, but funds may have been disbursed
					paymentorder.Not(paymentorder.HasFulfillmentsWith(
						paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusFailed),
						paymentorderfulfillment.ValidationErrorContains("Failed to get transaction status after"),
					)),
				),
			),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		All(ctx)
	if err != nil {
		return fmt.Errorf("RetryStaleUserOperations: %w", err)
	}

	wg.Add(1)
	go func(ctx context.Context) {
		defer wg.Done()
		for _, order := range lockOrders {
			var service types.OrderService
			if strings.HasPrefix(order.Edges.Token.Edges.Network.Identifier, "tron") {
				service = orderService.NewOrderTron()
			} else if strings.HasPrefix(order.Edges.Token.Edges.Network.Identifier, "starknet") {
				client, err := starknetService.NewClient()
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":   fmt.Sprintf("%v", err),
						"OrderID": order.ID.String(),
					}).Errorf("RetryStaleUserOperations.RefundOrder.NewStarknetClient")
					continue
				}
				service = orderService.NewOrderStarknet(client)
				logger.WithFields(logger.Fields{
					"OrderID":           order.ID.String(),
					"NetworkIdentifier": order.Edges.Token.Edges.Network.Identifier,
					"Status":            order.Status.String(),
					"GatewayID":         order.GatewayID,
				}).Errorf("RetryStaleUserOperations.RefundOrder.NewStarknetClient")
			} else {
				service = orderService.NewOrderEVM()
			}
			err := service.RefundOrder(ctx, order.Edges.Token.Edges.Network, order.GatewayID)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":             fmt.Sprintf("%v", err),
					"OrderID":           order.ID.String(),
					"Amount":            order.Amount,
					"GatewayID":         order.GatewayID,
					"NetworkIdentifier": order.Edges.Token.Edges.Network.Identifier,
				}).Errorf("RetryStaleUserOperations.RefundOrder")
			}
		}
	}(ctx)

	return nil
}
