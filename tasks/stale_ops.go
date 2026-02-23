package tasks

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/paymentorderfulfillment"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/provisionbucket"
	"github.com/paycrest/aggregator/services"
	orderService "github.com/paycrest/aggregator/services/order"
	starknetService "github.com/paycrest/aggregator/services/starknet"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
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
				// Stuck settling: updated > 10 min ago and < 12 min ago. The retry process is called every 60 seconds, so we should only retry once or twice at most.
				paymentorder.And(
					paymentorder.StatusEQ(paymentorder.StatusSettling),
					paymentorder.UpdatedAtLT(time.Now().Add(-10*time.Minute)),
					paymentorder.CreatedAtLTE(time.Now().Add(-15*time.Minute)),
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
		WithProvisionBucket(func(pbq *ent.ProvisionBucketQuery) {
			pbq.WithCurrency()
		}).
		WithProvider().
		All(ctx)
	if err != nil {
		return fmt.Errorf("RetryStaleUserOperations: %w", err)
	}

	wg.Add(1)
	go func(ctx context.Context) {
		defer wg.Done()
		for _, order := range lockOrders {
			// 1) If we already tried fallback (DB) or order is already on fallback provider, skip reassignment and refund.
			tryFallback := orderConf.FallbackProviderID != ""
			fallbackAlreadyTried := false
			if tryFallback {
				if !order.FallbackTriedAt.IsZero() || (order.Edges.Provider != nil && order.Edges.Provider.ID == orderConf.FallbackProviderID) {
					tryFallback = false
					fallbackAlreadyTried = true
				}
			}

			pq := services.NewPriorityQueueService()

			// If the order could still be reassigned to another public provider (per order_requests logic),
			if order.CancellationCount < orderConf.RefundCancellationCount {
				// Safeguard: only reassign via full-queue when order was NOT already sent to a provider (no order_request in Redis).
				// When order_request_* exists, sendOrderRequest already stored it; skip full-queue and go through fallback to avoid double-send.
				orderRequestKey := fmt.Sprintf("order_request_%s", order.ID.String())
				orderRequestExists, orderRequestErr := storage.RedisClient.Exists(ctx, orderRequestKey).Result()
				if orderRequestErr != nil {
					logger.WithFields(logger.Fields{"OrderID": order.ID.String(), "Error": orderRequestErr}).Errorf("RetryStaleUserOperations: failed to check order_request key; assuming exists to avoid double-send")
					orderRequestExists = 1 // treat as exists so we skip full-queue
				}
				tryFullQueue := !fallbackAlreadyTried && (orderRequestExists == 0)

				// No provider or public provider: can try full-queue (reassign to public). Private provider: skip full-queue.
				// Allow nil bucket so we can try to resolve and persist it before assignment (another node can then pick the order).
				canTryFullQueue := (order.Edges.ProvisionBucket == nil || (order.Edges.ProvisionBucket != nil && order.Edges.ProvisionBucket.Edges.Currency != nil)) &&
					(order.Edges.Provider == nil || order.Edges.Provider.VisibilityMode != providerprofile.VisibilityModePrivate)

				if tryFullQueue && canTryFullQueue {
					// AssignPaymentOrder expects StatusPending; if Cancelled (e.g. from HandleCancellation), set to Pending first.
					if order.Status == paymentorder.StatusCancelled {
						_, _ = storage.Client.PaymentOrder.
							Update().
							Where(paymentorder.IDEQ(order.ID)).
							ClearProvider().
							SetStatus(paymentorder.StatusPending).
							Save(ctx)
					}

					// Resolve and persist nil provision bucket so AssignPaymentOrder can run and another node can pick the order.
					if order.Edges.ProvisionBucket == nil {
						institution, instErr := utils.GetInstitutionByCode(ctx, order.Institution, true)
						if instErr == nil && institution != nil && institution.Edges.FiatCurrency != nil {
							fiatAmount := order.Amount.Mul(order.Rate)
							bucket, bErr := storage.Client.ProvisionBucket.
								Query().
								Where(
									provisionbucket.MaxAmountGTE(fiatAmount),
									provisionbucket.MinAmountLTE(fiatAmount),
									provisionbucket.HasCurrencyWith(fiatcurrency.IDEQ(institution.Edges.FiatCurrency.ID)),
								).
								WithCurrency().
								First(ctx)
							if bErr == nil && bucket != nil {
								if _, upErr := storage.Client.PaymentOrder.UpdateOneID(order.ID).SetProvisionBucket(bucket).Save(ctx); upErr == nil {
									order.Edges.ProvisionBucket = bucket
								}
							}
						}
						if order.Edges.ProvisionBucket == nil {
							logger.WithFields(logger.Fields{"OrderID": order.ID.String()}).Warnf("stale_ops: could not resolve provision bucket for order; skipping full-queue assignment")
						}
					}

					if order.Edges.ProvisionBucket != nil && order.Edges.ProvisionBucket.Edges.Currency != nil {
						orderFields := types.PaymentOrderFields{
						ID:                order.ID,
						OrderType:         order.OrderType.String(),
						Token:             order.Edges.Token,
						GatewayID:         order.GatewayID,
						Amount:            order.Amount,
						Rate:              order.Rate,
						Institution:       order.Institution,
						AccountIdentifier: order.AccountIdentifier,
						AccountName:       order.AccountName,
						ProviderID:        "",
						ProvisionBucket:   order.Edges.ProvisionBucket,
						MessageHash:       order.MessageHash,
						Memo:              order.Memo,
						UpdatedAt:         order.UpdatedAt,
						CreatedAt:         order.CreatedAt,
					}
					if order.Edges.Token != nil && order.Edges.Token.Edges.Network != nil {
						orderFields.Network = order.Edges.Token.Edges.Network
					}

					err := pq.AssignPaymentOrder(ctx, orderFields)
					if err == nil {
						logger.WithFields(logger.Fields{"OrderID": order.ID.String()}).Infof("order assigned to provider during refund process; skipping refund")
						continue
					}
					// We tried public reassignment and it failed; set cancellation count to threshold immediately so we can refund.
					// Any failure should proceed to try fallback, else proceed with refund
					_, _ = storage.Client.PaymentOrder.
						Update().
						Where(paymentorder.IDEQ(order.ID)).
						SetCancellationCount(orderConf.RefundCancellationCount).
						Save(ctx)
					}
				}
			}

			// 3) Full queue skipped or failed; try fallback (only if configured and not already tried).
			// Fallback only succeeds when order_request_* key is gone (expired or cleared); TryFallbackAssignment returns error if key exists.
			// Any failure should proceed with refund
			if tryFallback {
				err := pq.TryFallbackAssignment(ctx, order)
				if err == nil {
					continue
				}
				logger.WithFields(logger.Fields{
					"OrderID": order.ID.String(),
					"Error":   err.Error(),
				}).Errorf("RetryStaleUserOperations: TryFallbackAssignment failed")
				if order.CancellationCount < orderConf.RefundCancellationCount {
					_, updateErr := storage.Client.PaymentOrder.
						Update().
						Where(paymentorder.IDEQ(order.ID)).
						SetCancellationCount(orderConf.RefundCancellationCount).
						Save(ctx)
					if updateErr != nil {
						logger.WithFields(logger.Fields{
							"Error":   fmt.Sprintf("%v", updateErr),
							"OrderID": order.ID.String(),
						}).Errorf("RetryStaleUserOperations: failed to update cancellation count; continue with refund")
					}
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
