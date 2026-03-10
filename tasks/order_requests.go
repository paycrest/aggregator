package tasks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/balance"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/redis/go-redis/v9"
	"github.com/shopspring/decimal"
)

// canReassignCancelledOrder returns true if the order is eligible for full reassignment (queue again).
// Same guard as reassignCancelledOrder: public provider, under cancellation threshold, within refund window.
func canReassignCancelledOrder(order *ent.PaymentOrder) bool {
	if order.Edges.Provider == nil {
		return false
	}
	return order.Edges.Provider.VisibilityMode != providerprofile.VisibilityModePrivate &&
		order.CancellationCount < orderConf.RefundCancellationCount &&
		order.CreatedAt.After(time.Now().Add(-orderConf.OrderRefundTimeout-10*time.Second))
}

// cleanupStuckFulfilledFailedOrder performs a state-only cleanup for Fulfilled+failed orders outside the refund window:
// ClearProvider and SetStatus(Pending). Does not queue the order or touch fulfillments.
func cleanupStuckFulfilledFailedOrder(ctx context.Context, order *ent.PaymentOrder) {
	updatedCount, err := storage.Client.PaymentOrder.
		Update().
		Where(
			paymentorder.IDEQ(order.ID),
			paymentorder.Or(
				paymentorder.StatusEQ(paymentorder.StatusFulfilled),
			),
		).
		ClearProvider().
		SetStatus(paymentorder.StatusPending).
		Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":   fmt.Sprintf("%v", err),
			"OrderID": order.ID.String(),
		}).Errorf("cleanupStuckFulfilledFailedOrder: failed to update order")
		return
	}
	if updatedCount == 0 {
		return
	}
}

// reassignCancelledOrder reassigns cancelled orders to providers
func reassignCancelledOrder(ctx context.Context, order *ent.PaymentOrder, fulfillment *ent.PaymentOrderFulfillment) {
	if canReassignCancelledOrder(order) {
		// Push provider ID to order exclude list
		orderKey := fmt.Sprintf("order_exclude_list_%s", order.ID)
		_, err := storage.RedisClient.RPush(ctx, orderKey, order.Edges.Provider.ID).Result()
		if err != nil {
			return
		}
		// Set TTL for the exclude list (2x order request validity since orders can be reassigned)
		err = storage.RedisClient.ExpireAt(ctx, orderKey, time.Now().Add(orderConf.OrderRequestValidity*2)).Err()
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"OrderID": order.ID.String(),
			}).Errorf("failed to set TTL for order exclude list")
		}

		// Defensive check: Verify order is still in a state that allows reassignment
		// AND that the provider hasn't changed (race condition protection)
		// Use atomic update to ensure order is still cancellable/processable by the SAME provider
		updatedCount, err := storage.Client.PaymentOrder.
			Update().
			Where(
				paymentorder.IDEQ(order.ID),
				paymentorder.Or(
					paymentorder.StatusEQ(paymentorder.StatusFulfilling),
					paymentorder.StatusEQ(paymentorder.StatusFulfilled),
					paymentorder.StatusEQ(paymentorder.StatusPending),
					paymentorder.StatusEQ(paymentorder.StatusCancelled), // Include cancelled state
				),
				// CRITICAL: Only update if provider hasn't changed (prevents clearing wrong provider)
				// If another provider accepted the order, this check will fail and we skip reassignment
				paymentorder.HasProviderWith(providerprofile.IDEQ(order.Edges.Provider.ID)),
			).
			ClearProvider().
			SetStatus(paymentorder.StatusPending).
			Save(ctx)
		if err != nil {
			return
		}
		if updatedCount == 0 {
			// Order status changed OR provider changed - no longer eligible for reassignment
			// This prevents clearing a different provider's assignment
			logger.WithFields(logger.Fields{
				"OrderID":    order.ID.String(),
				"Status":     order.Status,
				"ProviderID": order.Edges.Provider.ID,
			}).Warnf("reassignCancelledOrder: Order status or provider changed, skipping reassignment")
			return
		}

		// Best-effort: release any reserved balance held by this provider for the order.
		// This prevents "stuck" reserved balances from blocking future assignments.
		if order.Edges.ProvisionBucket != nil && order.Edges.ProvisionBucket.Edges.Currency != nil {
			currency := order.Edges.ProvisionBucket.Edges.Currency.Code
			amount := order.Amount.Mul(order.Rate).RoundBank(0)
			balanceSvc := balance.New()
			if relErr := balanceSvc.ReleaseFiatBalance(ctx, order.Edges.Provider.ID, currency, amount, nil); relErr != nil {
				logger.WithFields(logger.Fields{
					"Error":      fmt.Sprintf("%v", relErr),
					"OrderID":    order.ID.String(),
					"ProviderID": order.Edges.Provider.ID,
					"Currency":   currency,
					"Amount":     amount.String(),
				}).Warnf("reassignCancelledOrder: failed to release reserved balance (best effort)")
			}
		}

		if fulfillment != nil {
			err = storage.Client.PaymentOrderFulfillment.
				DeleteOneID(fulfillment.ID).
				Exec(ctx)
			if err != nil {
				return
			}
		}

		// Defensive check: Verify order request doesn't already exist before reassigning
		orderRequestKey := fmt.Sprintf("order_request_%s", order.ID)
		exists, existsErr := storage.RedisClient.Exists(ctx, orderRequestKey).Result()
		if existsErr == nil && exists > 0 {
			logger.WithFields(logger.Fields{
				"OrderID": order.ID.String(),
			}).Warnf("reassignCancelledOrder: Order request already exists, skipping duplicate reassignment")
			return
		}

		// Reassign the order to a provider
		paymentOrder := types.PaymentOrderFields{
			ID:                order.ID,
			Token:             order.Edges.Token,
			GatewayID:         order.GatewayID,
			Amount:            order.Amount,
			Rate:              order.Rate,
			BlockNumber:       order.BlockNumber,
			Institution:       order.Institution,
			AccountIdentifier: order.AccountIdentifier,
			AccountName:       order.AccountName,
			ProviderID:        "",
			Memo:              order.Memo,
			ProvisionBucket:   order.Edges.ProvisionBucket,
		}

		err = services.NewPriorityQueueService().AssignPaymentOrder(ctx, paymentOrder)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":     fmt.Sprintf("%v", err),
				"OrderID":   order.ID.String(),
				"OrderKey":  orderKey,
				"GatewayID": order.GatewayID,
			}).Errorf("Redis: Failed to reassign declined order request")
		}
	}
}

const orderRequestKeyPrefix = "order_request_"

// ReassignStaleOrderRequest reassigns expired order requests to providers
func ReassignStaleOrderRequest(ctx context.Context, orderRequestChan <-chan *redis.Message) {
	priorityQueueSvc := services.NewPriorityQueueService()
	balanceSvc := balance.New()

	for {
		select {
		case msg, ok := <-orderRequestChan:
			if !ok {
				// Channel closed, exit gracefully
				return
			}

			isDelEvent := strings.Contains(msg.Channel, ":del:")

			if !strings.HasPrefix(msg.Payload, orderRequestKeyPrefix) {
				logger.WithFields(logger.Fields{"Payload": msg.Payload}).Warnf("ReassignStaleOrderRequest: unexpected payload format, skipping")
				continue
			}
			orderID := strings.TrimPrefix(msg.Payload, orderRequestKeyPrefix)

			orderUUID, err := uuid.Parse(orderID)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   fmt.Sprintf("%v", err),
					"OrderID": orderID,
				}).Errorf("ReassignStaleOrderRequest: Failed to parse order ID")
				continue
			}

			// If this is a DEL event (e.g. provider accept/decline), wait briefly for any concurrent DB update
			// (AcceptOrder updates order status in a separate transaction after deleting the Redis key).
			if isDelEvent {
				shouldSkip := false
				for i := 0; i < 3; i++ {
					currentOrder, err := storage.Client.PaymentOrder.Get(ctx, orderUUID)
					if err == nil && currentOrder != nil && currentOrder.Status != paymentorder.StatusPending {
						shouldSkip = true
						break
					}
					if i < 2 {
						select {
						case <-time.After(250 * time.Millisecond):
						case <-ctx.Done():
							return
						}
					}
				}
				if shouldSkip {
					continue
				}
			}

			// Get the order from the database
			order, err := storage.Client.PaymentOrder.
				Query().
				Where(
					paymentorder.IDEQ(orderUUID),
				).
				WithProvisionBucket(func(pbq *ent.ProvisionBucketQuery) {
					pbq.WithCurrency()
				}).
				WithProvider().
				WithToken(func(tq *ent.TokenQuery) {
					tq.WithNetwork()
				}).
				Only(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   fmt.Sprintf("%v", err),
					"OrderID": orderUUID.String(),
					"UUID":    orderUUID,
				}).Errorf("ReassignStaleOrderRequest: Failed to get order from database")
				continue
			}

			// Best-effort: release reserved balance for the provider that was previously notified.
			// Run before any "skip reassignment" checks so we release even when skipping (e.g. FallbackTriedAt
			// or non-pending status), preventing reserved balance from staying stuck.
			// For regular (public) assignments, the provider isn't persisted on the order until AcceptOrder,
			// so we rely on order_request_meta_* as the source of truth.
			metaKey := fmt.Sprintf("order_request_meta_%s", order.ID)
			meta, metaErr := storage.RedisClient.HGetAll(ctx, metaKey).Result()
			if metaErr == nil && len(meta) > 0 {
				metaProviderID := meta["providerId"]
				metaCurrency := meta["currency"]
				metaAmountStr := meta["amount"]

				// Increment exclude list for this provider (tracks retries and prevents immediate re-selection).
				if metaProviderID != "" {
					excludeKey := fmt.Sprintf("order_exclude_list_%s", order.ID)
					_, _ = storage.RedisClient.RPush(ctx, excludeKey, metaProviderID).Result()
					if expErr := storage.RedisClient.ExpireAt(ctx, excludeKey, time.Now().Add(orderConf.OrderRequestValidity*2)).Err(); expErr != nil {
						logger.WithFields(logger.Fields{
							"Error":      fmt.Sprintf("%v", expErr),
							"OrderID":    order.ID.String(),
							"ExcludeKey": excludeKey,
						}).Warnf("ReassignStaleOrderRequest: failed to set TTL for order exclude list")
					}
				}

				// Release reserved amount (best effort; failures should not block reassignment).
				if metaProviderID != "" && metaCurrency != "" && metaAmountStr != "" {
					amountDec, err := decimal.NewFromString(metaAmountStr)
					if err == nil {
						if relErr := balanceSvc.ReleaseFiatBalance(ctx, metaProviderID, metaCurrency, amountDec, nil); relErr != nil {
							logger.WithFields(logger.Fields{
								"Error":      fmt.Sprintf("%v", relErr),
								"OrderID":    order.ID.String(),
								"ProviderID": metaProviderID,
								"Currency":   metaCurrency,
								"Amount":     metaAmountStr,
							}).Warnf("ReassignStaleOrderRequest: failed to release reserved balance (best effort)")
						}
					}
				}

				// Cleanup metadata key regardless of success to avoid stale entries.
				_, _ = storage.RedisClient.Del(ctx, metaKey).Result()
			} else if order.Edges.Provider != nil && order.Edges.ProvisionBucket != nil && order.Edges.ProvisionBucket.Edges.Currency != nil {
				// Fallback: no meta (e.g. key missing/expired) but order has provider and bucket (e.g. private/pre-set).
				// Release so reserved balance is not left stuck.
				currency := order.Edges.ProvisionBucket.Edges.Currency.Code
				amount := order.Amount.Mul(order.Rate).RoundBank(0)
				if relErr := balanceSvc.ReleaseFiatBalance(ctx, order.Edges.Provider.ID, currency, amount, nil); relErr != nil {
					logger.WithFields(logger.Fields{
						"Error":      fmt.Sprintf("%v", relErr),
						"OrderID":    order.ID.String(),
						"ProviderID": order.Edges.Provider.ID,
						"Currency":   currency,
						"Amount":     amount.String(),
					}).Warnf("ReassignStaleOrderRequest: failed to release reserved balance from order (best effort)")
				}
			}

			// Defensive check: Only reassign if order is in a valid state
			// Skip if order is already processing, fulfilled, validated, settled, or refunded
			if order.Status != paymentorder.StatusPending {
				logger.WithFields(logger.Fields{
					"OrderID": order.ID.String(),
					"Status":  order.Status,
				}).Infof("ReassignStaleOrderRequest: Order is not in pending state, skipping reassignment")
				continue
			}

			// If fallback was already tried, allow retry only if fallback has not exceeded ProviderMaxRetryAttempts
			// (same as queue providers: exclude list count for fallback < N means we can retry).
			if !order.FallbackTriedAt.IsZero() {
				if orderConf.FallbackProviderID == "" {
					continue
				}
				excludeKey := fmt.Sprintf("order_exclude_list_%s", order.ID)
				excludeList, listErr := storage.RedisClient.LRange(ctx, excludeKey, 0, -1).Result()
				if listErr != nil {
					// Retry LRange up to 2 times; on persistent failure proceed with empty exclude list
					// so we still attempt reassignment instead of silently skipping the order.
					for retry := 0; retry < 2 && listErr != nil; retry++ {
						time.Sleep(100 * time.Millisecond)
						excludeList, listErr = storage.RedisClient.LRange(ctx, excludeKey, 0, -1).Result()
					}
					if listErr != nil {
						logger.WithFields(logger.Fields{
							"Error":   fmt.Sprintf("%v", listErr),
							"OrderID": order.ID.String(),
							"Key":     excludeKey,
						}).Warnf("ReassignStaleOrderRequest: LRange failed for exclude list, proceeding with empty list")
						excludeList = nil
					}
				}
				fallbackExcludeCount := 0
				for _, id := range excludeList {
					if id == orderConf.FallbackProviderID {
						fallbackExcludeCount++
					}
				}
				if fallbackExcludeCount >= orderConf.ProviderMaxRetryAttempts {
					continue
				}

				// Clear FallbackTriedAt so TryFallbackAssignment can run again when AssignPaymentOrder is called
				_, updErr := storage.Client.PaymentOrder.
					Update().
					Where(paymentorder.IDEQ(order.ID)).
					ClearFallbackTriedAt().
					Save(ctx)
				if updErr != nil {
					logger.WithFields(logger.Fields{
						"OrderID": order.ID.String(),
						"Error":   updErr,
					}).Errorf("ReassignStaleOrderRequest: failed to clear FallbackTriedAt for retry")
					continue
				}
				order.FallbackTriedAt = time.Time{} // so downstream uses updated value if needed
			}

			// Extract provider ID from relation if available
			providerID := ""
			if order.Edges.Provider != nil {
				providerID = order.Edges.Provider.ID
			}

			// Build order fields for reassignment
			orderFields := types.PaymentOrderFields{
				ID:                order.ID,
				OrderType:         string(order.OrderType),
				GatewayID:         order.GatewayID,
				Amount:            order.Amount,
				Rate:              order.Rate,
				BlockNumber:       order.BlockNumber,
				Institution:       order.Institution,
				AccountIdentifier: order.AccountIdentifier,
				AccountName:       order.AccountName,
				Memo:              order.Memo,
				ProviderID:        providerID,
				MessageHash:       order.MessageHash,
				ProvisionBucket:   order.Edges.ProvisionBucket,
			}

			// Include token and network if available
			if order.Edges.Token != nil {
				orderFields.Token = order.Edges.Token
				if order.Edges.Token.Edges.Network != nil {
					orderFields.Network = order.Edges.Token.Edges.Network
				}
			}

			// Assign the order to a provider
			err = priorityQueueSvc.AssignPaymentOrder(ctx, orderFields)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":     fmt.Sprintf("%v", err),
					"OrderID":   order.ID.String(),
					"UUID":      orderUUID,
					"GatewayID": order.GatewayID,
				}).Errorf("ReassignStaleOrderRequest: Failed to assign order to provider")
			}

		case <-ctx.Done():
			// Context cancelled, exit gracefully to allow deferred cleanup
			return
		}
	}
}
