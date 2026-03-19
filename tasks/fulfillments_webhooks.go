package tasks

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/paymentorderfulfillment"
	"github.com/paycrest/aggregator/ent/senderprofile"
	"github.com/paycrest/aggregator/ent/transactionlog"
	"github.com/paycrest/aggregator/ent/webhookretryattempt"
	"github.com/paycrest/aggregator/services/balance"
	"github.com/paycrest/aggregator/services/email"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

const txStatusFiveMinError = "Failed to get transaction status after 5 minutes"
const txStatusRetryWindow = 5 * time.Minute
const txStatusRetryCutoff = 24 * time.Hour

// txStatusBackoffDelaysMinutes are cumulative minutes from UpdatedAt for each retry slot (exponential: 10, +20, +40, +80, +160, +320).
var txStatusBackoffDelaysMinutes = []float64{10, 30, 70, 150, 310, 630}

func shouldRetryTxStatusFiveMinFailure(fulfillment *ent.PaymentOrderFulfillment) bool {
	if fulfillment.ValidationError != txStatusFiveMinError || fulfillment.ValidationStatus != paymentorderfulfillment.ValidationStatusFailed {
		return false
	}
	elapsed := time.Since(fulfillment.UpdatedAt)
	if elapsed < 10*time.Minute || elapsed >= txStatusRetryCutoff {
		return false
	}
	elapsedMin := elapsed.Minutes()
	windowMin := txStatusRetryWindow.Minutes()
	for _, d := range txStatusBackoffDelaysMinutes {
		if elapsedMin >= d && elapsedMin < d+windowMin {
			return true
		}
	}
	return false
}

// SyncPaymentOrderFulfillments syncs payment order fulfillments
// Only processes regular orders
// TODO: refactor this to process OTC orders as well when OTC fulfillment validation is automated
func SyncPaymentOrderFulfillments() {
	// ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	// defer cancel()
	ctx := context.Background()

	// Use distributed lock to prevent concurrent execution
	// Lock TTL: 90 seconds (2x cron interval + buffer for processing time)
	// This ensures the lock doesn't expire even if processing takes longer than one cron cycle
	cleanup, acquired, err := acquireDistributedLock(ctx, "sync_payment_order_fulfillments_lock", 90*time.Second, "SyncPaymentOrderFulfillments")
	if err != nil {
		return
	}
	if !acquired {
		// Another instance is already running; skip.
		return
	}
	defer cleanup()

	// Query unvalidated lock orders (regular orders only - exclude OTC)
	paymentOrders, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.OrderTypeEQ(paymentorder.OrderTypeRegular), // Only regular orders
			paymentorder.Or(
				paymentorder.And(
					paymentorder.StatusEQ(paymentorder.StatusFulfilled),
					paymentorder.Or(
						paymentorder.HasFulfillmentsWith(
							paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusFailed),
							paymentorderfulfillment.Not(paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusSuccess)),
							paymentorderfulfillment.Not(paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusPending)),
						),
						paymentorder.HasFulfillmentsWith(
							paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusPending),
							paymentorderfulfillment.UpdatedAtLTE(time.Now().Add(-orderConf.OrderFulfillmentValidity)),
						),
						paymentorder.HasFulfillmentsWith(
							paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusSuccess),
						),
					),
				),
				paymentorder.And(
					paymentorder.StatusEQ(paymentorder.StatusCancelled),
					paymentorder.Or(
						paymentorder.HasFulfillmentsWith(
							paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusPending),
						),
						paymentorder.Not(paymentorder.HasFulfillments()),
					),
				),
				paymentorder.And(
					paymentorder.StatusEQ(paymentorder.StatusFulfilling),
					paymentorder.UpdatedAtLTE(time.Now().Add(-30*time.Second)),
					paymentorder.Not(paymentorder.HasFulfillments()),
				),
				// Payin insufficient-balance refund: onramp orders in Refunding (no on-chain Refunded event)
				paymentorder.And(
					paymentorder.StatusEQ(paymentorder.StatusRefunding),
					paymentorder.DirectionEQ(paymentorder.DirectionOnramp),
				),
			),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithProvider(func(pq *ent.ProviderProfileQuery) {
			pq.WithAPIKey()
		}).
		WithFulfillments().
		All(ctx)
	if err != nil {
		return
	}

	for _, order := range paymentOrders {
		// Defensive check: Re-fetch order to ensure it still exists and is in a valid state
		// This handles cases where another concurrent process might have deleted or finalized it.
		currentOrder, err := storage.Client.PaymentOrder.Query().
			Where(paymentorder.IDEQ(order.ID)).
			WithToken(func(tq *ent.TokenQuery) {
				tq.WithNetwork()
			}).
			WithProvider(func(pq *ent.ProviderProfileQuery) {
				pq.WithAPIKey()
			}).
			WithFulfillments().
			Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				continue
			}
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"OrderID": order.ID.String(),
			}).Errorf("SyncPaymentOrderFulfillments: Failed to fetch order, skipping processing")
			continue
		}
		// Use currentOrder for further processing
		order = currentOrder

		if order.Edges.Provider == nil {
			continue
		}
		if order.Edges.Provider.Edges.APIKey == nil {
			logger.WithFields(logger.Fields{
				"OrderID":    order.ID.String(),
				"ProviderID": order.Edges.Provider.ID,
				"Reason":     "internal: Provider APIKey is nil",
			}).Errorf("SyncPaymentOrderFulfillments.MissingAPIKey")
			continue
		}
		if len(order.Edges.Fulfillments) == 0 {
			// Refunding (onramp): sync refund outcome via /tx_status
			if order.Status == paymentorder.StatusRefunding {
				syncRefundingOrder(ctx, order)
				continue
			}
			if order.Status == paymentorder.StatusCancelled {
				if order.Direction == paymentorder.DirectionOfframp {
					reassignCancelledOrder(ctx, order, nil)
				}
				continue
			}

			currencyCode, curErr := utils.GetInstitutionCurrencyCode(ctx, order.Institution, true)
			if curErr != nil || currencyCode == "" {
				logger.WithFields(logger.Fields{
					"OrderID":    order.ID.String(),
					"ProviderID": order.Edges.Provider.ID,
					"Reason":     "internal: institution currency lookup failed",
				}).Errorf("SyncPaymentOrderFulfillments.MissingCurrency")
				continue
			}

			payload := map[string]interface{}{
				"reference": getTxStatusReferenceForVA(order),
				"currency":  currencyCode,
			}
			data, err := utils.CallProviderWithHMAC(ctx, order.Edges.Provider.ID, "POST", "/tx_status", payload)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":            fmt.Sprintf("%v", err),
					"ProviderID":       order.Edges.Provider.ID,
					"PayloadReference": payload["reference"],
					"PayloadCurrency":  payload["currency"],
					"Reason":           "internal: Failed to send tx_status request to provider",
				}).Errorf("SyncPaymentOrderFulfillments.SendTxStatusRequest")

				// Set status to pending on 400 error
				if strings.Contains(fmt.Sprintf("%v", err), "400") {
					_, updateErr := storage.Client.PaymentOrder.
						UpdateOneID(order.ID).
						SetStatus(paymentorder.StatusPending).
						Save(ctx)
					if updateErr != nil {
						logger.WithFields(logger.Fields{
							"Error":      updateErr,
							"OrderID":    order.ID.String(),
							"ProviderID": order.Edges.Provider.ID,
							"Reason":     "internal: Failed to update order status",
						}).Errorf("SyncPaymentOrderFulfillments.UpdateStatus")
					}
				}
				continue
			}

			status := data["data"].(map[string]interface{})["status"].(string)
			psp := data["data"].(map[string]interface{})["psp"].(string)
			txId := data["data"].(map[string]interface{})["txId"].(string)
			validationError := ""
			if errVal, ok := data["data"].(map[string]interface{})["error"].(string); ok {
				validationError = errVal
			}

			if status == "failed" {
				_, err = storage.Client.PaymentOrderFulfillment.
					Create().
					SetOrderID(order.ID).
					SetPsp(psp).
					SetTxID(txId).
					SetValidationStatus(paymentorderfulfillment.ValidationStatusFailed).
					SetValidationError(validationError).
					Save(ctx)
				if err != nil {
					continue
				}
				_, err = order.Update().
					SetStatus(paymentorder.StatusFulfilled).
					Save(ctx)
				if err != nil {
					continue
				}
				// Payin (onramp): release reserved token balance on failure
				if order.Direction == paymentorder.DirectionOnramp && order.Edges.Token != nil && order.Edges.Provider != nil {
					balanceService := balance.New()
					totalCryptoReserved := order.Amount.Add(order.SenderFee)
					if relErr := balanceService.ReleaseTokenBalance(ctx, order.Edges.Provider.ID, order.Edges.Token.ID, totalCryptoReserved, nil); relErr != nil {
						logger.WithFields(logger.Fields{"OrderID": order.ID.String(), "Error": relErr}).Errorf("SyncPaymentOrderFulfillments: release balance on payin failed")
					}
				}
			} else if status == "success" {
				_, err = storage.Client.PaymentOrderFulfillment.
					Create().
					SetOrderID(order.ID).
					SetPsp(psp).
					SetTxID(txId).
					SetValidationStatus(paymentorderfulfillment.ValidationStatusSuccess).
					Save(ctx)
				if err != nil {
					continue
				}
				// Payin (onramp): ask provider to run AcceptOrder + FulfillOrder(Success) with EIP-7702 auth
				if order.Direction == paymentorder.DirectionOnramp {
					if reqErr := callRequestAuthorization(ctx, order, psp, txId, order.Amount.Add(order.SenderFee).String()); reqErr != nil {
						logger.WithFields(logger.Fields{
							"OrderID": order.ID.String(),
							"Error":   reqErr.Error(),
						}).Warnf("SyncPaymentOrderFulfillments: request_authorization failed (will retry on next sync)")
					}
					continue
				}
				// Payout (offramp): set order to Validated and send webhook
				if order.Edges.Token == nil {
					logger.WithFields(logger.Fields{
						"OrderID":    order.ID.String(),
						"ProviderID": order.Edges.Provider.ID,
						"Reason":     "internal: Token is nil",
					}).Errorf("SyncPaymentOrderFulfillments.MissingToken")
					continue
				}
				if order.Edges.Token.Edges.Network == nil {
					logger.WithFields(logger.Fields{
						"OrderID":    order.ID.String(),
						"ProviderID": order.Edges.Provider.ID,
						"Reason":     "internal: Token Network is nil",
					}).Errorf("SyncPaymentOrderFulfillments.MissingNetwork")
					continue
				}
				transactionLog, err := storage.Client.TransactionLog.
					Create().
					SetStatus(transactionlog.StatusOrderValidated).
					SetNetwork(order.Edges.Token.Edges.Network.Identifier).
					Save(ctx)
				if err != nil {
					continue
				}
				_, err = storage.Client.PaymentOrder.
					UpdateOneID(order.ID).
					SetStatus(paymentorder.StatusValidated).
					AddTransactions(transactionLog).
					Save(ctx)
				if err != nil {
					continue
				}
				if err := utils.SendPaymentOrderWebhook(ctx, order); err != nil {
					logger.WithFields(logger.Fields{
						"Error":       fmt.Sprintf("%v", err),
						"MessageHash": order.MessageHash,
						"OrderID":     order.ID,
					}).Errorf("SyncPaymentOrderFulfillments.UpdatePaymentOrderValidated.webhook")
				}
			}
		} else {
			currencyCode, curErr := utils.GetInstitutionCurrencyCode(ctx, order.Institution, true)
			if curErr != nil || currencyCode == "" {
				logger.WithFields(logger.Fields{
					"OrderID":    order.ID.String(),
					"ProviderID": order.Edges.Provider.ID,
					"Reason":     "internal: institution currency lookup failed",
				}).Errorf("SyncPaymentOrderFulfillments.MissingCurrency")
				continue
			}

			for _, fulfillment := range order.Edges.Fulfillments {
				if fulfillment.ValidationStatus == paymentorderfulfillment.ValidationStatusPending {
					payload := map[string]interface{}{
						"reference": getTxStatusReferenceForVA(order),
						"currency":  currencyCode,
						"psp":       fulfillment.Psp,
						"txId":      fulfillment.TxID,
					}

					data, err := utils.CallProviderWithHMAC(ctx, order.Edges.Provider.ID, "POST", "/tx_status", payload)
					if err != nil {
						if strings.Contains(err.Error(), "400") && time.Since(fulfillment.CreatedAt) > 5*time.Minute {
							logger.WithFields(logger.Fields{
								"Error":           fmt.Sprintf("%v", err),
								"Data":            data,
								"ProviderID":      order.Edges.Provider.ID,
								"PayloadCurrency": payload["currency"],
								"PayloadPsp":      payload["psp"],
								"PayloadTxId":     payload["txId"],
							}).Errorf("%s: %s", txStatusFiveMinError, order.ID.String())
							_, updateErr := storage.Client.PaymentOrderFulfillment.
								UpdateOneID(fulfillment.ID).
								SetValidationStatus(paymentorderfulfillment.ValidationStatusFailed).
								SetValidationError(txStatusFiveMinError).
								Save(ctx)
							if updateErr != nil {
								logger.WithFields(logger.Fields{
									"Error":         fmt.Sprintf("%v", updateErr),
									"OrderID":       order.ID.String(),
									"FulfillmentID": fulfillment.ID,
								}).Errorf("Failed to mark fulfillment as failed after 5 minutes")
							}
							continue
						}

						logger.WithFields(logger.Fields{
							"Error":           fmt.Sprintf("%v", err),
							"ProviderID":      order.Edges.Provider.ID,
							"PayloadOrderId":  payload["orderId"],
							"PayloadCurrency": payload["currency"],
							"PayloadPsp":      payload["psp"],
							"PayloadTxId":     payload["txId"],
						}).Errorf("Failed to parse JSON response after getting trx status from provider: %s", order.ID.String())
						continue
					}

					dataMap, ok := data["data"].(map[string]interface{})
					if !ok {
						continue
					}
					status, ok := dataMap["status"].(string)
					if !ok {
						continue
					}

					if status == "failed" {
						errMsg, _ := dataMap["error"].(string)
						_, err = storage.Client.PaymentOrderFulfillment.
							UpdateOneID(fulfillment.ID).
							SetTxID(fulfillment.TxID).
							SetValidationStatus(paymentorderfulfillment.ValidationStatusFailed).
							SetValidationError(errMsg).
							Save(ctx)
						if err != nil {
							continue
						}

						_, err = order.Update().
							SetStatus(paymentorder.StatusFulfilled).
							Save(ctx)
						if err != nil {
							continue
						}
						// Payin (onramp): release reserved token balance on failure
						if order.Direction == paymentorder.DirectionOnramp && order.Edges.Token != nil && order.Edges.Provider != nil {
							balanceService := balance.New()
							totalCryptoReserved := order.Amount.Add(order.SenderFee)
							if relErr := balanceService.ReleaseTokenBalance(ctx, order.Edges.Provider.ID, order.Edges.Token.ID, totalCryptoReserved, nil); relErr != nil {
								logger.WithFields(logger.Fields{"OrderID": order.ID.String(), "Error": relErr}).Errorf("SyncPaymentOrderFulfillments: release balance on payin failed (pending→failed)")
							}
						}
					} else if status == "success" {
						_, err = storage.Client.PaymentOrderFulfillment.
							UpdateOneID(fulfillment.ID).
							SetTxID(fulfillment.TxID).
							SetValidationStatus(paymentorderfulfillment.ValidationStatusSuccess).
							SetValidationError("").
							Save(ctx)
						if err != nil {
							continue
						}
						// Onramp: ask provider to run AcceptOrder + FulfillOrder(Success) with EIP-7702 auth
						if order.Direction == paymentorder.DirectionOnramp {
							if reqErr := callRequestAuthorization(ctx, order, fulfillment.Psp, fulfillment.TxID, order.Amount.Add(order.SenderFee).String()); reqErr != nil {
								logger.WithFields(logger.Fields{
									"OrderID": order.ID.String(),
									"Error":   reqErr.Error(),
								}).Warnf("SyncPaymentOrderFulfillments: request_authorization failed for pending→success (will retry on next sync)")
							}
							continue
						}
						// Offramp: set order to Validated and send webhook
						if order.Edges.Token == nil {
							logger.WithFields(logger.Fields{
								"OrderID":    order.ID.String(),
								"ProviderID": order.Edges.Provider.ID,
								"Reason":     "internal: Token is nil",
							}).Errorf("SyncPaymentOrderFulfillments.MissingToken")
							continue
						}
						if order.Edges.Token.Edges.Network == nil {
							logger.WithFields(logger.Fields{
								"OrderID":    order.ID.String(),
								"ProviderID": order.Edges.Provider.ID,
								"Reason":     "internal: Token Network is nil",
							}).Errorf("SyncPaymentOrderFulfillments.MissingNetwork")
							continue
						}

						transactionLog, err := storage.Client.TransactionLog.
							Create().
							SetStatus(transactionlog.StatusOrderValidated).
							SetNetwork(order.Edges.Token.Edges.Network.Identifier).
							Save(ctx)
						if err != nil {
							continue
						}

						_, err = storage.Client.PaymentOrder.
							UpdateOneID(order.ID).
							SetStatus(paymentorder.StatusValidated).
							AddTransactions(transactionLog).
							Save(ctx)
						if err != nil {
							continue
						}

						if err := utils.SendPaymentOrderWebhook(ctx, order); err != nil {
							logger.WithFields(logger.Fields{
								"Error":       fmt.Sprintf("%v", err),
								"MessageHash": order.MessageHash,
								"OrderID":     order.ID,
							}).Errorf("SyncPaymentOrderFulfillments.UpdatePaymentOrderValidated.webhook")
						}
					}

				} else if fulfillment.ValidationStatus == paymentorderfulfillment.ValidationStatusFailed &&
					shouldRetryTxStatusFiveMinFailure(fulfillment) {
					currencyCode, curErr := utils.GetInstitutionCurrencyCode(ctx, order.Institution, true)
					if curErr != nil || currencyCode == "" {
						continue
					}
					payload := map[string]interface{}{
						"orderId":  order.ID.String(),
						"currency": currencyCode,
						"psp":      fulfillment.Psp,
						"txId":     fulfillment.TxID,
					}
					data, err := utils.CallProviderWithHMAC(ctx, order.Edges.Provider.ID, "POST", "/tx_status", payload)
					if err != nil {
						continue
					}
					dataMap, ok := data["data"].(map[string]interface{})
					if !ok {
						continue
					}
					status, ok := dataMap["status"].(string)
					if !ok {
						continue
					}
					if status == "failed" {
						errMsg, _ := dataMap["error"].(string)
						if errMsg != fulfillment.ValidationError {
							_, _ = storage.Client.PaymentOrderFulfillment.
								UpdateOneID(fulfillment.ID).
								SetTxID(fulfillment.TxID).
								SetValidationStatus(paymentorderfulfillment.ValidationStatusFailed).
								SetValidationError(errMsg).
								Save(ctx)
						}
						_, _ = order.Update().SetStatus(paymentorder.StatusFulfilled).Save(ctx)
					} else if status == "success" {
						_, err = storage.Client.PaymentOrderFulfillment.
							UpdateOneID(fulfillment.ID).
							SetTxID(fulfillment.TxID).
							SetValidationStatus(paymentorderfulfillment.ValidationStatusSuccess).
							SetValidationError("").
							Save(ctx)
						if err != nil {
							continue
						}
						if order.Edges.Token != nil && order.Edges.Token.Edges.Network != nil {
							transactionLog, err := storage.Client.TransactionLog.
								Create().
								SetStatus(transactionlog.StatusOrderValidated).
								SetNetwork(order.Edges.Token.Edges.Network.Identifier).
								Save(ctx)
							if err == nil && transactionLog != nil {
								_, _ = storage.Client.PaymentOrder.
									UpdateOneID(order.ID).
									SetStatus(paymentorder.StatusValidated).
									AddTransactions(transactionLog).
									Save(ctx)
								_ = utils.SendPaymentOrderWebhook(ctx, order)
							}
						}
					}
					continue
				} else if fulfillment.ValidationStatus == paymentorderfulfillment.ValidationStatusFailed {
					// Onramp: no reassign on failed fulfillment (balance released in syncRefundingOrder or payin-failed path).
					if order.Direction == paymentorder.DirectionOnramp {
						continue
					}
					if canReassignCancelledOrder(order) {
						reassignCancelledOrder(ctx, order, fulfillment)
					} else if order.CreatedAt.Before(time.Now().Add(-orderConf.OrderRefundTimeout-10*time.Second)) &&
						fulfillment.ValidationError != txStatusFiveMinError {
						cleanupStuckFulfilledFailedOrder(ctx, order)
					}
					continue

				} else if fulfillment.ValidationStatus == paymentorderfulfillment.ValidationStatusSuccess {
					// Onramp: no OrderValidated from sync; order stays Fulfilling until FulfillOrder(Success) from provider
					if order.Direction == paymentorder.DirectionOnramp {
						continue
					}

					// Offramp: set order to Validated and send webhook
					if order.Edges.Token == nil {
						logger.WithFields(logger.Fields{
							"OrderID":    order.ID.String(),
							"ProviderID": order.Edges.Provider.ID,
							"Reason":     "internal: Token is nil",
						}).Errorf("SyncPaymentOrderFulfillments.MissingToken")
						continue
					}
					if order.Edges.Token.Edges.Network == nil {
						logger.WithFields(logger.Fields{
							"OrderID":    order.ID.String(),
							"ProviderID": order.Edges.Provider.ID,
							"Reason":     "internal: Token Network is nil",
						}).Errorf("SyncPaymentOrderFulfillments.MissingNetwork")
						continue
					}

					transactionLog, err := storage.Client.TransactionLog.
						Create().
						SetStatus(transactionlog.StatusOrderValidated).
						SetNetwork(order.Edges.Token.Edges.Network.Identifier).
						Save(ctx)
					if err != nil {
						continue
					}

					_, err = storage.Client.PaymentOrder.
						UpdateOneID(order.ID).
						SetStatus(paymentorder.StatusValidated).
						AddTransactions(transactionLog).
						Save(ctx)
					if err != nil {
						continue
					}

					if err := utils.SendPaymentOrderWebhook(ctx, order); err != nil {
						logger.WithFields(logger.Fields{
							"Error":       fmt.Sprintf("%v", err),
							"MessageHash": order.MessageHash,
							"OrderID":     order.ID,
						}).Errorf("SyncPaymentOrderFulfillments.UpdatePaymentOrderValidated.webhook")
					}
				}
			}
		}
	}
}

// Retry failed webhook notifications
func RetryFailedWebhookNotifications() error {
	// Use timeout only for fetching attempts, not for processing them
	// Processing should use per-operation timeouts to avoid deadline exceeded errors
	fetchCtx, fetchCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer fetchCancel()

	// Fetch failed webhook notifications that are due for retry
	attempts, err := storage.Client.WebhookRetryAttempt.
		Query().
		Where(
			webhookretryattempt.StatusEQ(webhookretryattempt.StatusFailed),
			webhookretryattempt.NextRetryTimeLTE(time.Now()),
		).
		All(fetchCtx)
	if err != nil {
		return fmt.Errorf("RetryFailedWebhookNotifications: %w", err)
	}

	baseDelay := 2 * time.Minute
	maxCumulativeTime := 24 * time.Hour

	for _, attempt := range attempts {
		// Send the webhook notification with per-request timeout
		body, err := fastshot.NewClient(attempt.WebhookURL).
			Config().SetCustomTransport(utils.GetHTTPClient().Transport).Config().SetTimeout(30*time.Second).
			Header().Add("X-Paycrest-Signature", attempt.Signature).
			Build().POST("").
			Body().AsJSON(attempt.Payload).
			Send()

		if err != nil || (body.Raw() != nil && body.Raw().StatusCode >= 205) {
			// Webhook notification failed - use per-operation timeouts to prevent deadline exceeded errors
			attemptNumber := attempt.AttemptNumber + 1
			delay := baseDelay * time.Duration(math.Pow(2, float64(attemptNumber-1)))

			nextRetryTime := time.Now().Add(delay)

			attemptUpdate := attempt.Update()

			attemptUpdate.
				AddAttemptNumber(1).
				SetNextRetryTime(nextRetryTime)

			// Set status to expired if cumulative time is greater than 24 hours
			if nextRetryTime.Sub(attempt.CreatedAt.Add(-baseDelay)) > maxCumulativeTime {
				attemptUpdate.SetStatus(webhookretryattempt.StatusExpired)

				// Safe payload extraction to avoid panic on bad or corrupted data; log and continue on error so batch is not aborted
				data, ok := attempt.Payload["data"].(map[string]interface{})
				if !ok {
					logger.WithFields(logger.Fields{
						"AttemptID": attempt.ID,
						"Payload":   attempt.Payload,
					}).Errorf("RetryFailedWebhookNotifications: invalid payload structure, missing 'data'")
					// Fall through to save expired status
				} else {
					senderIDStr, ok := data["senderId"].(string)
					if !ok {
						logger.WithFields(logger.Fields{
							"AttemptID": attempt.ID,
							"Payload":   attempt.Payload,
						}).Errorf("RetryFailedWebhookNotifications: invalid payload structure, missing 'senderId'")
					} else if uid, parseErr := uuid.Parse(senderIDStr); parseErr != nil {
						logger.WithFields(logger.Fields{
							"Error":     fmt.Sprintf("%v", parseErr),
							"AttemptID": attempt.ID,
						}).Errorf("RetryFailedWebhookNotifications.FailedExtraction")
					} else {
						// Use separate context for SenderProfile fetch to avoid deadline pressure
						profileCtx, profileCancel := context.WithTimeout(context.Background(), 10*time.Second)
						profile, profileErr := storage.Client.SenderProfile.
							Query().
							Where(senderprofile.IDEQ(uid)).
							WithUser().
							Only(profileCtx)
						profileCancel()

						if profileErr != nil {
							logger.WithFields(logger.Fields{
								"Error":     fmt.Sprintf("%v", profileErr),
								"AttemptID": attempt.ID,
							}).Errorf("RetryFailedWebhookNotifications.CouldNotFetchProfile")
						} else if profile == nil || profile.Edges.User == nil {
							logger.WithFields(logger.Fields{"AttemptID": attempt.ID}).Errorf("RetryFailedWebhookNotifications: profile or user missing")
						} else {
							emailCtx, emailCancel := context.WithTimeout(context.Background(), 15*time.Second)
							emailService := email.NewEmailServiceWithProviders()
							_, emailErr := emailService.SendWebhookFailureEmail(emailCtx, profile.Edges.User.Email, profile.Edges.User.FirstName)
							emailCancel()
							if emailErr != nil {
								logger.WithFields(logger.Fields{
									"Error":     fmt.Sprintf("%v", emailErr),
									"AttemptID": attempt.ID,
								}).Errorf("RetryFailedWebhookNotifications.SendWebhookFailureEmail")
								// Still save expired status below
							}
						}
					}
				}
			}

			// Use separate context for save operation to ensure clean deadline
			saveCtx, saveCancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, err := attemptUpdate.Save(saveCtx)
			saveCancel()

			if err != nil {
				// Log error but don't fail entire batch - skip this attempt and continue
				logger.WithFields(logger.Fields{
					"Error":     fmt.Sprintf("%v", err),
					"AttemptID": attempt.ID,
				}).Errorf("RetryFailedWebhookNotifications.SaveUpdate")
				continue
			}

			continue
		}

		// Webhook notification was successful - use per-operation timeout for update
		successCtx, successCancel := context.WithTimeout(context.Background(), 10*time.Second)

		_, err = attempt.Update().
			SetStatus(webhookretryattempt.StatusSuccess).
			Save(successCtx)

		successCancel()

		if err != nil {
			// Log error but don't fail entire batch - skip this attempt and continue
			logger.WithFields(logger.Fields{
				"Error":     fmt.Sprintf("%v", err),
				"AttemptID": attempt.ID,
			}).Errorf("RetryFailedWebhookNotifications.SaveSuccess")
			continue
		}
	}

	return nil
}

// syncRefundingOrder calls the provider /tx_status for an onramp order in Refunding and updates order/fulfillment to refunded/failed/pending.
func syncRefundingOrder(ctx context.Context, order *ent.PaymentOrder) {
	currencyCode, curErr := utils.GetInstitutionCurrencyCode(ctx, order.Institution, true)
	if curErr != nil || currencyCode == "" {
		logger.WithFields(logger.Fields{
			"OrderID":    order.ID.String(),
			"ProviderID": order.Edges.Provider.ID,
		}).Errorf("SyncPaymentOrderFulfillments.syncRefundingOrder: missing institution currency")
		return
	}

	// Use refundReference for tx_status (refund status). If missing, call /tx_refund first to get one.
	refundReference := getRefundReferenceFromOrder(order)
	if refundReference == "" {
		var err error
		refundReference, err = callTxRefundAndStore(ctx, order)
		if err != nil || refundReference == "" {
			return
		}
	}

	payload := map[string]interface{}{
		"reference": refundReference,
		"currency":  currencyCode,
	}
	data, err := utils.CallProviderWithHMAC(ctx, order.Edges.Provider.ID, "POST", "/tx_status", payload)
	if err != nil {
		logger.WithFields(logger.Fields{
			"OrderID":    order.ID.String(),
			"ProviderID": order.Edges.Provider.ID,
			"Error":      err,
		}).Errorf("SyncPaymentOrderFulfillments.syncRefundingOrder: tx_status request")
		return
	}
	dataMap, ok := data["data"].(map[string]interface{})
	if !ok {
		return
	}
	statusVal, _ := dataMap["status"].(string)
	pspVal, _ := dataMap["psp"].(string)
	txIdVal, _ := dataMap["txId"].(string)
	errorVal, _ := dataMap["error"].(string)

	switch statusVal {
	case "success":
		_, err = storage.Client.PaymentOrderFulfillment.
			Create().
			SetOrderID(order.ID).
			SetPsp(pspVal).
			SetTxID(txIdVal).
			SetValidationStatus(paymentorderfulfillment.ValidationStatusRefunded).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"OrderID":    order.ID.String(),
				"ProviderID": order.Edges.Provider.ID,
				"Error":      err,
			}).Errorf("SyncPaymentOrderFulfillments.syncRefundingOrder: create fulfillment")
			return
		}
		_, err = storage.Client.PaymentOrder.UpdateOneID(order.ID).SetStatus(paymentorder.StatusRefunded).Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"OrderID":    order.ID.String(),
				"ProviderID": order.Edges.Provider.ID,
				"Error":      err,
			}).Errorf("SyncPaymentOrderFulfillments.syncRefundingOrder: set Refunded")
			return
		}
		if order.Edges.Token != nil && order.Edges.Provider != nil {
			balanceService := balance.New()
			totalCryptoReserved := order.Amount.Add(order.SenderFee)
			if relErr := balanceService.ReleaseTokenBalance(ctx, order.Edges.Provider.ID, order.Edges.Token.ID, totalCryptoReserved, nil); relErr != nil {
				logger.WithFields(logger.Fields{
					"OrderID":    order.ID.String(),
					"ProviderID": order.Edges.Provider.ID,
					"Error":      relErr,
				}).Errorf("SyncPaymentOrderFulfillments.syncRefundingOrder: release balance")
			}
		}
		// Emit payment_order.refunded webhook (SendPaymentOrderWebhook reloads by ID and will see StatusRefunded)
		if err := utils.SendPaymentOrderWebhook(ctx, order); err != nil {
			logger.WithFields(logger.Fields{
				"OrderID":    order.ID.String(),
				"ProviderID": order.Edges.Provider.ID,
				"Error":      fmt.Sprintf("%v", err),
			}).Errorf("SyncPaymentOrderFulfillments.syncRefundingOrder: webhook")
		}
	case "failed":
		// Guard: cap retries for /tx_refund to avoid unbounded calls when provider keeps returning failed
		if getRefundAttemptCountFromOrder(order) >= maxRefundAttempts {
			logger.WithFields(logger.Fields{
				"OrderID":    order.ID.String(),
				"ProviderID": order.Edges.Provider.ID,
				"Attempts":   maxRefundAttempts,
			}).Warnf("SyncPaymentOrderFulfillments.syncRefundingOrder: max refund attempts reached, skipping callTxRefundAndStore")
			return
		}
		// Do not create failed fulfillment; call /tx_refund to retry. Validate refund account first.
		if order.AccountIdentifier == "" || order.AccountName == "" || order.Institution == "" {
			_, _ = storage.Client.PaymentOrderFulfillment.
				Create().
				SetOrderID(order.ID).
				SetPsp(pspVal).
				SetTxID(txIdVal).
				SetValidationStatus(paymentorderfulfillment.ValidationStatusFailed).
				SetValidationError(errorVal).
				Save(ctx)
			if order.Edges.Token != nil && order.Edges.Provider != nil {
				balanceService := balance.New()
				totalCryptoReserved := order.Amount.Add(order.SenderFee)
				_ = balanceService.ReleaseTokenBalance(ctx, order.Edges.Provider.ID, order.Edges.Token.ID, totalCryptoReserved, nil)
			}
			// Mark order as Fulfilled so it does not remain in Refunding indefinitely (consistent with payin-failed and handlePayinFulfillment).
			_, err = storage.Client.PaymentOrder.UpdateOneID(order.ID).SetStatus(paymentorder.StatusFulfilled).Save(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"OrderID":    order.ID.String(),
					"ProviderID": order.Edges.Provider.ID,
					"Error":      err,
				}).Errorf("SyncPaymentOrderFulfillments.syncRefundingOrder: set Fulfilled after refund failed")
			}
			return
		}

		// On success, refundReference is stored in order metadata; next sync will poll /tx_status with it.
		if _, err := callTxRefundAndStore(ctx, order); err != nil {
			return
		}
	}
}

const maxRefundAttempts = 3

// getRefundReferenceFromOrder returns order.Metadata["providerAccount"]["refundReference"] if set.
func getRefundReferenceFromOrder(order *ent.PaymentOrder) string {
	if order.Metadata == nil {
		return ""
	}
	pa, _ := order.Metadata["providerAccount"].(map[string]interface{})
	if pa == nil {
		return ""
	}
	ref, _ := pa["refundReference"].(string)
	return ref
}

// getRefundAttemptCountFromOrder returns order.Metadata["providerAccount"]["refundAttemptCount"] (1-based count of callTxRefundAndStore calls).
func getRefundAttemptCountFromOrder(order *ent.PaymentOrder) int {
	if order.Metadata == nil {
		return 0
	}
	pa, _ := order.Metadata["providerAccount"].(map[string]interface{})
	if pa == nil {
		return 0
	}
	switch v := pa["refundAttemptCount"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	default:
		return 0
	}
}

// getTxStatusReferenceForVA returns the reference to use for /tx_status when querying VA/deposit (no-fulfillments or fulfillments>0).
// Onramp and present in providerAccount: return stored "reference"; else order ID.
func getTxStatusReferenceForVA(order *ent.PaymentOrder) string {
	if order.Direction == paymentorder.DirectionOnramp && order.Metadata != nil {
		pa, _ := order.Metadata["providerAccount"].(map[string]interface{})
		if pa != nil {
			if ref, _ := pa["reference"].(string); ref != "" {
				return ref
			}
		}
	}
	return order.ID.String()
}

// callRequestAuthorization calls POST /request_authorization on the provider (same HMAC auth as /tx_status). On 200 returns nil; on 4xx/5xx/network returns error for logging; no change to order/fulfillment.
func callRequestAuthorization(ctx context.Context, order *ent.PaymentOrder, psp, txId, amountStr string) error {
	payload := map[string]interface{}{
		"orderId": order.ID.String(),
		"amount":  amountStr,
	}
	if psp != "" {
		payload["psp"] = psp
	}
	if txId != "" {
		payload["txId"] = txId
	}
	_, err := utils.CallProviderWithHMAC(ctx, order.Edges.Provider.ID, "POST", "/request_authorization", payload)
	return err
}

// callTxRefundAndStore calls POST /tx_refund via CallProviderWithHMAC; on 200 stores refundReference in order metadata and returns it.
func callTxRefundAndStore(ctx context.Context, order *ent.PaymentOrder) (refundReference string, err error) {
	currencyCode, curErr := utils.GetInstitutionCurrencyCode(ctx, order.Institution, true)
	if curErr != nil || currencyCode == "" {
		return "", fmt.Errorf("institution currency lookup failed")
	}
	fiatAmount := order.Amount.Add(order.SenderFee).Mul(order.Rate).RoundBank(0).String()
	refundAccount := map[string]interface{}{
		"accountIdentifier": order.AccountIdentifier,
		"accountName":       order.AccountName,
		"institution":       order.Institution,
	}
	if order.Metadata != nil {
		if m, ok := order.Metadata["refundAccountMetadata"].(map[string]interface{}); ok {
			refundAccount["metadata"] = m
		}
	}
	body := map[string]interface{}{
		"orderId":       order.ID.String(),
		"currency":      currencyCode,
		"amount":        fiatAmount,
		"refundAccount": refundAccount,
	}
	data, err := utils.CallProviderWithHMAC(ctx, order.Edges.Provider.ID, "POST", "/tx_refund", body)
	if err != nil {
		logger.WithFields(logger.Fields{
			"OrderID": order.ID.String(),
			"Error":   err,
		}).Errorf("SyncPaymentOrderFulfillments.syncRefundingOrder: tx_refund request")
		return "", err
	}
	dataMap, _ := data["data"].(map[string]interface{})
	if dataMap == nil {
		return "", nil
	}
	refundReference, _ = dataMap["refundReference"].(string)
	if refundReference == "" {
		return "", nil
	}

	// Store refundReference in order metadata
	orderMetadata := order.Metadata
	if orderMetadata == nil {
		orderMetadata = make(map[string]interface{})
	}
	providerAccount, _ := orderMetadata["providerAccount"].(map[string]interface{})
	if providerAccount == nil {
		providerAccount = make(map[string]interface{})
	}
	providerAccount["refundReference"] = refundReference
	attemptCount := getRefundAttemptCountFromOrder(order) + 1
	providerAccount["refundAttemptCount"] = attemptCount
	orderMetadata["providerAccount"] = providerAccount
	_, err = storage.Client.PaymentOrder.UpdateOneID(order.ID).SetMetadata(orderMetadata).Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"OrderID": order.ID.String(), "Error": err}).Errorf("SyncPaymentOrderFulfillments.syncRefundingOrder: save refundReference")
		return refundReference, err
	}
	return refundReference, nil
}
