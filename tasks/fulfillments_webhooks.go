package tasks

import (
	"context"
	"encoding/base64"
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
	"github.com/paycrest/aggregator/services/email"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/logger"
	tokenUtils "github.com/paycrest/aggregator/utils/token"
)

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
			),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithProvider(func(pq *ent.ProviderProfileQuery) {
			pq.WithAPIKey()
		}).
		WithFulfillments().
		WithProvisionBucket(func(pb *ent.ProvisionBucketQuery) {
			pb.WithCurrency()
		}).
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
			WithProvisionBucket(func(pb *ent.ProvisionBucketQuery) {
				pb.WithCurrency()
			}).
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
			if order.Status == paymentorder.StatusCancelled {
				reassignCancelledOrder(ctx, order, nil)
				continue
			}

			if order.Edges.ProvisionBucket == nil {
				logger.WithFields(logger.Fields{
					"OrderID":    order.ID.String(),
					"ProviderID": order.Edges.Provider.ID,
					"Reason":     "internal: ProvisionBucket is nil",
				}).Errorf("SyncPaymentOrderFulfillments.MissingProvisionBucket")
				continue
			}
			if order.Edges.ProvisionBucket.Edges.Currency == nil {
				logger.WithFields(logger.Fields{
					"OrderID":    order.ID.String(),
					"ProviderID": order.Edges.Provider.ID,
					"Reason":     "internal: ProvisionBucket Currency is nil",
				}).Errorf("SyncPaymentOrderFulfillments.MissingCurrency")
				continue
			}

			// Compute HMAC
			decodedSecret, err := base64.StdEncoding.DecodeString(order.Edges.Provider.Edges.APIKey.Secret)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":      fmt.Sprintf("%v", err),
					"OrderID":    order.ID.String(),
					"ProviderID": order.Edges.Provider.ID,
					"Reason":     "internal: Failed to decode provider secret",
				}).Errorf("SyncPaymentOrderFulfillments.DecodeSecret")
				continue
			}
			decryptedSecret, err := cryptoUtils.DecryptPlain(decodedSecret)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":      fmt.Sprintf("%v", err),
					"OrderID":    order.ID.String(),
					"ProviderID": order.Edges.Provider.ID,
					"Reason":     "internal: Failed to decrypt provider secret",
				}).Errorf("SyncPaymentOrderFulfillments.DecryptSecret")
				continue
			}

			payload := map[string]interface{}{
				"orderId":  order.ID.String(),
				"currency": order.Edges.ProvisionBucket.Edges.Currency.Code,
			}
			signature := tokenUtils.GenerateHMACSignature(payload, string(decryptedSecret))

			// Send POST request to the provider's node
			res, err := fastshot.NewClient(order.Edges.Provider.HostIdentifier).
				Config().SetTimeout(10*time.Second).
				Header().Add("X-Request-Signature", signature).
				Build().POST("/tx_status").
				Body().AsJSON(payload).
				Send()
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":           fmt.Sprintf("%v", err),
					"ProviderID":      order.Edges.Provider.ID,
					"PayloadOrderId":  payload["orderId"],
					"PayloadCurrency": payload["currency"],
					"Reason":          "internal: Failed to send tx_status request to provider",
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

			data, err := utils.ParseJSONResponse(res.RawResponse)
			if err != nil {
				// Instead of deleting the order, log the error and skip processing
				// The order will be retried in the next sync cycle or can be manually investigated
				logger.WithFields(logger.Fields{
					"Error":           fmt.Sprintf("%v", err),
					"ProviderID":      order.Edges.Provider.ID,
					"PayloadOrderId":  payload["orderId"],
					"PayloadCurrency": payload["currency"],
					"OrderID":         order.ID.String(),
					"OrderStatus":     order.Status.String(),
				}).Errorf("SyncPaymentOrderFulfillments: Failed to parse JSON response after getting trx status from provider, skipping order")
				continue
			}

			status := data["data"].(map[string]interface{})["status"].(string)
			psp := data["data"].(map[string]interface{})["psp"].(string)
			txId := data["data"].(map[string]interface{})["txId"].(string)

			if status == "failed" {
				_, err = storage.Client.PaymentOrderFulfillment.
					Create().
					SetOrderID(order.ID).
					SetPsp(psp).
					SetTxID(txId).
					SetValidationStatus(paymentorderfulfillment.ValidationStatusFailed).
					SetValidationError(data["data"].(map[string]interface{})["error"].(string)).
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
			if order.Edges.ProvisionBucket == nil {
				logger.WithFields(logger.Fields{
					"OrderID":    order.ID.String(),
					"ProviderID": order.Edges.Provider.ID,
					"Reason":     "internal: ProvisionBucket is nil",
				}).Errorf("SyncPaymentOrderFulfillments.MissingProvisionBucket")
				continue
			}
			if order.Edges.ProvisionBucket.Edges.Currency == nil {
				logger.WithFields(logger.Fields{
					"OrderID":    order.ID.String(),
					"ProviderID": order.Edges.Provider.ID,
					"Reason":     "internal: ProvisionBucket Currency is nil",
				}).Errorf("SyncPaymentOrderFulfillments.MissingCurrency")
				continue
			}

			for _, fulfillment := range order.Edges.Fulfillments {
				if fulfillment.ValidationStatus == paymentorderfulfillment.ValidationStatusPending {
					// Compute HMAC
					decodedSecret, err := base64.StdEncoding.DecodeString(order.Edges.Provider.Edges.APIKey.Secret)
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error":      fmt.Sprintf("%v", err),
							"OrderID":    order.ID.String(),
							"ProviderID": order.Edges.Provider.ID,
						}).Errorf("Failed to decode provider secret for pending fulfillment")
						continue
					}
					decryptedSecret, err := cryptoUtils.DecryptPlain(decodedSecret)
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error":      fmt.Sprintf("%v", err),
							"OrderID":    order.ID.String(),
							"ProviderID": order.Edges.Provider.ID,
						}).Errorf("Failed to decrypt provider secret for pending fulfillment")
						continue
					}

					payload := map[string]interface{}{
						"orderId":  order.ID.String(),
						"currency": order.Edges.ProvisionBucket.Edges.Currency.Code,
						"psp":      fulfillment.Psp,
						"txId":     fulfillment.TxID,
					}

					signature := tokenUtils.GenerateHMACSignature(payload, string(decryptedSecret))

					// Send POST request to the provider's node
					res, err := fastshot.NewClient(order.Edges.Provider.HostIdentifier).
						Config().SetTimeout(30*time.Second).
						Header().Add("X-Request-Signature", signature).
						Build().POST("/tx_status").
						Body().AsJSON(payload).
						Send()
					if err != nil {
						continue
					}

					data, err := utils.ParseJSONResponse(res.RawResponse)
					if err != nil {
						// Check if it's a 400 error and fulfillment is older than 5 minutes
						if res.RawResponse.StatusCode == 400 {
							if time.Since(fulfillment.CreatedAt) > 5*time.Minute {
								// Mark fulfillment as failed
								_, updateErr := storage.Client.PaymentOrderFulfillment.
									UpdateOneID(fulfillment.ID).
									SetValidationStatus(paymentorderfulfillment.ValidationStatusFailed).
									SetValidationError("Failed to get transaction status after 5 minutes").
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
						}

						logger.WithFields(logger.Fields{
							"Error":           fmt.Sprintf("%v", err),
							"OrderID":         order.ID.String(),
							"ProviderID":      order.Edges.Provider.ID,
							"PayloadOrderId":  payload["orderId"],
							"PayloadCurrency": payload["currency"],
							"PayloadPsp":      payload["psp"],
							"PayloadTxId":     payload["txId"],
						}).Errorf("Failed to parse JSON response after getting trx status from provider")
						continue
					}

					status := data["data"].(map[string]interface{})["status"].(string)

					if status == "failed" {
						_, err = storage.Client.PaymentOrderFulfillment.
							UpdateOneID(fulfillment.ID).
							SetTxID(fulfillment.TxID).
							SetValidationStatus(paymentorderfulfillment.ValidationStatusFailed).
							SetValidationError(data["data"].(map[string]interface{})["error"].(string)).
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

					} else if status == "success" {
						_, err = storage.Client.PaymentOrderFulfillment.
							UpdateOneID(fulfillment.ID).
							SetTxID(fulfillment.TxID).
							SetValidationStatus(paymentorderfulfillment.ValidationStatusSuccess).
							Save(ctx)
						if err != nil {
							continue
						}

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

				} else if fulfillment.ValidationStatus == paymentorderfulfillment.ValidationStatusFailed {
					reassignCancelledOrder(ctx, order, fulfillment)
					continue

				} else if fulfillment.ValidationStatus == paymentorderfulfillment.ValidationStatusSuccess {
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
	// Use context with timeout to prevent indefinite hanging
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Fetch failed webhook notifications that are due for retry
	attempts, err := storage.Client.WebhookRetryAttempt.
		Query().
		Where(
			webhookretryattempt.StatusEQ(webhookretryattempt.StatusFailed),
			webhookretryattempt.NextRetryTimeLTE(time.Now()),
		).
		All(ctx)
	if err != nil {
		return fmt.Errorf("RetryFailedWebhookNotifications: %w", err)
	}

	baseDelay := 2 * time.Minute
	maxCumulativeTime := 24 * time.Hour

	for _, attempt := range attempts {
		// Send the webhook notification
		body, err := fastshot.NewClient(attempt.WebhookURL).
			Config().SetTimeout(30*time.Second).
			Header().Add("X-Paycrest-Signature", attempt.Signature).
			Build().POST("").
			Body().AsJSON(attempt.Payload).
			Send()

		if err != nil || (body.StatusCode() >= 205) {
			// Webhook notification failed
			// Update attempt with next retry time
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
				uid, err := uuid.Parse(attempt.Payload["data"].(map[string]interface{})["senderId"].(string))
				if err != nil {
					return fmt.Errorf("RetryFailedWebhookNotifications.FailedExtraction: %w", err)
				}
				profile, err := storage.Client.SenderProfile.
					Query().
					Where(
						senderprofile.IDEQ(uid),
					).
					WithUser().
					Only(ctx)
				if err != nil {
					return fmt.Errorf("RetryFailedWebhookNotifications.CouldNotFetchProfile: %w", err)
				}

				emailService := email.NewEmailServiceWithProviders()
				_, err = emailService.SendWebhookFailureEmail(ctx, profile.Edges.User.Email, profile.Edges.User.FirstName)

				if err != nil {
					return fmt.Errorf("RetryFailedWebhookNotifications.SendWebhookFailureEmail: %w", err)
				}
			}

			_, err := attemptUpdate.Save(ctx)
			if err != nil {
				return fmt.Errorf("RetryFailedWebhookNotifications: %w", err)
			}

			continue
		}

		// Webhook notification was successful
		_, err = attempt.Update().
			SetStatus(webhookretryattempt.StatusSuccess).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("RetryFailedWebhookNotifications: %w", err)
		}
	}

	return nil
}
