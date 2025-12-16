package tasks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"strings"
	"sync"
	"time"

	"entgo.io/ent/dialect/sql"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/go-co-op/gocron"
	"github.com/google/uuid"
	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/lockorderfulfillment"
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/paymentorderrecipient"
	"github.com/paycrest/aggregator/ent/providercurrencies"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/receiveaddress"
	"github.com/paycrest/aggregator/ent/senderprofile"
	tokenent "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/transactionlog"
	"github.com/paycrest/aggregator/ent/webhookretryattempt"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/services/contracts"
	"github.com/paycrest/aggregator/services/email"
	"github.com/paycrest/aggregator/services/indexer"
	orderService "github.com/paycrest/aggregator/services/order"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/logger"
	tokenUtils "github.com/paycrest/aggregator/utils/token"
	"github.com/redis/go-redis/v9"
	"github.com/shopspring/decimal"
)

var orderConf = config.OrderConfig()
var serverConf = config.ServerConfig()

// Indexing coordination: track addresses currently being indexed to prevent duplicate work
var (
	indexingAddresses sync.Map // address_chainID -> time.Time (when indexing started)
	recentlyIndexed   sync.Map // address_chainID -> time.Time (when last indexed)

	// Minimum time between indexing same address (3 minutes)
	indexingCooldown = 3 * time.Minute

	// Maximum time an address can be "in progress" before considering it stale (5 minutes)
	indexingTimeout = 5 * time.Minute

	// Cleanup interval for stale entries in indexing maps
	indexingCleanupInterval = 10 * time.Minute
)

// cleanupIndexingMaps removes stale entries from indexing coordination maps
func cleanupIndexingMaps() {
	now := time.Now()
	var cleanedIndexing, cleanedRecent int

	// Clean up stale "in progress" entries
	indexingAddresses.Range(func(key, value interface{}) bool {
		if startTime, ok := value.(time.Time); ok {
			if now.Sub(startTime) > indexingTimeout {
				indexingAddresses.Delete(key)
				cleanedIndexing++
			}
		}
		return true
	})

	// Clean up old "recently indexed" entries (older than cooldown + 1 hour buffer)
	recentlyIndexed.Range(func(key, value interface{}) bool {
		if lastIndexed, ok := value.(time.Time); ok {
			if now.Sub(lastIndexed) > indexingCooldown+1*time.Hour {
				recentlyIndexed.Delete(key)
				cleanedRecent++
			}
		}
		return true
	})

	if cleanedIndexing > 0 || cleanedRecent > 0 {
		logger.WithFields(logger.Fields{
			"CleanedIndexing": cleanedIndexing,
			"CleanedRecent":   cleanedRecent,
		}).Debugf("Cleaned up stale indexing map entries")
	}
}

// RetryStaleUserOperations retries stale user operations
// TODO: Fetch failed orders from a separate db table and process them
func RetryStaleUserOperations() error {
	ctx := context.Background()

	var wg sync.WaitGroup

	// Create initiated orders
	orders, err := storage.Client.PaymentOrder.
		Query().
		Where(func(s *sql.Selector) {
			ra := sql.Table(receiveaddress.Table)
			s.LeftJoin(ra).On(s.C(paymentorder.FieldReceiveAddressText), ra.C(receiveaddress.FieldAddress)).
				Where(sql.And(
					sql.EQ(s.C(paymentorder.FieldStatus), paymentorder.StatusInitiated),
					sql.EQ(ra.C(receiveaddress.FieldStatus), receiveaddress.StatusUsed),
					sql.IsNull(s.C(paymentorder.FieldGatewayID)),
				))
		}).
		Where(
			paymentorder.Or(
				paymentorder.UpdatedAtGTE(time.Now().Add(-5*time.Minute)),
				paymentorder.HasRecipientWith(
					paymentorderrecipient.MemoHasPrefix("P#P"),
				),
			)).
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
					SetStatus(paymentorder.StatusInitiated).
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

	// Settle order process
	lockOrders, err := storage.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.StatusEQ(lockpaymentorder.StatusValidated),
			lockpaymentorder.HasFulfillmentsWith(
				lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusSuccess),
			),
			lockpaymentorder.UpdatedAtLT(time.Now().Add(-5*time.Minute)),
			lockpaymentorder.UpdatedAtGTE(time.Now().Add(-15*time.Minute)),
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

	lockOrders, err = storage.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.GatewayIDNEQ(""),
			lockpaymentorder.UpdatedAtGTE(time.Now().Add(-5*time.Minute)),
			lockpaymentorder.StatusNEQ(lockpaymentorder.StatusValidated),
			lockpaymentorder.StatusNEQ(lockpaymentorder.StatusSettled),
			lockpaymentorder.StatusNEQ(lockpaymentorder.StatusRefunded),
			lockpaymentorder.Or(
				// Regular orders with normal refund timeout
				lockpaymentorder.And(
					lockpaymentorder.OrderTypeEQ(lockpaymentorder.OrderTypeRegular),
					lockpaymentorder.Or(
						lockpaymentorder.StatusEQ(lockpaymentorder.StatusPending),
						lockpaymentorder.StatusEQ(lockpaymentorder.StatusCancelled),
					),
					lockpaymentorder.CreatedAtLTE(time.Now().Add(-regularRefundTimeout)),
					lockpaymentorder.Or(
						lockpaymentorder.Not(lockpaymentorder.HasFulfillments()),
						lockpaymentorder.HasFulfillmentsWith(
							lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusFailed),
							lockorderfulfillment.Not(lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusSuccess)),
							lockorderfulfillment.Not(lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusPending)),
						),
					),
				),
				// OTC orders with 15x refund timeout
				lockpaymentorder.And(
					lockpaymentorder.OrderTypeEQ(lockpaymentorder.OrderTypeOtc),
					lockpaymentorder.Or(
						lockpaymentorder.StatusEQ(lockpaymentorder.StatusPending),
						lockpaymentorder.StatusEQ(lockpaymentorder.StatusCancelled),
					),
					lockpaymentorder.CreatedAtLTE(time.Now().Add(-otcRefundTimeout)),
					lockpaymentorder.Or(
						lockpaymentorder.Not(lockpaymentorder.HasFulfillments()),
						lockpaymentorder.HasFulfillmentsWith(
							lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusFailed),
							lockorderfulfillment.Not(lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusSuccess)),
							lockorderfulfillment.Not(lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusPending)),
						),
					),
				),
				lockpaymentorder.And(
					lockpaymentorder.HasProviderWith(
						providerprofile.VisibilityModeEQ(providerprofile.VisibilityModePrivate),
					),
					lockpaymentorder.StatusEQ(lockpaymentorder.StatusFulfilled),
					lockpaymentorder.HasFulfillmentsWith(
						lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusFailed),
						lockorderfulfillment.Not(lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusSuccess)),
						lockorderfulfillment.Not(lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusPending)),
					),
				),
			),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithFulfillments().
		WithProvider().
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
			} else {
				service = orderService.NewOrderEVM()
			}

			if order.OrderType == lockpaymentorder.OrderTypeRegular && order.Status == lockpaymentorder.StatusPending && order.Edges.Provider != nil && len(order.Edges.Fulfillments) == 0 {
				// Check if there's an active order request in Redis
				exists, err := hasActiveOrderRequest(ctx, order.ID, "RetryStaleUserOperations")
				if err != nil {
					// If we can't check Redis, skip refund
					continue
				}
				if exists {
					// Active order request exists, don't refund (skip)
					continue
				}
				// If order_request doesn't exist, proceed with refund check
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

	// // Retry refunded linked address deposits
	// orders, err = storage.Client.PaymentOrder.
	// 	Query().
	// 	Where(
	// 		paymentorder.StatusEQ(paymentorder.StatusRefunded),
	// 		paymentorder.HasLinkedAddress(),
	// 	).
	// 	WithToken(func(tq *ent.TokenQuery) {
	// 		tq.WithNetwork()
	// 	}).
	// 	All(ctx)
	// if err != nil {
	// 	return fmt.Errorf("RetryStaleUserOperations: %w", err)
	// }

	// wg.Add(1)
	// go func(ctx context.Context) {
	// 	defer wg.Done()
	// 	for _, order := range orders {
	// 		service := orderService.NewOrderEVM()
	// 		err = service.CreateOrder(ctx, order.ID)
	// 		if err != nil {
	// 			logger.WithFields(logger.Fields{
	// 				"Error":             fmt.Sprintf("%v", err),
	// 				"OrderID":           order.ID.String(),
	// 				"Amount":            order.Amount,
	// 				"GatewayID":         order.GatewayID,
	// 				"NetworkIdentifier": order.Edges.Token.Edges.Network.Identifier,
	// 			}).Errorf("RetryStaleUserOperations.RetryLinkedAddress")
	// 		}
	// 	}
	// }(ctx)

	return nil
}

// TaskIndexBlockchainEvents indexes transfer events for all enabled tokens
func TaskIndexBlockchainEvents() error {
	ctx := context.Background()

	// Fetch networks
	isTestnet := false
	if serverConf.Environment != "production" && serverConf.Environment != "staging" {
		isTestnet = true
	}
	networks, err := storage.Client.Network.
		Query().
		Where(
			networkent.IsTestnetEQ(isTestnet),
			// networkent.Or(
			// 	networkent.IdentifierEQ("bnb-smart-chain"),
			// 	networkent.IdentifierEQ("lisk"),
			// ),
			networkent.Not(networkent.IdentifierHasPrefix("tron")),
		).
		All(ctx)
	if err != nil {
		return fmt.Errorf("TaskIndexBlockchainEvents.fetchNetworks: %w", err)
	}

	// Process each network in parallel
	for _, network := range networks {
		go func(network *ent.Network) {
			// Create a new context for this network's operations
			ctx := context.Background()
			var indexerInstance types.Indexer

			if strings.HasPrefix(network.Identifier, "tron") {
				indexerInstance = indexer.NewIndexerTron()
				_, _ = indexerInstance.IndexGateway(ctx, network, network.GatewayContractAddress, 0, 0, "")
			} else {
				indexerInstance, err = indexer.NewIndexerEVM()
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":             fmt.Sprintf("%v", err),
						"NetworkIdentifier": network.Identifier,
					}).Errorf("TaskIndexBlockchainEvents.createIndexer")
					return
				}
				_, _ = indexerInstance.IndexGateway(ctx, network, network.GatewayContractAddress, 0, 0, "")

				// Find payment orders with missed transfers
				// Prioritize recent orders (created in last 30 minutes) - most likely to have transfers
				recentCutoff := time.Now().Add(-30 * time.Minute)
				paymentOrders, err := storage.Client.PaymentOrder.
					Query().
					Where(
						paymentorder.StatusEQ(paymentorder.StatusInitiated),
						paymentorder.TxHashIsNil(),
						paymentorder.BlockNumberEQ(0),
						paymentorder.AmountPaidEQ(decimal.Zero),
						paymentorder.FromAddressIsNil(),
						paymentorder.CreatedAtGTE(recentCutoff), // Focus on recent orders
						paymentorder.HasReceiveAddressWith(
							receiveaddress.StatusEQ(receiveaddress.StatusUnused),
						),
						paymentorder.HasTokenWith(
							tokenent.HasNetworkWith(
								networkent.IDEQ(network.ID),
							),
						),
					).
					WithToken(func(tq *ent.TokenQuery) {
						tq.WithNetwork()
					}).
					WithReceiveAddress().
					Order(ent.Desc(paymentorder.FieldCreatedAt)).
					Limit(50). // Limit to 50 most recent to avoid processing too many at once
					All(ctx)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":             fmt.Sprintf("%v", err),
						"NetworkIdentifier": network.Identifier,
					}).Errorf("TaskIndexBlockchainEvents.fetchPaymentOrders")
					return
				}

				// Index Transfer events in parallel using goroutines
				if len(paymentOrders) > 0 {
					var wg sync.WaitGroup

					for _, order := range paymentOrders {
						if order.Edges.ReceiveAddress == nil {
							continue
						}

						address := order.Edges.ReceiveAddress.Address
						chainID := network.ChainID
						indexKey := fmt.Sprintf("%s_%d", address, chainID)

						// Check if address is currently being indexed by another task
						if _, indexing := indexingAddresses.Load(indexKey); indexing {
							// Check if indexing started too long ago (stale)
							if startTime, ok := indexingAddresses.Load(indexKey); ok {
								if time.Since(startTime.(time.Time)) > indexingTimeout {
									indexingAddresses.Delete(indexKey) // Remove stale entry
								} else {
									continue // Skip, already being indexed
								}
							}
						}

						// Check if address was recently indexed (within cooldown period)
						if lastIndexed, indexed := recentlyIndexed.Load(indexKey); indexed {
							if time.Since(lastIndexed.(time.Time)) < indexingCooldown {
								continue // Skip, recently indexed
							}
						}

						// Mark as being indexed
						indexingAddresses.Store(indexKey, time.Now())

						wg.Add(1)
						go func(order *ent.PaymentOrder, addr string, key string) {
							defer wg.Done()
							defer indexingAddresses.Delete(key) // Remove from indexing map when done

							// Check circuit breaker before indexing (if Etherscan service is available)
							// Note: This is a best-effort check, actual circuit breaker is in etherscan service

							_, err := indexerInstance.IndexReceiveAddress(ctx, order.Edges.Token, addr, 0, 0, "")
							if err != nil {
								logger.WithFields(logger.Fields{
									"Error":   fmt.Sprintf("%v", err),
									"OrderID": order.ID.String(),
								}).Errorf("TaskIndexBlockchainEvents.IndexReceiveAddress")
							} else {
								// Mark as recently indexed on success
								recentlyIndexed.Store(key, time.Now())
							}
						}(order, address, indexKey)
					}

					// Wait for all transfer indexing to complete
					wg.Wait()
				}
			}
		}(network)
	}
	return nil
}

// GetTronLatestBlock fetches the latest block (timestamp in milliseconds) for Tron
func GetTronLatestBlock(endpoint string) (int64, error) {
	res, err := fastshot.NewClient(endpoint).
		Config().SetTimeout(15 * time.Second).
		Build().POST("/wallet/getblockbylatestnum").
		Body().AsJSON(map[string]interface{}{
		"num": 1,
	}).
		Send()
	if err != nil {
		return 0, fmt.Errorf("failed to get latest block: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return 0, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return int64(data["block"].([]interface{})[0].(map[string]interface{})["block_header"].(map[string]interface{})["raw_data"].(map[string]interface{})["timestamp"].(float64)), nil
}

// hasActiveOrderRequest checks if there's an active order_request entry in Redis for the given order ID.
// Returns (exists bool, err error). If err != nil, exists will be false.
func hasActiveOrderRequest(ctx context.Context, orderID uuid.UUID, logPrefix string) (bool, error) {
	orderKey := fmt.Sprintf("order_request_%s", orderID)
	exists, err := storage.RedisClient.Exists(ctx, orderKey).Result()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"OrderID":  orderID.String(),
			"OrderKey": orderKey,
		}).Errorf("%s: Failed to check order_request Redis entry", logPrefix)
		return false, err
	}
	return exists > 0, nil
}

// reassignCancelledOrder reassigns cancelled orders to providers
func reassignCancelledOrder(ctx context.Context, order *ent.LockPaymentOrder, fulfillment *ent.LockOrderFulfillment) {
	if order.Edges.Provider.VisibilityMode != providerprofile.VisibilityModePrivate && order.CancellationCount < orderConf.RefundCancellationCount {
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

		_, err = storage.Client.LockPaymentOrder.
			UpdateOneID(order.ID).
			ClearProvider().
			SetStatus(lockpaymentorder.StatusPending).
			Save(ctx)
		if err != nil {
			return
		}

		if fulfillment != nil {
			err = storage.Client.LockOrderFulfillment.
				DeleteOneID(fulfillment.ID).
				Exec(ctx)
			if err != nil {
				return
			}
		}

		// Reassign the order to a provider
		lockPaymentOrder := types.LockPaymentOrderFields{
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

		err = services.NewPriorityQueueService().AssignLockPaymentOrder(ctx, lockPaymentOrder)
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

// SyncLockOrderFulfillments syncs lock order fulfillments
// Only processes regular orders
// TODO: refactor this to process OTC orders as well when OTC fulfillment validation is automated
func SyncLockOrderFulfillments() {
	// ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	// defer cancel()
	ctx := context.Background()

	updatePaymentOrderValidated := func(ctx context.Context, lockOrder *ent.LockPaymentOrder) {
		if lockOrder == nil || lockOrder.MessageHash == "" {
			return
		}

		paymentOrder, err := storage.Client.PaymentOrder.
			Query().
			Where(paymentorder.MessageHashEQ(lockOrder.MessageHash)).
			WithSenderProfile().
			WithRecipient().
			WithToken(func(tq *ent.TokenQuery) {
				tq.WithNetwork()
			}).
			Only(ctx)
		if err != nil {
			if !ent.IsNotFound(err) {
				logger.WithFields(logger.Fields{
					"Error":       fmt.Sprintf("%v", err),
					"MessageHash": lockOrder.MessageHash,
					"OrderID":     lockOrder.ID,
				}).Errorf("SyncLockOrderFulfillments.UpdatePaymentOrderValidated.query")
			}
			return
		}

		_, err = storage.Client.PaymentOrder.
			Update().
			Where(paymentorder.IDEQ(paymentOrder.ID)).
			SetStatus(paymentorder.StatusValidated).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":       fmt.Sprintf("%v", err),
				"MessageHash": lockOrder.MessageHash,
				"OrderID":     lockOrder.ID,
				"PaymentID":   paymentOrder.ID,
			}).Errorf("SyncLockOrderFulfillments.UpdatePaymentOrderValidated.update")
			return
		}

		paymentOrder.Status = paymentorder.StatusValidated
		if err := utils.SendPaymentOrderWebhook(ctx, paymentOrder); err != nil {
			logger.WithFields(logger.Fields{
				"Error":       fmt.Sprintf("%v", err),
				"MessageHash": lockOrder.MessageHash,
				"OrderID":     lockOrder.ID,
				"PaymentID":   paymentOrder.ID,
			}).Errorf("SyncLockOrderFulfillments.UpdatePaymentOrderValidated.webhook")
		}
	}

	// Query unvalidated lock orders (regular orders only - exclude OTC)
	lockOrders, err := storage.Client.LockPaymentOrder.
		Query().
		Where(
			// case 1: regular, pending, created older than 2 minutes, no fulfillments
			lockpaymentorder.OrderTypeEQ(lockpaymentorder.OrderTypeRegular), // Only regular orders
			lockpaymentorder.Or(
				lockpaymentorder.And(
					lockpaymentorder.StatusEQ(lockpaymentorder.StatusFulfilled),
					lockpaymentorder.Or(
						lockpaymentorder.HasFulfillmentsWith(
							lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusFailed),
							lockorderfulfillment.Not(lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusSuccess)),
							lockorderfulfillment.Not(lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusPending)),
						),
						lockpaymentorder.HasFulfillmentsWith(
							lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusPending),
							lockorderfulfillment.UpdatedAtLTE(time.Now().Add(-orderConf.OrderFulfillmentValidity)),
						),
						lockpaymentorder.HasFulfillmentsWith(
							lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusSuccess),
						),
					),
				),
				lockpaymentorder.And(
					lockpaymentorder.Or(
						lockpaymentorder.StatusEQ(lockpaymentorder.StatusCancelled),
						lockpaymentorder.StatusEQ(lockpaymentorder.StatusPending),
					),
					lockpaymentorder.Or(
						lockpaymentorder.HasFulfillmentsWith(
							lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusPending),
						),
						lockpaymentorder.Not(lockpaymentorder.HasFulfillments()),
					),
				),
				lockpaymentorder.And(
					lockpaymentorder.StatusEQ(lockpaymentorder.StatusProcessing),
					lockpaymentorder.UpdatedAtLTE(time.Now().Add(-30*time.Second)),
					lockpaymentorder.Not(lockpaymentorder.HasFulfillments()),
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

	for _, order := range lockOrders {
		if order.Edges.Provider == nil {
			continue
		}
		if len(order.Edges.Fulfillments) == 0 {
			if order.Status == lockpaymentorder.StatusCancelled {
				reassignCancelledOrder(ctx, order, nil)
				continue
			}

			// Check if there's an active order request before querying tx_status
			if order.Status == lockpaymentorder.StatusPending {
				exists, err := hasActiveOrderRequest(ctx, order.ID, "SyncLockOrderFulfillments")
				if err != nil {
					continue
				}
				if !exists {
					// No active order request, skip tx_status check
					continue
				}
			}

			// Compute HMAC
			decodedSecret, err := base64.StdEncoding.DecodeString(order.Edges.Provider.Edges.APIKey.Secret)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":      fmt.Sprintf("%v", err),
					"OrderID":    order.ID.String(),
					"ProviderID": order.Edges.Provider.ID,
					"Reason":     "internal: Failed to decode provider secret",
				}).Errorf("SyncLockOrderFulfillments.DecodeSecret")
				continue
			}
			decryptedSecret, err := cryptoUtils.DecryptPlain(decodedSecret)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":      fmt.Sprintf("%v", err),
					"OrderID":    order.ID.String(),
					"ProviderID": order.Edges.Provider.ID,
					"Reason":     "internal: Failed to decrypt provider secret",
				}).Errorf("SyncLockOrderFulfillments.DecryptSecret")
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
				}).Errorf("SyncLockOrderFulfillments.SendTxStatusRequest")

				// Set status to pending on 400 error
				if strings.Contains(fmt.Sprintf("%v", err), "400") {
					_, updateErr := storage.Client.LockPaymentOrder.
						UpdateOneID(order.ID).
						SetStatus(lockpaymentorder.StatusPending).
						Save(ctx)
					if updateErr != nil {
						logger.WithFields(logger.Fields{
							"Error":      updateErr,
							"OrderID":    order.ID.String(),
							"ProviderID": order.Edges.Provider.ID,
							"Reason":     "internal: Failed to update order status",
						}).Errorf("SyncLockOrderFulfillments.UpdateStatus")
					}
				}
				continue
			}

			data, err := utils.ParseJSONResponse(res.RawResponse)
			if err != nil {
				if order.Status == lockpaymentorder.StatusProcessing && order.UpdatedAt.Add(orderConf.OrderFulfillmentValidity*2).Before(time.Now()) {
					logger.WithFields(logger.Fields{
						"Error":           fmt.Sprintf("%v", err),
						"ProviderID":      order.Edges.Provider.ID,
						"PayloadOrderId":  payload["orderId"],
						"PayloadCurrency": payload["currency"],
					}).Errorf("Failed to parse JSON response after getting trx status from provider")
					// delete lock order to trigger re-indexing
					err := storage.Client.LockPaymentOrder.
						DeleteOneID(order.ID).
						Exec(ctx)
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error":      fmt.Sprintf("%v", err),
							"OrderID":    order.ID.String(),
							"ProviderID": order.Edges.Provider.ID,
						}).Errorf("Failed to delete order after failing to parse JSON response when getting trx status from provider")
					}
					continue
				}
				continue
			}

			status := data["data"].(map[string]interface{})["status"].(string)
			psp := data["data"].(map[string]interface{})["psp"].(string)
			txId := data["data"].(map[string]interface{})["txId"].(string)

			if status == "failed" {
				_, err = storage.Client.LockOrderFulfillment.
					Create().
					SetOrderID(order.ID).
					SetPsp(psp).
					SetTxID(txId).
					SetValidationStatus(lockorderfulfillment.ValidationStatusFailed).
					SetValidationError(data["data"].(map[string]interface{})["error"].(string)).
					Save(ctx)
				if err != nil {
					continue
				}

				_, err = storage.Client.LockPaymentOrder.
					UpdateOneID(order.ID).
					SetStatus(lockpaymentorder.StatusFulfilled).
					Save(ctx)
				if err != nil {
					continue
				}

			} else if status == "success" {
				_, err = storage.Client.LockOrderFulfillment.
					Create().
					SetOrderID(order.ID).
					SetPsp(psp).
					SetTxID(txId).
					SetValidationStatus(lockorderfulfillment.ValidationStatusSuccess).
					Save(ctx)
				if err != nil {
					continue
				}

				transactionLog, err := storage.Client.TransactionLog.
					Create().
					SetStatus(transactionlog.StatusOrderValidated).
					SetNetwork(order.Edges.Token.Edges.Network.Identifier).
					SetMetadata(map[string]interface{}{
						"TransactionID": txId,
						"PSP":           psp,
					}).
					Save(ctx)
				if err != nil {
					continue
				}

				_, err = storage.Client.LockPaymentOrder.
					UpdateOneID(order.ID).
					SetStatus(lockpaymentorder.StatusValidated).
					AddTransactions(transactionLog).
					Save(ctx)
				if err == nil {
					updatePaymentOrderValidated(ctx, order)
				} else {
					continue
				}
			}
		} else {
			for _, fulfillment := range order.Edges.Fulfillments {
				if fulfillment.ValidationStatus == lockorderfulfillment.ValidationStatusPending {
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
								_, updateErr := storage.Client.LockOrderFulfillment.
									UpdateOneID(fulfillment.ID).
									SetValidationStatus(lockorderfulfillment.ValidationStatusFailed).
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
						_, err = storage.Client.LockOrderFulfillment.
							UpdateOneID(fulfillment.ID).
							SetTxID(fulfillment.TxID).
							SetValidationStatus(lockorderfulfillment.ValidationStatusFailed).
							SetValidationError(data["data"].(map[string]interface{})["error"].(string)).
							Save(ctx)
						if err != nil {
							continue
						}

						_, err = order.Update().
							SetStatus(lockpaymentorder.StatusFulfilled).
							Save(ctx)
						if err != nil {
							continue
						}

					} else if status == "success" {
						_, err = storage.Client.LockOrderFulfillment.
							UpdateOneID(fulfillment.ID).
							SetTxID(fulfillment.TxID).
							SetValidationStatus(lockorderfulfillment.ValidationStatusSuccess).
							Save(ctx)
						if err != nil {
							continue
						}

						transactionLog, err := storage.Client.TransactionLog.
							Create().
							SetStatus(transactionlog.StatusOrderValidated).
							SetNetwork(order.Edges.Token.Edges.Network.Identifier).
							SetMetadata(map[string]interface{}{
								"TransactionID": fulfillment.TxID,
								"PSP":           fulfillment.Psp,
							}).
							Save(ctx)
						if err != nil {
							continue
						}

						_, err = storage.Client.LockPaymentOrder.
							UpdateOneID(order.ID).
							SetStatus(lockpaymentorder.StatusValidated).
							AddTransactions(transactionLog).
							Save(ctx)
						if err == nil {
							updatePaymentOrderValidated(ctx, order)
						} else {
							continue
						}
					}

				} else if fulfillment.ValidationStatus == lockorderfulfillment.ValidationStatusFailed {
					reassignCancelledOrder(ctx, order, fulfillment)
					continue

				} else if fulfillment.ValidationStatus == lockorderfulfillment.ValidationStatusSuccess {
					transactionLog, err := storage.Client.TransactionLog.
						Create().
						SetStatus(transactionlog.StatusOrderValidated).
						SetNetwork(order.Edges.Token.Edges.Network.Identifier).
						SetMetadata(map[string]interface{}{
							"TransactionID": fulfillment.TxID,
							"PSP":           fulfillment.Psp,
						}).
						Save(ctx)
					if err != nil {
						continue
					}

					_, err = storage.Client.LockPaymentOrder.
						UpdateOneID(order.ID).
						SetStatus(lockpaymentorder.StatusValidated).
						AddTransactions(transactionLog).
						Save(ctx)
					if err == nil {
						updatePaymentOrderValidated(ctx, order)
					} else {
						continue
					}
				}
			}
		}
	}
}

// ReassignStaleOrderRequest reassigns expired order requests to providers
func ReassignStaleOrderRequest(ctx context.Context, orderRequestChan <-chan *redis.Message) {
	for msg := range orderRequestChan {
		key := strings.Split(msg.Payload, "_")
		orderID := key[len(key)-1]

		orderUUID, err := uuid.Parse(orderID)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"OrderID": orderID,
			}).Errorf("ReassignStaleOrderRequest: Failed to parse order ID")
			continue
		}

		// Get the order from the database
		order, err := storage.Client.LockPaymentOrder.
			Query().
			Where(
				lockpaymentorder.IDEQ(orderUUID),
			).
			WithProvisionBucket().
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

		// Extract provider ID from relation if available
		providerID := ""
		if order.Edges.Provider != nil {
			providerID = order.Edges.Provider.ID
		}

		// Build order fields for reassignment
		orderFields := types.LockPaymentOrderFields{
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
		err = services.NewPriorityQueueService().AssignLockPaymentOrder(ctx, orderFields)
		if err != nil {
			// logger.Errorf("ReassignStaleOrderRequest.AssignLockPaymentOrder: %v", err)
			logger.WithFields(logger.Fields{
				"Error":     fmt.Sprintf("%v", err),
				"OrderID":   order.ID.String(),
				"UUID":      orderUUID,
				"GatewayID": order.GatewayID,
			}).Errorf("ReassignStaleOrderRequest: Failed to assign order to provider")
		}
	}
}

// func FixDatabaseMishap() error {
// 	ctx := context.Background()
// 	network, err := storage.Client.Network.
// 		Query().
// 		Where(networkent.ChainIDEQ(1135)).
// 		Only(ctx)
// 	if err != nil {
// 		return fmt.Errorf("FixDatabaseMishap.fetchNetworks: %w", err)
// 	}

// 	indexerInstance := indexer.NewIndexerEVM()

// 	_ = indexerInstance.IndexOrderCreated(ctx, network, 18052684, 18052684, "")
// 	_ = indexerInstance.IndexOrderCreated(ctx, network, 18056857, 18056857, "")

// 	return nil
// }

// HandleReceiveAddressValidity handles receive address validity
func HandleReceiveAddressValidity() error {
	ctx := context.Background()

	// Fetch expired receive addresses that are due for validity check
	addresses, err := storage.Client.ReceiveAddress.
		Query().
		Where(
			receiveaddress.ValidUntilLTE(time.Now()),
			receiveaddress.Or(
				receiveaddress.StatusNEQ(receiveaddress.StatusUsed),
				receiveaddress.And(
					receiveaddress.StatusEQ(receiveaddress.StatusUsed),
					receiveaddress.HasPaymentOrderWith(
						paymentorder.StatusEQ(paymentorder.StatusInitiated),
					),
				),
			),
			receiveaddress.HasPaymentOrder(),
		).
		WithPaymentOrder(func(po *ent.PaymentOrderQuery) {
			po.WithToken(func(tq *ent.TokenQuery) {
				tq.WithNetwork()
			})
			po.WithRecipient()
			po.WithSenderProfile()
		}).
		All(ctx)
	if err != nil {
		return fmt.Errorf("HandleReceiveAddressValidity: %w", err)
	}

	for _, address := range addresses {
		err := common.HandleReceiveAddressValidity(ctx, address, address.Edges.PaymentOrder)
		if err != nil {
			continue
		}
	}

	return nil
}

// RefundsInterval defines the interval for processing expired orders refunds
const RefundsInterval = 30

// ProcessExpiredOrdersRefunds processes expired orders and transfers any remaining funds to refund addresses
func ProcessExpiredOrdersRefunds() error {
	ctx := context.Background()

	// Get all payment orders that are expired and initiated in the last RefundsInterval
	expiredOrders, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.StatusEQ(paymentorder.StatusExpired),
			paymentorder.CreatedAtGTE(time.Now().Add(-(RefundsInterval * time.Minute))), // Should match jobs retrying expired orders refunds
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithReceiveAddress().
		All(ctx)
	if err != nil {
		return fmt.Errorf("ProcessExpiredOrdersRefunds.fetchExpiredOrders: %w", err)
	}

	if len(expiredOrders) == 0 {
		return nil
	}

	engineService := services.NewEngineService()

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5)

	for _, order := range expiredOrders {
		wg.Add(1)
		go func(order *ent.PaymentOrder) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if order.Edges.ReceiveAddress == nil {
				return
			}

			receiveAddress := order.Edges.ReceiveAddress.Address
			tokenContract := order.Edges.Token.ContractAddress
			network := order.Edges.Token.Edges.Network
			rpcEndpoint := network.RPCEndpoint
			chainID := network.ChainID

			// Skip if no return address (nowhere to refund to)
			if order.ReturnAddress == "" {
				return
			}

			// Check balance of token at receive address
			balance, err := getTokenBalance(rpcEndpoint, tokenContract, receiveAddress)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":             err.Error(),
					"OrderID":           order.ID.String(),
					"ReceiveAddress":    receiveAddress,
					"TokenContract":     tokenContract,
					"NetworkIdentifier": network.Identifier,
				}).Errorf("Failed to check token balance for receive address %s", receiveAddress)
				return
			}

			if balance.Cmp(big.NewInt(0)) == 0 {
				return
			}

			// Prepare transfer method call
			method := "function transfer(address recipient, uint256 amount) public returns (bool)"
			params := []interface{}{
				order.ReturnAddress, // recipient address
				balance.String(),    // amount to transfer
			}

			// Send the transfer transaction
			_, err = engineService.SendContractCall(
				ctx,
				chainID,
				receiveAddress,
				tokenContract,
				method,
				params,
			)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":             err.Error(),
					"OrderID":           order.ID.String(),
					"ReceiveAddress":    receiveAddress,
					"ReturnAddress":     order.ReturnAddress,
					"Balance":           balance.String(),
					"TokenContract":     tokenContract,
					"NetworkIdentifier": network.Identifier,
				}).Errorf("Failed to send refund transfer transaction")
				return
			}

		}(order)
	}

	wg.Wait()
	return nil
}

func getTokenBalance(rpcEndpoint string, tokenContractAddress string, walletAddress string) (*big.Int, error) {
	client, err := ethclient.Dial(rpcEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to create RPC client: %w", err)
	}
	defer client.Close()

	tokenContract, err := contracts.NewERC20Token(ethcommon.HexToAddress(tokenContractAddress), client)
	if err != nil {
		return nil, fmt.Errorf("failed to create token contract instance: %w", err)
	}

	balance, err := tokenContract.BalanceOf(nil, ethcommon.HexToAddress(walletAddress))
	if err != nil {
		return nil, fmt.Errorf("failed to get token balance: %w", err)
	}

	return balance, nil
}

// SubscribeToRedisKeyspaceEvents subscribes to redis keyspace events according to redis.conf settings
func SubscribeToRedisKeyspaceEvents() {
	// ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	// defer cancel()
	ctx := context.Background()

	// Handle expired or deleted order request key events
	orderRequest := storage.RedisClient.PSubscribe(
		ctx,
		"__keyevent@0__:expired:order_request_*",
		"__keyevent@0__:del:order_request_*",
	)
	orderRequestChan := orderRequest.Channel()

	go ReassignStaleOrderRequest(ctx, orderRequestChan)
}

// fetchExternalRate fetches the external rate for a fiat currency
func fetchExternalRate(currency string) (decimal.Decimal, error) {
	currency = strings.ToUpper(currency)
	supportedCurrencies := []string{"KES", "NGN", "GHS", "MWK", "TZS", "UGX", "XOF", "BRL"}
	isSupported := false
	for _, supported := range supportedCurrencies {
		if currency == supported {
			isSupported = true
			break
		}
	}
	if !isSupported {
		return decimal.Zero, fmt.Errorf("ComputeMarketRate: currency not supported")
	}

	// Fetch rates from noblocks rates API
	res, err := fastshot.NewClient("https://api.rates.noblocks.xyz").
		Config().SetTimeout(30*time.Second).
		Build().GET(fmt.Sprintf("/rates/usdt/%s", strings.ToLower(currency))).
		Retry().Set(3, 5*time.Second).
		Send()
	if err != nil {
		return decimal.Zero, fmt.Errorf("ComputeMarketRate: %w", err)
	}

	// Read the response body manually since we need to parse an array, not an object
	responseBody, err := io.ReadAll(res.RawResponse.Body)
	defer res.RawResponse.Body.Close()
	if err != nil {
		return decimal.Zero, fmt.Errorf("ComputeMarketRate: failed to read response body: %w", err)
	}

	var dataArray []map[string]interface{}
	err = json.Unmarshal(responseBody, &dataArray)
	if err != nil {
		return decimal.Zero, fmt.Errorf("ComputeMarketRate: failed to parse JSON response: %w", err)
	}

	// Check if we have data
	if len(dataArray) == 0 {
		return decimal.Zero, fmt.Errorf("ComputeMarketRate: No data in the response")
	}

	// Get the first rate object
	rateData := dataArray[0]

	// Extract buy and sell rates
	buyRate, ok := rateData["buyRate"].(float64)
	if !ok {
		return decimal.Zero, fmt.Errorf("ComputeMarketRate: Invalid buyRate format")
	}

	sellRate, ok := rateData["sellRate"].(float64)
	if !ok {
		return decimal.Zero, fmt.Errorf("ComputeMarketRate: Invalid sellRate format")
	}

	// Calculate the average of buy and sell rates for the external rate
	avgRate := (buyRate + sellRate) / 2
	price := decimal.NewFromFloat(avgRate)

	return price, nil
}

// ComputeMarketRate computes the market price for fiat currencies
func ComputeMarketRate() error {
	// ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	// defer cancel()
	ctx := context.Background()

	// Fetch all fiat currencies
	currencies, err := storage.Client.FiatCurrency.
		Query().
		Where(fiatcurrency.IsEnabledEQ(true)).
		All(ctx)
	if err != nil {
		return fmt.Errorf("ComputeMarketRate: %w", err)
	}

	for _, currency := range currencies {
		// Fetch external rate
		externalRate, err := fetchExternalRate(currency.Code)
		if err != nil {
			continue
		}

		// Fetch rates from token configs with fixed conversion rate
		tokenConfigs, err := storage.Client.ProviderOrderToken.
			Query().
			Where(
				providerordertoken.HasTokenWith(
					tokenent.SymbolIn("USDT", "USDC"),
				),
				providerordertoken.ConversionRateTypeEQ(providerordertoken.ConversionRateTypeFixed),
				providerordertoken.HasProviderWith(
					providerprofile.IsActiveEQ(true),
				),
			).
			Select(providerordertoken.FieldFixedConversionRate).
			All(ctx)
		if err != nil {
			continue
		}

		var rates []decimal.Decimal
		for _, tokenConfig := range tokenConfigs {
			rates = append(rates, tokenConfig.FixedConversionRate)
		}

		// Calculate median
		median := utils.Median(rates)

		// Check the median rate against the external rate to ensure it's not too far off
		percentDeviation := utils.AbsPercentageDeviation(externalRate, median)
		if percentDeviation.GreaterThan(orderConf.PercentDeviationFromExternalRate) {
			median = externalRate
		}

		// Update currency with median rate
		_, err = storage.Client.FiatCurrency.
			UpdateOneID(currency.ID).
			SetMarketRate(median).
			Save(ctx)
		if err != nil {
			continue
		}
	}

	return nil
}

// Retry failed webhook notifications
func RetryFailedWebhookNotifications() error {
	// ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	// defer cancel()
	ctx := context.Background()

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

// ResolvePaymentOrderMishaps resolves payment order mishaps across all networks
func ResolvePaymentOrderMishaps() error {
	ctx := context.Background()

	// Fetch networks
	isTestnet := false
	if serverConf.Environment != "production" && serverConf.Environment != "staging" {
		isTestnet = true
	}

	networks, err := storage.Client.Network.
		Query().
		Where(networkent.IsTestnetEQ(isTestnet)).
		All(ctx)
	if err != nil {
		return fmt.Errorf("ResolvePaymentOrderMishaps.fetchNetworks: %w", err)
	}

	// Process each network in parallel (EVM only)
	for i, network := range networks {
		// Skip Tron networks
		if strings.HasPrefix(network.Identifier, "tron") {
			continue
		}

		// Add a larger delay between starting goroutines to prevent overwhelming Etherscan
		// Increased from 100ms to 500ms to respect 5 requests/second limit
		if i > 0 {
			time.Sleep(500 * time.Millisecond)
		}

		go func(network *ent.Network) {
			ctx := context.Background()

			// Only resolve missed Transfer and OrderCreated events
			resolveMissedEvents(ctx, network)
		}(network)
	}

	return nil
}

// IndexGatewayEvents indexes all gateway events for missed OrderCreated, OrderRefunded, and OrderSettled events
func IndexGatewayEvents() error {
	ctx := context.Background()

	// Fetch networks
	isTestnet := false
	if serverConf.Environment != "production" && serverConf.Environment != "staging" {
		isTestnet = true
	}

	networks, err := storage.Client.Network.
		Query().
		Where(networkent.IsTestnetEQ(isTestnet)).
		All(ctx)
	if err != nil {
		return fmt.Errorf("IndexGatewayEvents.fetchNetworks: %w", err)
	}

	// Process each network in parallel (EVM only)
	for i, network := range networks {
		// Skip Tron networks
		if strings.HasPrefix(network.Identifier, "tron") {
			continue
		}

		// Add a larger delay between starting goroutines to prevent overwhelming Etherscan
		// Increased from 100ms to 500ms to respect 5 requests/second limit
		if i > 0 {
			time.Sleep(500 * time.Millisecond)
		}

		go func(network *ent.Network) {
			ctx := context.Background()

			// Index gateway events by fetching last 20 transactions of the gateway contract
			indexerInstance, indexerErr := indexer.NewIndexerEVM()
			if indexerErr != nil {
				logger.WithFields(logger.Fields{
					"Error":             fmt.Sprintf("%v", indexerErr),
					"NetworkIdentifier": network.Identifier,
				}).Errorf("IndexGatewayEvents.createIndexer")
				return
			}
			_, err := indexerInstance.IndexGateway(ctx, network, network.GatewayContractAddress, 0, 0, "")
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":             fmt.Sprintf("%v", err),
					"NetworkIdentifier": network.Identifier,
				}).Errorf("IndexGatewayEvents.indexGateway")
				return
			}
		}(network)
	}

	return nil
}

// resolveMissedEvents resolves cases where transfers to receive addresses were missed
func resolveMissedEvents(ctx context.Context, network *ent.Network) {
	// Find payment orders with missed transfers
	// Focus on orders older than 30 seconds but created in last 2 hours (sweet spot for missed transfers)
	now := time.Now()
	recentCutoff := now.Add(-2 * time.Hour)
	oldEnoughCutoff := now.Add(-30 * time.Second)

	orders, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.StatusEQ(paymentorder.StatusInitiated),
			paymentorder.CreatedAtLTE(oldEnoughCutoff), // At least 30 seconds old
			paymentorder.CreatedAtGTE(recentCutoff),    // But within last 2 hours
			paymentorder.HasReceiveAddressWith(
				receiveaddress.StatusNEQ(receiveaddress.StatusExpired),
			),
			paymentorder.HasTokenWith(
				tokenent.HasNetworkWith(
					networkent.IDEQ(network.ID),
				),
			),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithReceiveAddress().
		Order(ent.Desc(paymentorder.FieldCreatedAt)).
		Limit(100). // Limit to avoid processing too many at once
		All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":             fmt.Sprintf("%v", err),
			"NetworkIdentifier": network.Identifier,
		}).Errorf("ResolvePaymentOrderMishaps.resolveMissedEvents.fetchOrders")
		return
	}

	// For missed transfers, we need to check each order's specific receive address
	// Process sequentially to avoid overwhelming the RPC node and for better error handling
	indexerInstance, indexerErr := indexer.NewIndexerEVM()
	if indexerErr != nil {
		logger.WithFields(logger.Fields{
			"Error":             fmt.Sprintf("%v", indexerErr),
			"NetworkIdentifier": network.Identifier,
		}).Errorf("ResolvePaymentOrderMishaps.resolveMissedEvents.createIndexer")
		return
	}
	processedCount := 0
	errorCount := 0

	for i, order := range orders {
		if order.Edges.ReceiveAddress == nil {
			continue
		}

		address := order.Edges.ReceiveAddress.Address
		chainID := network.ChainID
		indexKey := fmt.Sprintf("%s_%d", address, chainID)

		// Check if address is currently being indexed by another task
		if _, indexing := indexingAddresses.Load(indexKey); indexing {
			// Check if indexing started too long ago (stale)
			if startTime, ok := indexingAddresses.Load(indexKey); ok {
				if time.Since(startTime.(time.Time)) > indexingTimeout {
					indexingAddresses.Delete(indexKey) // Remove stale entry
				} else {
					continue // Skip, already being indexed
				}
			}
		}

		// Check if address was recently indexed (within cooldown period)
		if lastIndexed, indexed := recentlyIndexed.Load(indexKey); indexed {
			if time.Since(lastIndexed.(time.Time)) < indexingCooldown {
				continue // Skip, recently indexed
			}
		}

		// Mark as being indexed
		indexingAddresses.Store(indexKey, time.Now())

		// Log progress selectively: all for small batches (<=10), first/last/every 50th for larger batches
		// This provides visibility without excessive logging during bulk operations
		shouldLog := len(orders) <= 10 || i == 0 || i == len(orders)-1 || (i+1)%50 == 0
		if shouldLog {
			logger.WithFields(logger.Fields{
				"NetworkIdentifier": network.Identifier,
				"ReceiveAddress":    address,
				"OrderID":           order.ID,
				"Progress":          fmt.Sprintf("%d/%d", i+1, len(orders)),
			}).Infof("ResolvePaymentOrderMishaps.resolveMissedEvents")
		}

		_, err = indexerInstance.IndexReceiveAddress(ctx, order.Edges.Token, address, 0, 0, "")

		// Remove from indexing map when done
		indexingAddresses.Delete(indexKey)

		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":             fmt.Sprintf("%v", err),
				"NetworkIdentifier": network.Identifier,
				"ReceiveAddress":    address,
				"OrderID":           order.ID,
			}).Errorf("ResolvePaymentOrderMishaps.resolveMissedEvents.indexReceiveAddress")
			errorCount++
			continue // Continue with other orders even if one fails
		}

		// Mark as recently indexed on success
		recentlyIndexed.Store(indexKey, time.Now())
		processedCount++

		// Removed 250ms delay - queue handles rate limiting, no need for artificial delay
	}

	// Log summary at end instead of logging every order
	if len(orders) > 0 {
		logger.WithFields(logger.Fields{
			"NetworkIdentifier": network.Identifier,
			"TotalOrders":       len(orders),
			"Processed":         processedCount,
			"Errors":            errorCount,
		}).Infof("ResolvePaymentOrderMishaps.resolveMissedEvents completed")
	}
}

// ProcessStuckValidatedOrders processes orders stuck on validated status by indexing provider addresses
func ProcessStuckValidatedOrders() error {
	ctx := context.Background()

	// Get all networks
	networks, err := storage.Client.Network.Query().All(ctx)
	if err != nil {
		return fmt.Errorf("ProcessStuckValidatedOrders.getNetworks: %w", err)
	}

	for i, network := range networks {
		// Add a small delay between starting goroutines to prevent overwhelming Etherscan
		if i > 0 {
			time.Sleep(100 * time.Millisecond)
		}

		go func(network *ent.Network) {
			// Get stuck validated orders for this network
			lockOrders, err := storage.Client.LockPaymentOrder.
				Query().
				Where(
					lockpaymentorder.StatusEQ(lockpaymentorder.StatusValidated),
					lockpaymentorder.HasTokenWith(
						tokenent.HasNetworkWith(
							networkent.IDEQ(network.ID),
						),
					),
					lockpaymentorder.HasProvider(),
					lockpaymentorder.HasProvisionBucket(),
				).
				WithToken(func(tq *ent.TokenQuery) {
					tq.WithNetwork()
				}).
				WithProvider().
				WithProvisionBucket(func(pb *ent.ProvisionBucketQuery) {
					pb.WithCurrency()
				}).
				All(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":             fmt.Sprintf("%v", err),
					"NetworkIdentifier": network.Identifier,
				}).Errorf("ProcessStuckValidatedOrders.getLockOrders")
				return
			}

			if len(lockOrders) == 0 {
				return
			}

			logger.WithFields(logger.Fields{
				"NetworkIdentifier": network.Identifier,
				"OrderCount":        len(lockOrders),
			}).Infof("Processing stuck validated orders")

			// Create indexer instance
			var indexerInstance types.Indexer
			if strings.HasPrefix(network.Identifier, "tron") {
				indexerInstance = indexer.NewIndexerTron()
			} else {
				indexerInstance, err = indexer.NewIndexerEVM()
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":             fmt.Sprintf("%v", err),
						"NetworkIdentifier": network.Identifier,
					}).Errorf("ProcessStuckValidatedOrders.createIndexer")
					return
				}
			}

			// Process each stuck order
			for _, order := range lockOrders {
				// Get provider address for this order
				providerAddress, err := common.GetProviderAddressFromLockOrder(ctx, order)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":             fmt.Sprintf("%v", err),
						"OrderID":           order.ID.String(),
						"NetworkIdentifier": network.Identifier,
					}).Errorf("ProcessStuckValidatedOrders.getProviderAddress")
					continue
				}

				// Index provider address for OrderSettled events
				_, err = indexerInstance.IndexProviderAddress(ctx, network, providerAddress, 0, 0, "")
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":             fmt.Sprintf("%v", err),
						"OrderID":           order.ID.String(),
						"ProviderAddress":   providerAddress,
						"NetworkIdentifier": network.Identifier,
					}).Errorf("ProcessStuckValidatedOrders.indexProviderAddress")
					continue
				}

				logger.WithFields(logger.Fields{
					"OrderID":           order.ID.String(),
					"ProviderAddress":   providerAddress,
					"NetworkIdentifier": network.Identifier,
				}).Infof("Successfully indexed provider address for stuck order")
			}
		}(network)
	}

	return nil
}

// FetchProviderBalances fetches balance updates from all providers
func FetchProviderBalances() error {
	ctx := context.Background()
	startTime := time.Now()

	// Get all provider profiles
	providers, err := storage.Client.ProviderProfile.
		Query().
		Where(
			providerprofile.HostIdentifierNEQ(""),
			providerprofile.IsActiveEQ(true),
			providerprofile.HasProviderCurrenciesWith(
				providercurrencies.IsAvailableEQ(true),
			),
		).
		All(ctx)
	if err != nil {
		logger.Errorf("Failed to fetch provider profiles: %v", err)
		return err
	}

	if len(providers) == 0 {
		logger.Infof("No providers found, skipping balance fetch")
		return nil
	}

	// Fetch balances for each provider in parallel
	type balanceResult struct {
		providerID string
		balances   map[string]*types.ProviderBalance
		err        error
	}

	results := make(chan balanceResult, len(providers))

	for _, provider := range providers {
		go func(p *ent.ProviderProfile) {
			balances, err := fetchProviderBalances(p.ID)
			results <- balanceResult{
				providerID: p.ID,
				balances:   balances,
				err:        err,
			}
		}(provider)
	}

	// Collect results
	successCount := 0
	errorCount := 0
	totalBalanceUpdates := 0

	for i := 0; i < len(providers); i++ {
		result := <-results
		if result.err != nil {
			logger.Errorf("Failed to fetch balances for provider %s: %v", result.providerID, result.err)
			errorCount++
			continue
		}

		// Update balances in database
		for currency, balance := range result.balances {
			err := utils.Retry(3, 2*time.Second, func() error {
				return updateProviderBalance(result.providerID, currency, balance)
			})
			if err != nil {
				logger.Errorf("Failed to update balance for provider %s currency %s: %v", result.providerID, currency, err)
				errorCount++
				continue
			}
			totalBalanceUpdates++
		}

		successCount++
		logger.Infof("Successfully updated balances for provider %s", result.providerID)
	}

	duration := time.Since(startTime)
	logger.Infof("Provider balance fetch completed: %d success, %d errors, %d balance updates in %v",
		successCount, errorCount, totalBalanceUpdates, duration)

	// Alert if more than 50% of providers failed
	if errorCount > 0 && float64(errorCount)/float64(len(providers)) > 0.5 {
		logger.Errorf("ALERT: More than 50%% of providers failed balance fetch: %d/%d", errorCount, len(providers))
		return fmt.Errorf("more than 50%% of providers failed balance fetch: %d/%d", errorCount, len(providers))
	}

	// Alert if no balance updates were made
	if totalBalanceUpdates == 0 {
		logger.Warnf("ALERT: No balance updates were made during this fetch cycle")
	}

	// Log performance metrics
	if duration > 30*time.Second {
		logger.Warnf("ALERT: Balance fetch took longer than expected: %v", duration)
	}

	return nil
}

// fetchProviderBalances fetches balances for a specific provider
func fetchProviderBalances(providerID string) (map[string]*types.ProviderBalance, error) {
	// Get provider with host identifier
	provider, err := storage.Client.ProviderProfile.
		Query().
		Where(providerprofile.IDEQ(providerID)).
		Only(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	// Check if provider has host identifier
	if provider.HostIdentifier == "" {
		return nil, fmt.Errorf("provider %s has no host identifier", providerID)
	}

	// Call provider /info endpoint without HMAC (endpoint doesn't require authentication)
	res, err := fastshot.NewClient(provider.HostIdentifier).
		Config().SetTimeout(30 * time.Second).
		Build().GET("/info").
		Send()
	if err != nil {
		return nil, fmt.Errorf("failed to call provider /info endpoint: %v", err)
	}

	// Parse JSON response
	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Parse the response data into ProviderInfoResponse using proper JSON unmarshaling
	responseBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %v", err)
	}

	var response types.ProviderInfoResponse
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response data: %v", err)
	}

	// Convert response to ProviderBalance map
	balances := make(map[string]*types.ProviderBalance)

	// Use totalBalances from response
	for currency, balanceData := range response.Data.TotalBalances {
		availableBalance, err := decimal.NewFromString(balanceData.AvailableBalance)
		if err != nil {
			logger.Warnf("Failed to parse available balance for %s: %v", currency, err)
			continue
		}
		if availableBalance.IsNegative() {
			logger.Errorf("Negative available balance for %s: %v", currency, availableBalance)
			continue
		}

		totalBalance, err := decimal.NewFromString(balanceData.TotalBalance)
		if err != nil {
			logger.Warnf("Failed to parse total balance for %s: %v", currency, err)
			continue
		}
		if totalBalance.IsNegative() {
			logger.Errorf("Negative total balance for %s: %v", currency, totalBalance)
			continue
		}

		balances[currency] = &types.ProviderBalance{
			AvailableBalance: availableBalance,
			TotalBalance:     totalBalance,
			ReservedBalance:  decimal.Zero, // Provider doesn't track reserved balance
			LastUpdated:      time.Now(),
		}
	}

	return balances, nil
}

// updateProviderBalance updates the balance for a specific provider and currency
func updateProviderBalance(providerID, currency string, balance *types.ProviderBalance) error {
	ctx := context.Background()
	// Get or create ProviderCurrencies entry
	providerCurrency, err := storage.Client.ProviderCurrencies.Query().
		Where(
			providercurrencies.HasProviderWith(providerprofile.IDEQ(providerID)),
			providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(currency)),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			// Create new entry
			provider, err := storage.Client.ProviderProfile.Get(ctx, providerID)
			if err != nil {
				return fmt.Errorf("failed to get provider: %v", err)
			}

			fiatCurrency, err := storage.Client.FiatCurrency.Query().
				Where(fiatcurrency.CodeEQ(currency)).
				Only(ctx)
			if err != nil {
				return fmt.Errorf("failed to get fiat currency: %v", err)
			}

			_, err = storage.Client.ProviderCurrencies.Create().
				SetProvider(provider).
				SetCurrency(fiatCurrency).
				SetAvailableBalance(balance.AvailableBalance).
				SetTotalBalance(balance.TotalBalance).
				SetReservedBalance(balance.ReservedBalance).
				SetUpdatedAt(time.Now()).
				SetIsAvailable(true).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("failed to create provider currency: %v", err)
			}
		} else {
			return fmt.Errorf("failed to query provider currency: %v", err)
		}
	} else {
		// Update existing entry
		_, err = providerCurrency.Update().
			SetAvailableBalance(balance.AvailableBalance).
			SetTotalBalance(balance.TotalBalance).
			SetReservedBalance(balance.ReservedBalance).
			SetUpdatedAt(time.Now()).
			Save(ctx)

		if err != nil {
			return fmt.Errorf("failed to update provider currency: %v", err)
		}
	}

	return nil
}

// StartCronJobs starts cron jobs
func StartCronJobs() {
	// Use the system's local timezone instead of hardcoded UTC to prevent timezone conflicts
	scheduler := gocron.NewScheduler(time.Local)
	priorityQueue := services.NewPriorityQueueService()

	err := ComputeMarketRate()
	if err != nil {
		logger.Errorf("StartCronJobs for ComputeMarketRate: %v", err)
	}

	if serverConf.Environment != "production" {
		err = priorityQueue.ProcessBucketQueues()
		if err != nil {
			logger.Errorf("StartCronJobs for ProcessBucketQueues: %v", err)
		}
	}

	// Compute market rate every 9 minutes
	_, err = scheduler.Every(9).Minutes().Do(ComputeMarketRate)
	if err != nil {
		logger.Errorf("StartCronJobs for ComputeMarketRate: %v", err)
	}

	// Refresh provision bucket priority queues every X minutes
	_, err = scheduler.Every(orderConf.BucketQueueRebuildInterval).Minutes().Do(priorityQueue.ProcessBucketQueues)
	if err != nil {
		logger.Errorf("StartCronJobs for ProcessBucketQueues: %v", err)
	}

	// Retry failed webhook notifications every 13 minutes
	_, err = scheduler.Every(13).Minutes().Do(RetryFailedWebhookNotifications)
	if err != nil {
		logger.Errorf("StartCronJobs for RetryFailedWebhookNotifications: %v", err)
	}

	// Sync lock order fulfillments every 32 seconds
	_, err = scheduler.Every(32).Seconds().Do(SyncLockOrderFulfillments)
	if err != nil {
		logger.Errorf("StartCronJobs for SyncLockOrderFulfillments: %v", err)
	}

	// Handle receive address validity every 6 minutes
	_, err = scheduler.Every(6).Minutes().Do(HandleReceiveAddressValidity)
	if err != nil {
		logger.Errorf("StartCronJobs for HandleReceiveAddressValidity: %v", err)
	}

	// Retry stale user operations every 60 seconds
	_, err = scheduler.Every(60).Seconds().Do(RetryStaleUserOperations)
	if err != nil {
		logger.Errorf("StartCronJobs for RetryStaleUserOperations: %v", err)
	}

	// Resolve payment order mishaps every 14 seconds
	_, err = scheduler.Every(14).Seconds().Do(ResolvePaymentOrderMishaps)
	if err != nil {
		logger.Errorf("StartCronJobs for ResolvePaymentOrderMishaps: %v", err)
	}

	// Index gateway events every 6 minutes
	_, err = scheduler.Every(6).Minutes().Do(IndexGatewayEvents)
	if err != nil {
		logger.Errorf("StartCronJobs for IndexGatewayEvents: %v", err)
	}

	// Process stuck validated orders every 12 minutes
	_, err = scheduler.Every(12).Minutes().Do(ProcessStuckValidatedOrders)
	if err != nil {
		logger.Errorf("StartCronJobs for ProcessStuckValidatedOrders: %v", err)
	}

	// Index blockchain events every 4 seconds
	_, err = scheduler.Every(4).Seconds().Do(TaskIndexBlockchainEvents)
	if err != nil {
		logger.Errorf("StartCronJobs for IndexBlockchainEvents: %v", err)
	}

	// Process expired orders refunds every RefundsInterval
	_, err = scheduler.Every(RefundsInterval).Minutes().Do(ProcessExpiredOrdersRefunds)
	if err != nil {
		logger.Errorf("StartCronJobs for ProcessExpiredOrdersRefunds: %v", err)
	}

	// Cleanup stale entries in indexing coordination maps
	_, err = scheduler.Every(indexingCleanupInterval).Do(cleanupIndexingMaps)
	if err != nil {
		logger.Errorf("StartCronJobs for cleanupIndexingMaps: %v", err)
	}

	// Start scheduler
	scheduler.StartAsync()
}
