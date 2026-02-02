package tasks

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/ent"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
	tokenent "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/services/indexer"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

// TaskIndexBlockchainEvents indexes transfer events for all enabled tokens
func TaskIndexBlockchainEvents() error {
	ctx := context.Background()

	// Use distributed lock to prevent concurrent execution
	// Lock TTL: 10 seconds (2.5x cron interval + buffer for processing time)
	// This ensures the lock doesn't expire even if processing takes longer than one cron cycle
	cleanup, acquired, err := acquireDistributedLock(ctx, "task_index_blockchain_events_lock", 10*time.Second, "TaskIndexBlockchainEvents")
	if err != nil {
		return err
	}
	if !acquired {
		// Another instance is already running; skip.
		return nil
	}
	defer cleanup()

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
				return
			} else if strings.HasPrefix(network.Identifier, "starknet") {
				indexerInstance, err = indexer.NewIndexerStarknet()
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":             fmt.Sprintf("%v", err),
						"NetworkIdentifier": network.Identifier,
					}).Errorf("TaskIndexBlockchainEvents.createStarknetIndexer")
					return
				}
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
			}

			// Find payment orders with missed transfers (for EVM and Starknet networks)
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
					paymentorder.ReceiveAddressNEQ(""),      // Must have receive address
					paymentorder.HasTokenWith(
						tokenent.HasNetworkWith(
							networkent.IDEQ(network.ID),
						),
					),
				).
				WithToken(func(tq *ent.TokenQuery) {
					tq.WithNetwork()
				}).
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
					if order.ReceiveAddress == "" {
						continue
					}

					address := order.ReceiveAddress
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

	// Process each network in parallel (EVM and Starknet)
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
			paymentorder.CreatedAtLTE(oldEnoughCutoff),      // At least 30 seconds old
			paymentorder.CreatedAtGTE(recentCutoff),         // But within last 2 hours
			paymentorder.ReceiveAddressNEQ(""),              // Must have receive address
			paymentorder.ReceiveAddressExpiryGT(time.Now()), // Not expired
			paymentorder.HasTokenWith(
				tokenent.HasNetworkWith(
					networkent.IDEQ(network.ID),
				),
			),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
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
	var indexerInstance types.Indexer
	var indexerErr error

	if strings.HasPrefix(network.Identifier, "starknet") {
		indexerInstance, indexerErr = indexer.NewIndexerStarknet()
		if indexerErr != nil {
			logger.WithFields(logger.Fields{
				"Error":             fmt.Sprintf("%v", indexerErr),
				"NetworkIdentifier": network.Identifier,
			}).Errorf("ResolvePaymentOrderMishaps.resolveMissedEvents.createStarknetIndexer")
			return
		}
	} else {
		indexerInstance, indexerErr = indexer.NewIndexerEVM()
		if indexerErr != nil {
			logger.WithFields(logger.Fields{
				"Error":             fmt.Sprintf("%v", indexerErr),
				"NetworkIdentifier": network.Identifier,
			}).Errorf("ResolvePaymentOrderMishaps.resolveMissedEvents.createEVMIndexer")
			return
		}
	}
	processedCount := 0
	errorCount := 0

	for i, order := range orders {
		if order.ReceiveAddress == "" {
			continue
		}

		address := order.ReceiveAddress
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
			lockOrders, err := storage.Client.PaymentOrder.
				Query().
				Where(
					paymentorder.StatusEQ(paymentorder.StatusValidated),
					paymentorder.HasTokenWith(
						tokenent.HasNetworkWith(
							networkent.IDEQ(network.ID),
						),
					),
					paymentorder.HasProvider(),
					paymentorder.HasProvisionBucket(),
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
			} else if strings.HasPrefix(network.Identifier, "starknet") {
				indexerInstance, err = indexer.NewIndexerStarknet()
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":             fmt.Sprintf("%v", err),
						"NetworkIdentifier": network.Identifier,
					}).Errorf("ProcessStuckValidatedOrders.createStarknetIndexer")
					return
				}
			} else {
				indexerInstance, err = indexer.NewIndexerEVM()
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":             fmt.Sprintf("%v", err),
						"NetworkIdentifier": network.Identifier,
					}).Errorf("ProcessStuckValidatedOrders.createEVMIndexer")
					return
				}
			}

			// Process each stuck order
			for _, order := range lockOrders {
				// Get provider address for this order
				providerAddress, err := common.GetProviderAddressFromOrder(ctx, order)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":             fmt.Sprintf("%v", err),
						"OrderID":           order.ID.String(),
						"NetworkIdentifier": network.Identifier,
					}).Errorf("ProcessStuckValidatedOrders.getProviderAddress")
					continue
				}

				// Index provider address for SettleOut events
				_, err = indexerInstance.IndexProviderSettlementAddress(ctx, network, providerAddress, 0, 0, "")
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
