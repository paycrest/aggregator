package indexer

import (
	"context"
	"fmt"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/paycrest/aggregator/ent"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/services/order"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

// IndexerEVM performs blockchain to database extract, transform, load (ETL) operations.
type IndexerEVM struct {
	priorityQueue *services.PriorityQueueService
	order         types.OrderService
	engineService *services.EngineService
}

// NewIndexerEVM creates a new instance of IndexerEVM.
func NewIndexerEVM() types.Indexer {
	priorityQueue := services.NewPriorityQueueService()
	orderService := order.NewOrderEVM()
	engineService := services.NewEngineService()

	return &IndexerEVM{
		priorityQueue: priorityQueue,
		order:         orderService,
		engineService: engineService,
	}
}

// IndexReceiveAddress indexes transfers to receive/linked addresses from user transaction history
func (s *IndexerEVM) IndexReceiveAddress(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64, txHash string) error {
	// If txHash is provided, process that specific transaction
	if txHash != "" {
		return s.indexReceiveAddressByTransaction(ctx, network, address, txHash)
	}

	// If only address is provided (no txHash, no block range), fetch user's transaction history
	if address != "" && fromBlock == 0 && toBlock == 0 {
		return s.indexReceiveAddressByUserAddress(ctx, network, address)
	}

	// If address is provided with block range, fetch user's transactions within that range
	if address != "" && (fromBlock > 0 || toBlock > 0) {
		return s.indexReceiveAddressByUserAddressInRange(ctx, network, address, fromBlock, toBlock)
	}

	// If only block range is provided, this is not applicable for receive address indexing
	return fmt.Errorf("receive address indexing requires an address parameter")
}

// indexReceiveAddressByTransaction processes a specific transaction for receive address transfers
func (s *IndexerEVM) indexReceiveAddressByTransaction(ctx context.Context, network *ent.Network, address string, txHash string) error {
	// Get all enabled tokens for this network
	tokens, err := storage.Client.Token.
		Query().
		Where(
			token.IsEnabled(true),
			token.HasNetworkWith(
				networkent.IDEQ(network.ID),
			),
		).
		WithNetwork().
		All(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch tokens: %w", err)
	}

	// Process each token for transfer events in this transaction
	for _, token := range tokens {
		err := s.IndexReceiveAddress(ctx, token.Edges.Network, address, 0, 0, txHash)
		if err != nil && err.Error() != "no events found" {
			logger.Errorf("Error processing transfer for token %s in transaction %s: %v", token.Symbol, txHash[:10]+"...", err)
		}
	}

	return nil
}

// indexReceiveAddressByUserAddress processes user's transaction history for receive address transfers
func (s *IndexerEVM) indexReceiveAddressByUserAddress(ctx context.Context, network *ent.Network, userAddress string) error {
	// Get user's transaction history (last 10 transactions by default)
	transactions, err := s.engineService.GetUserTransactionHistory(ctx, network.ChainID, userAddress, 10, 0, 0)
	if err != nil {
		return fmt.Errorf("failed to get user transaction history: %w", err)
	}

	if len(transactions) == 0 {
		logger.Infof("No transactions found for address: %s", userAddress)
		return nil
	}

	logger.Infof("Processing %d transactions for address: %s", len(transactions), userAddress)

	// Process each transaction to find transfer events to linked addresses
	for i, tx := range transactions {
		txHash := tx["hash"].(string)
		logger.Infof("Processing transaction %d/%d: %s", i+1, len(transactions), txHash[:10]+"...")

		// Index transfer events for this specific transaction
		err := s.indexReceiveAddressByTransaction(ctx, network, userAddress, txHash)
		if err != nil {
			logger.Errorf("Error processing transaction %s: %v", txHash[:10]+"...", err)
			continue // Skip transactions with errors
		}
	}

	return nil
}

// indexReceiveAddressByUserAddressInRange processes user's transaction history within a block range for receive address transfers
func (s *IndexerEVM) indexReceiveAddressByUserAddressInRange(ctx context.Context, network *ent.Network, userAddress string, fromBlock int64, toBlock int64) error {
	// Get user's transaction history filtered by block range
	transactions, err := s.engineService.GetUserTransactionHistory(ctx, network.ChainID, userAddress, 100, fromBlock, toBlock)
	if err != nil {
		return fmt.Errorf("failed to get user transaction history: %w", err)
	}

	if len(transactions) == 0 {
		logger.Infof("No transactions found in block range %d-%d for address: %s", fromBlock, toBlock, userAddress)
		return nil
	}

	logger.Infof("Processing %d transactions in block range %d-%d for address: %s", len(transactions), fromBlock, toBlock, userAddress)

	// Process each transaction to find transfer events to linked addresses
	for i, tx := range transactions {
		txHash := tx["hash"].(string)
		logger.Infof("Processing transaction %d/%d: %s", i+1, len(transactions), txHash[:10]+"...")

		// Index transfer events for this specific transaction
		err := s.indexReceiveAddressByTransaction(ctx, network, userAddress, txHash)
		if err != nil {
			logger.Errorf("Error processing transaction %s: %v", txHash[:10]+"...", err)
			continue // Skip transactions with errors
		}
	}

	return nil
}

// IndexGateway indexes all Gateway contract events (OrderCreated, OrderSettled, OrderRefunded) in a single call
func (s *IndexerEVM) IndexGateway(ctx context.Context, network *ent.Network, fromBlock int64, toBlock int64, txHash string) error {
	var events []interface{}
	var err error

	// Check if this is BNB Smart Chain (chain ID 56) - use RPC instead of Thirdweb Insight
	if network.ChainID == 56 {
		// Use GetContractEventsRPC to fetch all gateway events in one call
		var topics []string
		events, err = s.engineService.GetContractEventsRPC(
			ctx,
			network.RPCEndpoint,
			network.GatewayContractAddress,
			fromBlock,
			toBlock,
			topics,
			txHash,
		)
		if err != nil {
			return fmt.Errorf("IndexGateway.getEvents: %w", err)
		}

		// Process all events in a single pass (similar to Thirdweb approach)
		orderCreatedEvents := []*types.OrderCreatedEvent{}
		orderSettledEvents := []*types.OrderSettledEvent{}
		orderRefundedEvents := []*types.OrderRefundedEvent{}

		for _, event := range events {
			eventParams := event.(map[string]interface{})["decoded"].(map[string]interface{})
			if eventParams["non_indexed_params"] == nil {
				continue
			}

			// Get event signature to determine event type
			topics := event.(map[string]interface{})["topics"].([]string)
			if len(topics) == 0 {
				continue
			}
			eventSignature := topics[0]

			blockNumber := int64(event.(map[string]interface{})["block_number"].(float64))
			txHash := event.(map[string]interface{})["transaction_hash"].(string)

			switch eventSignature {
			case utils.OrderCreatedEventSignature:
				orderAmount, err := decimal.NewFromString(eventParams["indexed_params"].(map[string]interface{})["amount"].(string))
				if err != nil {
					continue
				}
				protocolFee, err := decimal.NewFromString(eventParams["non_indexed_params"].(map[string]interface{})["protocolFee"].(string))
				if err != nil {
					continue
				}
				rate, err := decimal.NewFromString(eventParams["non_indexed_params"].(map[string]interface{})["rate"].(string))
				if err != nil {
					continue
				}

				createdEvent := &types.OrderCreatedEvent{
					BlockNumber: blockNumber,
					TxHash:      txHash,
					Token:       ethcommon.HexToAddress(eventParams["indexed_params"].(map[string]interface{})["token"].(string)).Hex(),
					Amount:      orderAmount,
					ProtocolFee: protocolFee,
					OrderId:     eventParams["non_indexed_params"].(map[string]interface{})["orderId"].(string),
					Rate:        rate.Div(decimal.NewFromInt(100)),
					MessageHash: eventParams["non_indexed_params"].(map[string]interface{})["messageHash"].(string),
					Sender:      ethcommon.HexToAddress(eventParams["indexed_params"].(map[string]interface{})["sender"].(string)).Hex(),
				}
				orderCreatedEvents = append(orderCreatedEvents, createdEvent)

			case utils.OrderSettledEventSignature:
				settlePercent, err := decimal.NewFromString(eventParams["non_indexed_params"].(map[string]interface{})["settlePercent"].(string))
				if err != nil {
					continue
				}

				settledEvent := &types.OrderSettledEvent{
					BlockNumber:       blockNumber,
					TxHash:            txHash,
					SplitOrderId:      eventParams["non_indexed_params"].(map[string]interface{})["splitOrderId"].(string),
					OrderId:           eventParams["indexed_params"].(map[string]interface{})["orderId"].(string),
					LiquidityProvider: ethcommon.HexToAddress(eventParams["indexed_params"].(map[string]interface{})["liquidityProvider"].(string)).Hex(),
					SettlePercent:     settlePercent,
				}
				orderSettledEvents = append(orderSettledEvents, settledEvent)

			case utils.OrderRefundedEventSignature:
				fee, err := decimal.NewFromString(eventParams["non_indexed_params"].(map[string]interface{})["fee"].(string))
				if err != nil {
					continue
				}

				refundedEvent := &types.OrderRefundedEvent{
					BlockNumber: blockNumber,
					TxHash:      txHash,
					OrderId:     eventParams["indexed_params"].(map[string]interface{})["orderId"].(string),
					Fee:         fee,
				}
				orderRefundedEvents = append(orderRefundedEvents, refundedEvent)
			}
		}

		// Process OrderCreated events
		if len(orderCreatedEvents) > 0 {
			txHashes := []string{}
			hashToEvent := make(map[string]*types.OrderCreatedEvent)
			for _, event := range orderCreatedEvents {
				txHashes = append(txHashes, event.TxHash)
				hashToEvent[event.TxHash] = event
			}
			err = common.ProcessCreatedOrders(ctx, network, txHashes, hashToEvent, s.order, s.priorityQueue)
			if err != nil {
				logger.Errorf("Failed to process OrderCreated events: %v", err)
			} else {
				logger.Infof("Successfully processed %d OrderCreated events", len(orderCreatedEvents))
			}
		}

		// Process OrderSettled events
		if len(orderSettledEvents) > 0 {
			txHashes := []string{}
			hashToEvent := make(map[string]*types.OrderSettledEvent)
			for _, event := range orderSettledEvents {
				txHashes = append(txHashes, event.TxHash)
				hashToEvent[event.TxHash] = event
			}
			err = common.ProcessSettledOrders(ctx, network, txHashes, hashToEvent)
			if err != nil {
				logger.Errorf("Failed to process OrderSettled events: %v", err)
			} else {
				logger.Infof("Successfully processed %d OrderSettled events", len(orderSettledEvents))
			}
		}

		// Process OrderRefunded events
		if len(orderRefundedEvents) > 0 {
			txHashes := []string{}
			hashToEvent := make(map[string]*types.OrderRefundedEvent)
			for _, event := range orderRefundedEvents {
				txHashes = append(txHashes, event.TxHash)
				hashToEvent[event.TxHash] = event
			}
			err = common.ProcessRefundedOrders(ctx, network, txHashes, hashToEvent)
			if err != nil {
				logger.Errorf("Failed to process OrderRefunded events: %v", err)
			} else {
				logger.Infof("Successfully processed %d OrderRefunded events", len(orderRefundedEvents))
			}
		}

		return nil
	}

	// Use Thirdweb Insight for other networks - make a single API call to get all events
	var eventPayload map[string]string
	if txHash != "" {
		eventPayload = map[string]string{
			"filter_transaction_hash": txHash,
			"sort_by":                 "block_number",
			"sort_order":              "desc",
			"decode":                  "true",
		}
	} else {
		eventPayload = map[string]string{
			"filter_block_number_gte": fmt.Sprintf("%d", fromBlock),
			"filter_block_number_lte": fmt.Sprintf("%d", toBlock),
			"sort_by":                 "block_number",
			"sort_order":              "desc",
			"decode":                  "true",
			"limit":                   "20",
		}
	}

	events, err = s.engineService.GetContractEvents(ctx, network.ChainID, network.GatewayContractAddress, eventPayload)
	if err != nil {
		return fmt.Errorf("IndexGateway.getEvents: %w", err)
	}

	// Process all events in a single pass
	orderCreatedEvents := []*types.OrderCreatedEvent{}
	orderSettledEvents := []*types.OrderSettledEvent{}
	orderRefundedEvents := []*types.OrderRefundedEvent{}

	for _, event := range events {
		eventParams := event.(map[string]interface{})["decoded"].(map[string]interface{})
		if eventParams["non_indexed_params"] == nil {
			continue
		}

		eventName := eventParams["name"].(string)
		blockNumber := int64(event.(map[string]interface{})["block_number"].(float64))
		txHash := event.(map[string]interface{})["transaction_hash"].(string)

		switch eventName {
		case "OrderCreated":
			orderAmount, err := decimal.NewFromString(eventParams["indexed_params"].(map[string]interface{})["amount"].(string))
			if err != nil {
				continue
			}
			protocolFee, err := decimal.NewFromString(eventParams["non_indexed_params"].(map[string]interface{})["protocolFee"].(string))
			if err != nil {
				continue
			}
			rate, err := decimal.NewFromString(eventParams["non_indexed_params"].(map[string]interface{})["rate"].(string))
			if err != nil {
				continue
			}

			createdEvent := &types.OrderCreatedEvent{
				BlockNumber: blockNumber,
				TxHash:      txHash,
				Token:       ethcommon.HexToAddress(eventParams["indexed_params"].(map[string]interface{})["token"].(string)).Hex(),
				Amount:      orderAmount,
				ProtocolFee: protocolFee,
				OrderId:     eventParams["non_indexed_params"].(map[string]interface{})["orderId"].(string),
				Rate:        rate.Div(decimal.NewFromInt(100)),
				MessageHash: eventParams["non_indexed_params"].(map[string]interface{})["messageHash"].(string),
				Sender:      ethcommon.HexToAddress(eventParams["indexed_params"].(map[string]interface{})["sender"].(string)).Hex(),
			}
			orderCreatedEvents = append(orderCreatedEvents, createdEvent)

		case "OrderSettled":
			settlePercent, err := decimal.NewFromString(eventParams["non_indexed_params"].(map[string]interface{})["settlePercent"].(string))
			if err != nil {
				continue
			}

			settledEvent := &types.OrderSettledEvent{
				BlockNumber:       blockNumber,
				TxHash:            txHash,
				SplitOrderId:      eventParams["non_indexed_params"].(map[string]interface{})["splitOrderId"].(string),
				OrderId:           eventParams["indexed_params"].(map[string]interface{})["orderId"].(string),
				LiquidityProvider: ethcommon.HexToAddress(eventParams["indexed_params"].(map[string]interface{})["liquidityProvider"].(string)).Hex(),
				SettlePercent:     settlePercent,
			}
			orderSettledEvents = append(orderSettledEvents, settledEvent)

		case "OrderRefunded":
			fee, err := decimal.NewFromString(eventParams["non_indexed_params"].(map[string]interface{})["fee"].(string))
			if err != nil {
				continue
			}

			refundedEvent := &types.OrderRefundedEvent{
				BlockNumber: blockNumber,
				TxHash:      txHash,
				OrderId:     eventParams["indexed_params"].(map[string]interface{})["orderId"].(string),
				Fee:         fee,
			}
			orderRefundedEvents = append(orderRefundedEvents, refundedEvent)
		}
	}

	// Process OrderCreated events
	if len(orderCreatedEvents) > 0 {
		txHashes := []string{}
		hashToEvent := make(map[string]*types.OrderCreatedEvent)
		for _, event := range orderCreatedEvents {
			txHashes = append(txHashes, event.TxHash)
			hashToEvent[event.TxHash] = event
		}
		err = common.ProcessCreatedOrders(ctx, network, txHashes, hashToEvent, s.order, s.priorityQueue)
		if err != nil {
			logger.Errorf("Failed to process OrderCreated events: %v", err)
		} else {
			logger.Infof("Successfully processed %d OrderCreated events", len(orderCreatedEvents))
		}
	}

	// Process OrderSettled events
	if len(orderSettledEvents) > 0 {
		txHashes := []string{}
		hashToEvent := make(map[string]*types.OrderSettledEvent)
		for _, event := range orderSettledEvents {
			txHashes = append(txHashes, event.TxHash)
			hashToEvent[event.TxHash] = event
		}
		err = common.ProcessSettledOrders(ctx, network, txHashes, hashToEvent)
		if err != nil {
			logger.Errorf("Failed to process OrderSettled events: %v", err)
		} else {
			logger.Infof("Successfully processed %d OrderSettled events", len(orderSettledEvents))
		}
	}

	// Process OrderRefunded events
	if len(orderRefundedEvents) > 0 {
		txHashes := []string{}
		hashToEvent := make(map[string]*types.OrderRefundedEvent)
		for _, event := range orderRefundedEvents {
			txHashes = append(txHashes, event.TxHash)
			hashToEvent[event.TxHash] = event
		}
		err = common.ProcessRefundedOrders(ctx, network, txHashes, hashToEvent)
		if err != nil {
			logger.Errorf("Failed to process OrderRefunded events: %v", err)
		} else {
			logger.Infof("Successfully processed %d OrderRefunded events", len(orderRefundedEvents))
		}
	}

	return nil
}
