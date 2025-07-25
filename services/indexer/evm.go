package indexer

import (
	"context"
	"fmt"
	"strings"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/services/order"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

// IndexerEVM performs blockchain to database extract, transform, load (ETL) operations.
type IndexerEVM struct {
	priorityQueue    *services.PriorityQueueService
	order            types.OrderService
	engineService    *services.EngineService
	etherscanService *services.EtherscanService
}

// NewIndexerEVM creates a new instance of IndexerEVM.
func NewIndexerEVM() (types.Indexer, error) {
	priorityQueue := services.NewPriorityQueueService()
	orderService := order.NewOrderEVM()
	engineService := services.NewEngineService()
	etherscanService, err := services.NewEtherscanService()
	if err != nil {
		return nil, fmt.Errorf("failed to create EtherscanService: %w", err)
	}

	return &IndexerEVM{
		priorityQueue:    priorityQueue,
		order:            orderService,
		engineService:    engineService,
		etherscanService: etherscanService,
	}, nil
}

// IndexReceiveAddress indexes all transfer events for a specific receive address
func (s *IndexerEVM) IndexReceiveAddress(ctx context.Context, token *ent.Token, address string, fromBlock int64, toBlock int64, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}

	if txHash != "" {
		// Index transfer events for this specific transaction
		counts, err := s.indexReceiveAddressByTransaction(ctx, token, txHash)
		if err != nil {
			logger.Errorf("Error processing receive address transaction %s: %v", txHash[:10]+"...", err)
			return eventCounts, err
		}
		return counts, nil
	}

	// Index transfer events for the receive address
	counts, err := s.indexReceiveAddressByUserAddress(ctx, token, address, fromBlock, toBlock)
	if err != nil {
		return eventCounts, err
	}

	// Return the actual counts from the indexing operation
	return counts, nil
}

// indexReceiveAddressByTransaction processes a specific transaction for receive address transfers
func (s *IndexerEVM) indexReceiveAddressByTransaction(ctx context.Context, token *ent.Token, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}

	// Get transfer events for this token contract in this transaction
	transferEvents, err := s.engineService.GetContractEventsWithFallback(
		ctx,
		token.Edges.Network,
		token.ContractAddress,
		0,
		0,
		[]string{utils.TransferEventSignature}, // Include transfer event signature
		txHash,
		map[string]string{
			"filter_transaction_hash": txHash,
			"sort_by":                 "block_number",
			"sort_order":              "desc",
			"decode":                  "true",
		},
	)
	if err != nil && err.Error() != "no events found" {
		return eventCounts, fmt.Errorf("error getting transfer events for token %s in transaction %s: %w", token.Symbol, txHash[:10]+"...", err)
	}

	// Find OrderCreated events for this transaction
	gatewayEvents, err := s.engineService.GetContractEventsWithFallback(
		ctx,
		token.Edges.Network,
		token.Edges.Network.GatewayContractAddress,
		0,
		0,
		[]string{utils.OrderCreatedEventSignature},
		txHash,
		map[string]string{
			"filter_transaction_hash": txHash,
			"sort_by":                 "block_number",
			"sort_order":              "desc",
			"decode":                  "true",
		},
	)
	if err != nil && err.Error() != "no events found" {
		return eventCounts, fmt.Errorf("error getting gateway events for transaction %s: %w", txHash[:10]+"...", err)
	}

	// Process transfer events
	for _, event := range transferEvents {
		eventMap := event.(map[string]interface{})
		decoded, ok := eventMap["decoded"].(map[string]interface{})
		if !ok || decoded == nil {
			continue
		}
		indexedParams := decoded["indexed_params"].(map[string]interface{})
		nonIndexedParams := decoded["non_indexed_params"].(map[string]interface{})

		// Extract transfer data
		fromAddress := ethcommon.HexToAddress(indexedParams["from"].(string)).Hex()
		toAddress := ethcommon.HexToAddress(indexedParams["to"].(string)).Hex()
		valueStr := nonIndexedParams["value"].(string)

		// Skip if transfer is from gateway contract
		if strings.EqualFold(fromAddress, token.Edges.Network.GatewayContractAddress) {
			continue
		}

		// Parse transfer value
		transferValue, err := decimal.NewFromString(valueStr)
		if err != nil {
			logger.Errorf("Error parsing transfer value for token %s: %v", token.Symbol, err)
			continue
		}

		// Create transfer event
		transferEvent := &types.TokenTransferEvent{
			BlockNumber: int64(eventMap["block_number"].(float64)),
			TxHash:      eventMap["transaction_hash"].(string),
			From:        fromAddress,
			To:          toAddress,
			Value:       transferValue.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(token.Decimals)))),
		}

		// Process transfer using existing logic
		addressToEvent := map[string]*types.TokenTransferEvent{
			toAddress: transferEvent,
		}

		err = common.ProcessTransfers(ctx, s.order, s.priorityQueue, []string{toAddress}, addressToEvent, token)
		if err != nil {
			logger.Errorf("Error processing transfer for token %s: %v", token.Symbol, err)
			continue
		}

		// Increment transfer count for successful processing
		eventCounts.Transfer++
	}

	// Process OrderCreated events
	orderCreatedEvents := []*types.OrderCreatedEvent{}

	for _, event := range gatewayEvents {
		eventMap := event.(map[string]interface{})
		decoded, ok := eventMap["decoded"].(map[string]interface{})
		if !ok || decoded == nil {
			continue
		}
		eventParams := decoded
		if eventParams["non_indexed_params"] == nil {
			continue
		}

		blockNumber := int64(eventMap["block_number"].(float64))
		txHash := eventMap["transaction_hash"].(string)

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
	}

	// Process OrderCreated events
	if len(orderCreatedEvents) > 0 {
		orderIds := []string{}
		orderIdToEvent := make(map[string]*types.OrderCreatedEvent)
		for _, event := range orderCreatedEvents {
			orderIds = append(orderIds, event.OrderId)
			orderIdToEvent[event.OrderId] = event
		}
		err = common.ProcessCreatedOrders(ctx, token.Edges.Network, orderIds, orderIdToEvent, s.order, s.priorityQueue)
		if err != nil {
			logger.Errorf("Failed to process OrderCreated events: %v", err)
		} else {
			if token.Edges.Network.ChainID != 56 {
				logger.Infof("Successfully processed %d OrderCreated events", len(orderCreatedEvents))
			}
		}
		eventCounts.OrderCreated = len(orderCreatedEvents)
	}

	return eventCounts, nil
}

// getAddressTransactionHistoryWithFallback tries etherscan first and falls back to engine
func (s *IndexerEVM) getAddressTransactionHistoryWithFallback(ctx context.Context, chainID int64, address string, limit int, fromBlock int64, toBlock int64) ([]map[string]interface{}, error) {
	var err error

	// Try etherscan first (except for Lisk which is not supported)
	if chainID != 1135 {
		transactions, err := s.etherscanService.GetAddressTransactionHistory(ctx, chainID, address, limit, fromBlock, toBlock)
		if err == nil {
			// Etherscan succeeded, return the transactions
			return transactions, nil
		}
		// Log the error but continue to fallback
		logger.Warnf("Etherscan failed for chain %d, falling back to Engine: %v", chainID, err)
	}

	// Try engine service as fallback
	// Note: Engine doesn't support chain ID 56 (BNB Smart Chain)
	if chainID != 56 {
		transactions, engineErr := s.engineService.GetAddressTransactionHistory(ctx, chainID, address, limit, fromBlock, toBlock)
		if engineErr != nil {
			logger.Errorf("Engine failed for chain %d: %v", chainID, engineErr)
			return nil, fmt.Errorf("both etherscan and engine failed - Etherscan: %w, Engine: %w", err, engineErr)
		}
		return transactions, nil
	}

	// For BSC (chain ID 56), only Etherscan is supported
	if chainID == 56 {
		return nil, fmt.Errorf("transaction history not supported for BNB Smart Chain (chain ID 56) via either etherscan or engine")
	}

	return nil, fmt.Errorf("transaction history not supported for Lisk (chain ID 1135) via either engine or etherscan")
}

// indexReceiveAddressByUserAddress processes user's transaction history for receive address transfers
func (s *IndexerEVM) indexReceiveAddressByUserAddress(ctx context.Context, token *ent.Token, userAddress string, fromBlock int64, toBlock int64) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}

	// Determine parameters based on whether block range is provided
	var limit int
	var logMessage string

	if fromBlock == 0 && toBlock == 0 {
		// No block range - get last 5 transactions
		limit = 5
		if token.Edges.Network.ChainID != 56 {
			logMessage = fmt.Sprintf("Processing transactions for address: %s", userAddress)
		}
	} else {
		// Block range provided - get up to 100 transactions in range
		limit = 100
		if token.Edges.Network.ChainID != 56 {
			logMessage = fmt.Sprintf("Processing transactions in block range %d-%d for address: %s", fromBlock, toBlock, userAddress)
		}
	}

	// Get address's transaction history with fallback
	transactions, err := s.getAddressTransactionHistoryWithFallback(ctx, token.Edges.Network.ChainID, userAddress, limit, fromBlock, toBlock)
	if err != nil {
		return eventCounts, fmt.Errorf("failed to get transaction history: %w", err)
	}

	if len(transactions) == 0 {
		if fromBlock == 0 && toBlock == 0 {
			logger.Infof("No transactions found for address: %s", userAddress)
		} else {
			logger.Infof("No transactions found in block range %d-%d for address: %s", fromBlock, toBlock, userAddress)
		}
		return eventCounts, nil
	}

	logger.Infof(logMessage)

	// Process each transaction to find transfer events to linked addresses
	for i, tx := range transactions {
		txHash := tx["hash"].(string)
		if token.Edges.Network.ChainID != 56 {
			logger.Infof("Processing transaction %d/%d: %s", i+1, len(transactions), txHash[:10]+"...")
		}

		// Index transfer events for this specific transaction
		counts, err := s.indexReceiveAddressByTransaction(ctx, token, txHash)
		if err != nil {
			logger.Errorf("Error processing transaction %s: %v", txHash[:10]+"...", err)
			continue // Skip transactions with errors
		}

		// Accumulate transfer counts
		eventCounts.Transfer += counts.Transfer
	}

	return eventCounts, nil
}

// IndexGateway indexes all gateway events (OrderCreated, OrderSettled, OrderRefunded) in one efficient call
func (s *IndexerEVM) IndexGateway(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}

	if txHash != "" {
		// Index gateway events for this specific transaction
		counts, err := s.indexGatewayByTransaction(ctx, network, txHash)
		if err != nil {
			logger.Errorf("Error processing gateway transaction %s: %v", txHash[:10]+"...", err)
			return eventCounts, err
		}
		return counts, nil
	}

	// Index gateway events for the contract address
	err := s.indexGatewayByContractAddress(ctx, network, address, fromBlock, toBlock)
	if err != nil {
		return eventCounts, err
	}

	return eventCounts, nil
}

// IndexProviderAddress indexes OrderSettled events for a provider address
func (s *IndexerEVM) IndexProviderAddress(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}

	if txHash != "" {
		// Index provider address events for this specific transaction
		counts, err := s.indexProviderAddressByTransaction(ctx, network, address, txHash)
		if err != nil {
			logger.Errorf("Error processing provider address transaction %s: %v", txHash[:10]+"...", err)
			return eventCounts, err
		}
		return counts, nil
	}

	// Index provider address events for the address
	err := s.indexProviderAddressByAddress(ctx, network, address, fromBlock, toBlock)
	if err != nil {
		return eventCounts, err
	}

	return eventCounts, nil
}

// indexGatewayByContractAddress processes gateway contract's transaction history for gateway events
func (s *IndexerEVM) indexGatewayByContractAddress(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64) error {
	// Determine parameters based on whether block range is provided
	var limit int
	var logMessage string

	if fromBlock == 0 && toBlock == 0 {
		limit = 10
		if network.ChainID != 56 {
			logMessage = fmt.Sprintf("Processing last %d transactions for gateway contract: %s", limit, address)
		}
	} else {
		// Block range provided - get up to 100 transactions in range
		limit = 100
		if network.ChainID != 56 {
			logMessage = fmt.Sprintf("Processing transactions in block range %d-%d for gateway contract: %s", fromBlock, toBlock, address)
		}
	}

	// Get gateway contract's transaction history with fallback
	transactions, err := s.getAddressTransactionHistoryWithFallback(ctx, network.ChainID, address, limit, fromBlock, toBlock)
	if err != nil {
		return fmt.Errorf("failed to get gateway transaction history: %w", err)
	}

	if len(transactions) == 0 {
		if fromBlock == 0 && toBlock == 0 {
			logger.Infof("No transactions found for gateway contract: %s", address)
		} else {
			logger.Infof("No transactions found in block range %d-%d for gateway contract: %s", fromBlock, toBlock, address)
		}
		return nil
	}

	logger.Infof(logMessage)

	// Process each transaction to find gateway events
	for i, tx := range transactions {
		txHash := tx["hash"].(string)
		if network.ChainID != 56 {
			logger.Infof("Processing gateway transaction %d/%d: %s", i+1, len(transactions), txHash[:10]+"...")
		}

		// Index gateway events for this specific transaction
		_, err := s.indexGatewayByTransaction(ctx, network, txHash)
		if err != nil {
			logger.Errorf("Error processing gateway transaction %s: %v", txHash[:10]+"...", err)
			continue // Skip transactions with errors
		}
	}

	return nil
}

// indexGatewayByTransaction processes a specific transaction for gateway events
func (s *IndexerEVM) indexGatewayByTransaction(ctx context.Context, network *ent.Network, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}

	// Use GetContractEventsWithFallback to try Thirdweb first and fall back to RPC
	eventPayload := map[string]string{
		"filter_transaction_hash": txHash,
		"sort_by":                 "block_number",
		"sort_order":              "desc",
		"decode":                  "true",
	}

	events, err := s.engineService.GetContractEventsWithFallback(
		ctx,
		network,
		network.GatewayContractAddress,
		0,
		0,
		[]string{}, // No specific topics filter
		txHash,
		eventPayload,
	)
	if err != nil {
		if err.Error() == "no events found" {
			return eventCounts, nil // No gateway events found for this transaction
		}
		return eventCounts, fmt.Errorf("error getting gateway events for transaction %s: %w", txHash[:10]+"...", err)
	}

	// Process all events in a single pass
	orderCreatedEvents := []*types.OrderCreatedEvent{}
	orderSettledEvents := []*types.OrderSettledEvent{}
	orderRefundedEvents := []*types.OrderRefundedEvent{}

	for _, event := range events {
		eventMap := event.(map[string]interface{})
		decoded, ok := eventMap["decoded"].(map[string]interface{})
		if !ok || decoded == nil {
			continue
		}
		eventParams := decoded
		if eventParams["non_indexed_params"] == nil {
			continue
		}

		// Get event name from the first topic (event signature)
		topicsInterface := eventMap["topics"]
		var eventSignature string

		// Handle both []string and []interface{} cases
		switch topics := topicsInterface.(type) {
		case []string:
			if len(topics) == 0 {
				continue
			}
			eventSignature = topics[0]
		case []interface{}:
			if len(topics) == 0 {
				continue
			}
			if topicStr, ok := topics[0].(string); ok {
				eventSignature = topicStr
			} else {
				continue
			}
		default:
			logger.Warnf("Unknown topics type: %T", topicsInterface)
			continue
		}

		if network.ChainID != 56 {
			// Log the event signature being processed
			logger.WithFields(logger.Fields{
				"EventSignature": eventSignature,
				"TxHash":         txHash,
				"BlockNumber":    int64(eventMap["block_number"].(float64)),
			}).Infof("Processing event signature")
		}

		blockNumber := int64(eventMap["block_number"].(float64))
		txHash := eventMap["transaction_hash"].(string)

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
		orderIds := []string{}
		orderIdToEvent := make(map[string]*types.OrderCreatedEvent)
		for _, event := range orderCreatedEvents {
			orderIds = append(orderIds, event.OrderId)
			orderIdToEvent[event.OrderId] = event
		}
		err = common.ProcessCreatedOrders(ctx, network, orderIds, orderIdToEvent, s.order, s.priorityQueue)
		if err != nil {
			logger.Errorf("Failed to process OrderCreated events: %v", err)
		} else {
			if network.ChainID != 56 {
				logger.Infof("Successfully processed %d OrderCreated events", len(orderCreatedEvents))
			}
		}
	}
	eventCounts.OrderCreated = len(orderCreatedEvents)

	// Process OrderSettled events
	if len(orderSettledEvents) > 0 {
		orderIds := []string{}
		orderIdToEvent := make(map[string]*types.OrderSettledEvent)
		for _, event := range orderSettledEvents {
			orderIds = append(orderIds, event.OrderId)
			orderIdToEvent[event.OrderId] = event
		}
		err = common.ProcessSettledOrders(ctx, network, orderIds, orderIdToEvent)
		if err != nil {
			logger.Errorf("Failed to process OrderSettled events: %v", err)
		} else {
			if network.ChainID != 56 {
				logger.Infof("Successfully processed %d OrderSettled events", len(orderSettledEvents))
			}
		}
	}
	eventCounts.OrderSettled = len(orderSettledEvents)

	// Process OrderRefunded events
	if len(orderRefundedEvents) > 0 {
		orderIds := []string{}
		orderIdToEvent := make(map[string]*types.OrderRefundedEvent)
		for _, event := range orderRefundedEvents {
			orderIds = append(orderIds, event.OrderId)
			orderIdToEvent[event.OrderId] = event
		}
		err = common.ProcessRefundedOrders(ctx, network, orderIds, orderIdToEvent)
		if err != nil {
			logger.Errorf("Failed to process OrderRefunded events: %v", err)
		} else {
			if network.ChainID != 56 {
				logger.Infof("Successfully processed %d OrderRefunded events", len(orderRefundedEvents))
			}
		}
	}
	eventCounts.OrderRefunded = len(orderRefundedEvents)

	return eventCounts, nil
}

// indexProviderAddressByTransaction processes a specific transaction for provider address OrderSettled events
func (s *IndexerEVM) indexProviderAddressByTransaction(ctx context.Context, network *ent.Network, providerAddress string, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}

	// Get OrderSettled events for this transaction
	events, err := s.engineService.GetContractEventsWithFallback(
		ctx,
		network,
		network.GatewayContractAddress,
		0,
		0,
		[]string{utils.OrderSettledEventSignature},
		txHash,
		map[string]string{
			"filter_transaction_hash": txHash,
			"sort_by":                 "block_number",
			"sort_order":              "desc",
			"decode":                  "true",
		},
	)
	if err != nil {
		if err.Error() == "no events found" {
			return eventCounts, nil // No OrderSettled events found for this transaction
		}
		return eventCounts, fmt.Errorf("error getting OrderSettled events for transaction %s: %w", txHash[:10]+"...", err)
	}

	// Process OrderSettled events for the specific provider address
	orderSettledEvents := []*types.OrderSettledEvent{}

	for _, event := range events {
		eventMap := event.(map[string]interface{})
		decoded, ok := eventMap["decoded"].(map[string]interface{})
		if !ok || decoded == nil {
			continue
		}
		eventParams := decoded
		if eventParams["non_indexed_params"] == nil {
			continue
		}

		// Check if this event is from the provider address we're looking for
		liquidityProvider := ethcommon.HexToAddress(eventParams["indexed_params"].(map[string]interface{})["liquidityProvider"].(string)).Hex()
		if !strings.EqualFold(liquidityProvider, providerAddress) {
			continue
		}

		blockNumber := int64(eventMap["block_number"].(float64))
		txHash := eventMap["transaction_hash"].(string)

		settlePercent, err := decimal.NewFromString(eventParams["non_indexed_params"].(map[string]interface{})["settlePercent"].(string))
		if err != nil {
			continue
		}

		settledEvent := &types.OrderSettledEvent{
			BlockNumber:       blockNumber,
			TxHash:            txHash,
			SplitOrderId:      eventParams["non_indexed_params"].(map[string]interface{})["splitOrderId"].(string),
			OrderId:           eventParams["indexed_params"].(map[string]interface{})["orderId"].(string),
			LiquidityProvider: liquidityProvider,
			SettlePercent:     settlePercent,
		}
		orderSettledEvents = append(orderSettledEvents, settledEvent)
	}

	// Process OrderSettled events
	if len(orderSettledEvents) > 0 {
		orderIds := []string{}
		orderIdToEvent := make(map[string]*types.OrderSettledEvent)
		for _, event := range orderSettledEvents {
			orderIds = append(orderIds, event.OrderId)
			orderIdToEvent[event.OrderId] = event
		}
		err = common.ProcessSettledOrders(ctx, network, orderIds, orderIdToEvent)
		if err != nil {
			logger.Errorf("Failed to process OrderSettled events: %v", err)
		} else {
			if network.ChainID != 56 {
				logger.Infof("Successfully processed %d OrderSettled events for provider %s", len(orderSettledEvents), providerAddress)
			}
		}
	}
	eventCounts.OrderSettled = len(orderSettledEvents)

	return eventCounts, nil
}

// indexProviderAddressByAddress processes provider address's transaction history for OrderSettled events
func (s *IndexerEVM) indexProviderAddressByAddress(ctx context.Context, network *ent.Network, providerAddress string, fromBlock int64, toBlock int64) error {
	// Determine parameters based on whether block range is provided
	var limit int
	var logMessage string

	if fromBlock == 0 && toBlock == 0 {
		limit = 20
		if network.ChainID != 56 {
			logMessage = fmt.Sprintf("Processing last %d transactions for provider address: %s", limit, providerAddress)
		}
	} else {
		// Block range provided - get up to 100 transactions in range
		limit = 100
		if network.ChainID != 56 {
			logMessage = fmt.Sprintf("Processing transactions in block range %d-%d for provider address: %s", fromBlock, toBlock, providerAddress)
		}
	}

	// Get provider address's transaction history with fallback
	transactions, err := s.getAddressTransactionHistoryWithFallback(ctx, network.ChainID, providerAddress, limit, fromBlock, toBlock)
	if err != nil {
		return fmt.Errorf("failed to get provider transaction history: %w", err)
	}

	if len(transactions) == 0 {
		if fromBlock == 0 && toBlock == 0 {
			logger.Infof("No transactions found for provider address: %s", providerAddress)
		} else {
			logger.Infof("No transactions found in block range %d-%d for provider address: %s", fromBlock, toBlock, providerAddress)
		}
		return nil
	}

	logger.Infof(logMessage)

	// Process each transaction to find OrderSettled events
	for i, tx := range transactions {
		txHash := tx["hash"].(string)
		if network.ChainID != 56 {
			logger.Infof("Processing provider transaction %d/%d: %s", i+1, len(transactions), txHash[:10]+"...")
		}

		// Index provider address events for this specific transaction
		_, err := s.indexProviderAddressByTransaction(ctx, network, providerAddress, txHash)
		if err != nil {
			logger.Errorf("Error processing provider transaction %s: %v", txHash[:10]+"...", err)
			continue // Skip transactions with errors
		}
	}

	return nil
}
