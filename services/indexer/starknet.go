package indexer

import (
	"context"
	"fmt"
	"strings"

	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/services/order"
	starknetService "github.com/paycrest/aggregator/services/starknet"
	"github.com/paycrest/aggregator/types"
	u "github.com/paycrest/aggregator/utils"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

// IndexerStarknet performs blockchain to database extract, transform, load (ETL) operations for Starknet
type IndexerStarknet struct {
	priorityQueue  *services.PriorityQueueService
	order          types.OrderService
	voyagerService *services.VoyagerService
}

// NewIndexerStarknet creates a new instance of IndexerStarknet
func NewIndexerStarknet() (types.Indexer, error) {
	// Create RPC client for order service (write operations)
	client, err := starknetService.NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create starknet client: %w", err)
	}
	orderService := order.NewOrderStarknet(client)

	// Create Voyager service for read operations (with RPC fallback)
	voyagerService, err := services.NewVoyagerService()
	if err != nil {
		return nil, fmt.Errorf("failed to create Voyager service: %w", err)
	}

	priorityQueue := services.NewPriorityQueueService()

	return &IndexerStarknet{
		priorityQueue:  priorityQueue,
		order:          orderService,
		voyagerService: voyagerService,
	}, nil
}

// IndexReceiveAddress indexes transfer events to receive addresses
func (s *IndexerStarknet) IndexReceiveAddress(ctx context.Context, token *ent.Token, userAccountAddress string, fromBlock int64, toBlock int64, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}
	var transactionHashReceipt []map[string]interface{}

	// Determine chunk size based on whether block range is provided
	var ChunkSize int
	if fromBlock == 0 && toBlock == 0 {
		// No block range - get last 10 transactions
		ChunkSize = 10
	} else {
		// Block range provided - get up to 100 transactions in range
		ChunkSize = 100
	}

	if txHash != "" {
		// Process specific transaction
		rpcTransactionHashReceipt, err := s.voyagerService.GetEventsByTransactionHashImmediate(ctx, txHash, ChunkSize)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to index receive address by transaction: %w", err)
		}
		// Transform RPC events to transfer format for processing
		for _, event := range rpcTransactionHashReceipt {
			transferEvent := s.transformRPCEventToTransferFormat(event)
			if transferEvent != nil {
				transactionHashReceipt = append(transactionHashReceipt, transferEvent)
			}
		}
	}

	if len(transactionHashReceipt) == 0 && txHash == "" {
		// Use Voyager service to get token transfers (handles RPC fallback internally)
		transfers, err := s.voyagerService.GetAddressTokenTransfers(ctx, token.ContractAddress, ChunkSize, fromBlock, toBlock, "", userAccountAddress)
		if err != nil {
			logger.WithFields(logger.Fields{
				"error":       fmt.Sprintf("%v", err),
				"Token":       token.Symbol,
				"UserAddress": userAccountAddress,
			}).Error("Failed to get token transfers for token")
			return eventCounts, fmt.Errorf("failed to get token transfers for token %s: %w", token.Symbol, err)
		}
		for _, transfer := range transfers {
			// Check if transformation is needed
			var processedTransfer map[string]interface{}
			if needsTransform, ok := transfer["needs_transformation"].(bool); ok && needsTransform {
				// Data from Voyager API, needs transformation
				processedTransfer = s.transformVoyagerTransferToRPCFormat(transfer)
				if processedTransfer == nil {
					logger.WithFields(logger.Fields{
						"Token":       token.Symbol,
						"UserAddress": userAccountAddress,
					}).Error("Failed to transform Voyager transfer to RPC format")
					continue
				}
			} else {
				// Data from RPC fallback, already in correct format
				processedTransfer = transfer
			}
			transactionHashReceipt = append(transactionHashReceipt, processedTransfer)
		}

	}

	if len(transactionHashReceipt) == 0 {
		logger.Infof("No transactions found in block range %d-%d for address: %s", fromBlock, toBlock, userAccountAddress)
		return eventCounts, nil
	}

	transferEventCount, err := s.processReceiveAddressByTransactionEvents(ctx, token, transactionHashReceipt, userAccountAddress)
	if err != nil {
		logger.WithFields(logger.Fields{
			"error":       fmt.Sprintf("%v", err),
			"Token":       token.Symbol,
			"UserAddress": userAccountAddress,
		}).Error("Failed to process receive address by transaction events")
		return eventCounts, fmt.Errorf("failed to index receive address by transaction: %w", err)
	}

	logger.WithFields(logger.Fields{
		"Token":         token.Symbol,
		"UserAddress":   userAccountAddress,
		"TransferCount": transferEventCount.Transfer,
	}).Infof("Processed transfer events for receive address")

	eventCounts.Transfer += transferEventCount.Transfer

	counts, err := s.IndexGateway(ctx, token.Edges.Network, token.Edges.Network.GatewayContractAddress, fromBlock, toBlock, "")
	if err != nil {
		return eventCounts, fmt.Errorf("failed to index gateway events: %w", err)
	}
	eventCounts.OrderCreated += counts.OrderCreated

	return eventCounts, nil
}

// processReceiveAddressByTransactionEvents processes a specific transaction for receive address transfers
func (s *IndexerStarknet) processReceiveAddressByTransactionEvents(ctx context.Context, token *ent.Token, transferEvents []map[string]interface{}, userAccountAddress string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}
	if len(transferEvents) == 0 {
		return eventCounts, nil
	}

	// Process transfer events
	for _, eventMap := range transferEvents {
		decoded, ok := eventMap["decoded"].(map[string]interface{})
		if !ok || decoded == nil {
			logger.Errorf("Missing or invalid 'decoded' field in transfer event")
			continue
		}
		nonIndexedParams, ok := decoded["non_indexed_params"].(map[string]interface{})
		if !ok || nonIndexedParams == nil {
			logger.Errorf("Missing or invalid 'non_indexed_params' in transfer event")
			continue
		}

		// Safely extract transfer data *big.Int, and string types
		var fromStr string
		if strVal, ok := nonIndexedParams["from"].(string); ok {
			fromStr = strVal
		} else {
			logger.Errorf("Unexpected type for 'from' parameter in transfer event")
			continue
		}
		if fromStr == "" {
			logger.Errorf("Empty 'from' parameter in transfer event")
			continue
		}

		var toStr string
		if strVal, ok := nonIndexedParams["to"].(string); ok {
			toStr = strVal
		} else {
			logger.Errorf("Unexpected type for 'to' parameter in transfer event")
			continue
		}
		if toStr == "" {
			logger.Errorf("Empty 'to' parameter in transfer event")
			continue
		}

		logger.WithFields(logger.Fields{
			"fromStr": fromStr,
			"toStr":   toStr,
		}).Infof("Extracted transfer event addresses")

		var valueStr string
		if strVal, ok := nonIndexedParams["value"].(string); ok {
			valueStr = strVal
		} else {
			logger.Errorf("Unexpected type for 'value' parameter in transfer event")
			continue
		}
		if valueStr == "" {
			logger.Errorf("Empty 'value' parameter in transfer event")
			continue
		}

		// Filter by userAccountAddress - only process transfers to the specified address
		if userAccountAddress != "" && !strings.EqualFold(cryptoUtils.NormalizeStarknetAddress(toStr), cryptoUtils.NormalizeStarknetAddress(userAccountAddress)) {
			logger.WithFields(logger.Fields{
				"toStr":              cryptoUtils.NormalizeStarknetAddress(toStr),
				"userAccountAddress": cryptoUtils.NormalizeStarknetAddress(userAccountAddress),
			}).Infof("Skipping transfer event - 'to' address does not match user account address")
			continue
		}

		// Skip if transfer is from gateway contract
		if strings.EqualFold(cryptoUtils.NormalizeStarknetAddress(fromStr), cryptoUtils.NormalizeStarknetAddress(token.Edges.Network.GatewayContractAddress)) {
			logger.WithFields(logger.Fields{
				"fromStr":                cryptoUtils.NormalizeStarknetAddress(fromStr),
				"GatewayContractAddress": cryptoUtils.NormalizeStarknetAddress(token.Edges.Network.GatewayContractAddress),
			}).Infof("Skipping transfer event - 'from' address is gateway contract")
			continue
		}

		// Parse transfer value
		transferValue, err := decimal.NewFromString(valueStr)
		if err != nil {
			logger.Errorf("Error parsing transfer value for token %s: %v", token.Symbol, err)
			continue
		}

		// Safely extract block_number and transaction_hash
		blockNumberFloat, ok := eventMap["block_number"].(float64)
		if !ok {
			logger.Errorf("Missing or invalid 'block_number' in transfer event")
			continue
		}
		blockNumber := int64(blockNumberFloat)
		txHashFromEvent, ok := eventMap["transaction_hash"].(string)
		if !ok || txHashFromEvent == "" {
			logger.Errorf("Missing or invalid 'transaction_hash' in transfer event")
			continue
		}

		// Create transfer event
		transferEvent := &types.TokenTransferEvent{
			BlockNumber: blockNumber,
			TxHash:      txHashFromEvent,
			From:        fromStr,
			To:          toStr,
			Value:       transferValue.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(token.Decimals)))),
		}

		// Process transfer using existing logic
		addressToEvent := map[string]*types.TokenTransferEvent{
			toStr: transferEvent,
		}
		logger.WithFields(logger.Fields{
			"Token":        token.Symbol,
			"UserAddress":  userAccountAddress,
			"ToAddress":    toStr,
			"From":         fromStr,
			"ValueStr":     valueStr,
			"ValueDecimal": transferEvent.Value.String(),
			"BlockNumber":  blockNumber,
			"TxHash":       txHashFromEvent[:10] + "...",
		}).Infof("Processing transfer event")

		err = common.ProcessTransfers(ctx, s.order, s.priorityQueue, []string{toStr}, addressToEvent)
		if err != nil {
			logger.Errorf("Error processing transfer for token %s: %v", token.Symbol, err)
			continue
		}

		// Increment transfer count for successful processing
		eventCounts.Transfer++
	}

	return eventCounts, nil
}

func (s *IndexerStarknet) indexGatewayByTransaction(ctx context.Context, network *ent.Network, gatewayContractTransactions []map[string]interface{}) (*types.EventCounts, error) {
	// Find OrderCreated events for this transaction
	eventCounts := &types.EventCounts{}

	if len(gatewayContractTransactions) == 0 {
		return eventCounts, nil
	}

	// Process all events in a single pass
	orderCreatedEvents := []*types.OrderCreatedEvent{}
	orderSettledEvents := []*types.OrderSettledEvent{}
	orderRefundedEvents := []*types.OrderRefundedEvent{}

	for _, eventMap := range gatewayContractTransactions {
		decoded, ok := eventMap["decoded"].(map[string]interface{})
		if !ok || decoded == nil {
			logger.Errorf("Missing or invalid 'decoded' field in gateway event")
			continue
		}
		eventParams := decoded

		// Convert eventSignature from *felt.Felt to hex string for comparison
		eventSignature, ok := eventMap["topics"].(string)
		if !ok {
			logger.Errorf("Missing or invalid 'topics' field in gateway event")
			continue
		}

		// Safely extract block_number and transaction_hash
		blockNumberFloat, ok := eventMap["block_number"].(float64)
		if !ok {
			logger.Errorf("Missing or invalid 'block_number' in gateway event")
			continue
		}

		blockNumber := int64(blockNumberFloat)

		txHashFromEvent, ok := eventMap["transaction_hash"].(string)
		if !ok || txHashFromEvent == "" {
			continue
		}

		switch eventSignature {
		case u.OrderCreatedStarknetSelector:
			indexedParams, ok := eventParams["indexed_params"].(map[string]interface{})
			if !ok || indexedParams == nil {
				logger.Errorf("Missing or invalid 'indexed_params' in OrderCreated event")
				continue
			}
			orderAmount, ok := indexedParams["amount"].(decimal.Decimal)
			if !ok {
				logger.Infof("CreateOrder-Gateway, Unable to decode amount")
				continue
			}

			// Extract sender (string)
			senderStr, ok := indexedParams["sender"].(string)
			if !ok || senderStr == "" {
				logger.Infof("CreateOrder-Gateway, Unable to decode sender")
				continue
			}

			tokenStr, ok := indexedParams["token"].(string)
			if !ok || tokenStr == "" {
				logger.Infof("CreateOrder-Gateway, Unable to decode token")
				continue
			}

			nonIndexedParams, ok := eventParams["non_indexed_params"].(map[string]interface{})
			if !ok || nonIndexedParams == nil {
				logger.Errorf("Missing or invalid 'non_indexed_params' in OrderCreated event")
				continue
			}

			protocolFee, ok := nonIndexedParams["protocol_fee"].(decimal.Decimal)
			if !ok {
				logger.Infof("CreateOrder-Gateway, Unable to decode protocol_fee")
				continue
			}

			rate, ok := nonIndexedParams["rate"].(decimal.Decimal)
			if !ok || rate.IsZero() {
				continue
			}

			orderIDStr, ok := nonIndexedParams["order_id"].(string)
			if !ok || orderIDStr == "" {
				logger.Infof("CreateOrder-Gateway, Unable to decode order_id")
				continue
			}

			// Extract messageHash (string)
			messageHashStr, ok := nonIndexedParams["message_hash"].(string)
			if !ok || messageHashStr == "" {
				logger.Infof("CreateOrder-Gateway, Unable to decode message_hash")
				continue
			}

			createdEvent := &types.OrderCreatedEvent{
				BlockNumber: blockNumber,
				TxHash:      txHashFromEvent,
				Token:       tokenStr, // Use Starknet address directly
				Amount:      orderAmount,
				ProtocolFee: protocolFee,
				OrderId:     orderIDStr,
				Rate:        rate.Div(decimal.NewFromInt(100)),
				MessageHash: messageHashStr,
				Sender:      senderStr, // Use Starknet address directly
			}
			orderCreatedEvents = append(orderCreatedEvents, createdEvent)

		case u.OrderSettledStarknetSelector:
			nonIndexedParams, ok := eventParams["non_indexed_params"].(map[string]interface{})
			if !ok || nonIndexedParams == nil {
				logger.Errorf("Missing or invalid 'non_indexed_params' in OrderSettled event")
				continue
			}
			settlePercent, ok := nonIndexedParams["settle_percent"].(decimal.Decimal)
			if !ok {
				logger.Errorf("Missing or invalid 'settle_percent' in OrderSettled event")
				continue
			}

			// Extract rebatePercent (uint64)
			rebatePercent, ok := nonIndexedParams["rebate_percent"].(decimal.Decimal)
			if !ok {
				logger.Errorf("Missing or invalid 'rebate_percent' in OrderSettled event")
				continue
			}
			// Extract splitOrderId (felt.Felt -> hex string)
			splitOrderIDStr, ok := nonIndexedParams["split_order_id"].(string)
			if !ok || splitOrderIDStr == "" {
				logger.Errorf("Missing or invalid 'split_order_id' in OrderSettled event")
				continue
			}

			indexedParams, ok := eventParams["indexed_params"].(map[string]interface{})
			if !ok || indexedParams == nil {
				logger.Errorf("Missing or invalid 'indexed_params' in OrderSettled event")
				continue
			}

			// Extract orderId (felt.Felt -> hex string)
			orderIDStr, ok := indexedParams["order_id"].(string)
			if !ok || orderIDStr == "" {
				continue
			}

			// Extract liquidityProvider (felt.Felt -> hex string)
			liquidityProviderStr, ok := indexedParams["liquidity_provider"].(string)
			if !ok || liquidityProviderStr == "" {
				continue
			}

			settledEvent := &types.OrderSettledEvent{
				BlockNumber:       blockNumber,
				TxHash:            txHashFromEvent,
				SplitOrderId:      splitOrderIDStr,
				OrderId:           orderIDStr,
				LiquidityProvider: liquidityProviderStr, // Use Starknet address directly
				SettlePercent:     settlePercent,
				RebatePercent:     rebatePercent,
			}
			orderSettledEvents = append(orderSettledEvents, settledEvent)

		case u.OrderRefundedStarknetSelector:
			nonIndexedParams, ok := eventParams["non_indexed_params"].(map[string]interface{})
			if !ok || nonIndexedParams == nil {
				logger.Errorf("Missing or invalid 'non_indexed_params' in OrderRefunded event")
				continue
			}
			// Extract fee (big.Int)
			fee, ok := nonIndexedParams["fee"].(decimal.Decimal)
			if !ok {
				continue
			}

			indexedParams, ok := eventParams["indexed_params"].(map[string]interface{})
			if !ok || indexedParams == nil {
				logger.Errorf("Missing or invalid 'indexed_params' in OrderRefunded event")
				continue
			}

			// Extract orderId (felt.Felt -> hex string)
			orderIDStr, ok := indexedParams["order_id"].(string)
			if !ok || orderIDStr == "" {
				continue
			}

			refundedEvent := &types.OrderRefundedEvent{
				BlockNumber: blockNumber,
				TxHash:      txHashFromEvent,
				OrderId:     orderIDStr,
				Fee:         fee,
			}
			orderRefundedEvents = append(orderRefundedEvents, refundedEvent)
		}
	}

	// Process OrderCreated events
	if len(orderCreatedEvents) > 0 {
		orderIDs := []string{}
		logger.Infof("Create order event found!!")
		orderIDToEvent := make(map[string]*types.OrderCreatedEvent)
		for _, event := range orderCreatedEvents {
			orderIDs = append(orderIDs, event.OrderId)
			orderIDToEvent[event.OrderId] = event
		}
		err := common.ProcessCreatedOrders(ctx, network, orderIDs, orderIDToEvent, s.order, s.priorityQueue)
		if err != nil {
			logger.Errorf("Failed to process OrderCreated events: %v", err)
		} else {
			if network.ChainID != 56 && network.ChainID != 1135 {
				logger.Infof("Successfully processed %d OrderCreated events", len(orderCreatedEvents))
			}
		}
	}
	eventCounts.OrderCreated = len(orderCreatedEvents)

	// Process OrderSettled events
	if len(orderSettledEvents) > 0 {
		orderIDs := []string{}
		orderIDToEvent := make(map[string]*types.OrderSettledEvent)
		for _, event := range orderSettledEvents {
			orderIDs = append(orderIDs, event.OrderId)
			orderIDToEvent[event.OrderId] = event
		}
		err := common.ProcessSettledOrders(ctx, network, orderIDs, orderIDToEvent)
		if err != nil {
			logger.Errorf("Failed to process OrderSettled events: %v", err)
		} else {
			if network.ChainID != 56 && network.ChainID != 1135 {
				logger.Infof("Successfully processed %d OrderSettled events", len(orderSettledEvents))
			}
		}
	}
	eventCounts.OrderSettled = len(orderSettledEvents)

	// Process OrderRefunded events
	if len(orderRefundedEvents) > 0 {
		orderIDs := []string{}
		orderIDToEvent := make(map[string]*types.OrderRefundedEvent)
		for _, event := range orderRefundedEvents {
			orderIDs = append(orderIDs, event.OrderId)
			orderIDToEvent[event.OrderId] = event
		}
		err := common.ProcessRefundedOrders(ctx, network, orderIDs, orderIDToEvent)
		if err != nil {
			logger.Errorf("Failed to process OrderRefunded events: %v", err)
		} else {
			if network.ChainID != 56 && network.ChainID != 1135 {
				logger.Infof("Successfully processed %d OrderRefunded events", len(orderRefundedEvents))
			}
		}
	}
	eventCounts.OrderRefunded = len(orderRefundedEvents)

	return eventCounts, nil
}

// IndexGateway indexes all gateway events (OrderCreated, OrderSettled, OrderRefunded)
func (s *IndexerStarknet) IndexGateway(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}
	var transactionHashReceipt []map[string]interface{}
	var allEvents []map[string]interface{}

	// Determine limit based on whether block range is provided
	var limit int
	if fromBlock == 0 && toBlock == 0 {
		// No block range - get last 10 events
		limit = 10
	} else {
		// Block range provided - get up to 100 events in range
		limit = 100
	}

	if txHash != "" {
		events, err := s.voyagerService.GetEventsByTransactionHashImmediate(ctx, txHash, limit)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to get transaction receipt: %w", err)
		}
		allEvents = append(allEvents, events...)
	}

	if len(transactionHashReceipt) == 0 && txHash == "" {
		// Use Voyager service to get gateway events (handles RPC fallback internally)
		events, err := s.voyagerService.GetContractEvents(ctx, address, limit, fromBlock, toBlock)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to get gateway events: %w", err)
		}
		allEvents = append(allEvents, events...)
	}

	if len(allEvents) == 0 {
		logger.Infof("No gateway events found for address: %s", address)
		return eventCounts, nil
	}

	for _, event := range allEvents {
		// Check if transformation is needed
		var processedEvent map[string]interface{}
		if needsTransform, ok := event["needs_transformation"].(bool); ok && needsTransform {
			// Data from Voyager API, needs transformation
			var err error
			processedEvent, err = s.transformVoyagerEventToRPCFormat(event)
			if err != nil {
				logger.Errorf("Failed to transform Gateway Voyager event to RPC format: %v", err)
				continue
			}
		} else {
			// Data from RPC fallback, already in correct format
			processedEvent = event
		}
		transactionHashReceipt = append(transactionHashReceipt, processedEvent)
	}

	if len(transactionHashReceipt) > 0 {
		eventsCounts, err := s.indexGatewayByTransaction(ctx, network, transactionHashReceipt)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to index gateway by transaction: %w", err)
		}
		eventCounts.OrderCreated += eventsCounts.OrderCreated
		eventCounts.OrderSettled += eventsCounts.OrderSettled
		eventCounts.OrderRefunded += eventsCounts.OrderRefunded
	}

	return eventCounts, nil
}

// IndexProviderAddress indexes settlement events from providers
func (s *IndexerStarknet) IndexProviderAddress(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}
	var transactionHashReceipt []map[string]interface{}
	var allEvents []map[string]interface{}

	// Determine limit based on whether block range is provided
	var limit int
	if fromBlock == 0 && toBlock == 0 {
		// No block range - get last 20 transfers
		limit = 10
	} else {
		// Block range provided - get up to 100 transfers in range
		limit = 100
	}

	if txHash != "" {
		// Index provider address events for this specific transaction
		events, err := s.voyagerService.GetEventsByTransactionHashImmediate(ctx, txHash, limit)
		if err != nil {
			logger.Errorf("Error processing provider address transaction %s: %v", txHash[:10]+"...", err)
			return eventCounts, err
		}
		allEvents = append(allEvents, events...)
	}

	if len(transactionHashReceipt) == 0 && txHash == "" {
		// Use Voyager transfers endpoint with from filter to get transfers from gateway to provider
		// This directly returns transfers from gateway contract to provider address
		transfers, err := s.voyagerService.GetAddressTokenTransfers(ctx, "", limit, fromBlock, toBlock, network.GatewayContractAddress, address)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to get provider transfers: %w", err)
		}
		for _, transfer := range transfers {
			txHash, _ := transfer["txHash"].(string)
			if txHash != "" {
				eventsByTx, err := s.voyagerService.GetEventsByTransactionHashImmediate(ctx, txHash, limit)
				if err != nil {
					logger.WithFields(logger.Fields{
						"provider": address,
						"txHash":   txHash,
						"error":    fmt.Sprintf("%v", err),
					}).Error("Failed to get provider transfer transaction receipt by hash")
					continue
				}
				allEvents = append(allEvents, eventsByTx...)
			}
		}
	}

	if len(allEvents) == 0 {
		logger.Infof("No provider transfer events found for address: %s", address)
		return eventCounts, nil
	}

	for _, event := range allEvents {
		// Check if transformation is needed
		var processedEvent map[string]interface{}
		if needsTransform, ok := event["needs_transformation"].(bool); ok && needsTransform {
			// Data from Voyager API, needs transformation
			var err error
			processedEvent, err = s.transformVoyagerEventToRPCFormat(event)
			if err != nil {
				logger.WithFields(logger.Fields{
					"provider": address,
					"error":    fmt.Sprintf("%v", err),
				}).Error("Failed to transform Provider Voyager event to RPC format")
				continue
			}
		} else {
			// Data from RPC fallback, already in correct format
			processedEvent = event
		}
		transactionHashReceipt = append(transactionHashReceipt, processedEvent)
	}

	if len(transactionHashReceipt) > 0 {
		eventsCounts, err := s.indexProviderAddressByTransaction(ctx, network, address, transactionHashReceipt)
		if err != nil {
			logger.WithFields(logger.Fields{
				"provider": address,
				"txHash":   txHash,
				"error":    fmt.Sprintf("%v", err),
			}).Error("Failed to index provider transfer transaction by hash")
			return eventCounts, err
		}
		eventCounts.OrderSettled += eventsCounts.OrderSettled
	}

	return eventCounts, nil
}

// indexProviderAddressByTransaction processes a specific transaction for provider address OrderSettled events
func (s *IndexerStarknet) indexProviderAddressByTransaction(ctx context.Context, network *ent.Network, providerAddress string, settledEvents []map[string]interface{}) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}
	if len(settledEvents) == 0 {
		return eventCounts, nil
	}
	// Process OrderSettled events for the specific provider address
	orderSettledEvents := []*types.OrderSettledEvent{}

	for _, eventMap := range settledEvents {
		topics, ok := eventMap["topics"].(string)
		if !ok {
			continue
		}
		if topics != u.OrderSettledStarknetSelector {
			continue
		}
		decoded, ok := eventMap["decoded"].(map[string]interface{})
		if !ok || decoded == nil {
			continue
		}
		eventParams := decoded
		if eventParams["non_indexed_params"] == nil {
			continue
		}

		// Check if indexed_params exists and is not nil before accessing it
		indexedParams, ok := eventParams["indexed_params"].(map[string]interface{})
		if !ok || indexedParams == nil {
			continue
		}

		// Check if this event is from the provider address we're looking for
		liquidityProvider, ok := indexedParams["liquidity_provider"].(string)
		if !ok || liquidityProvider == "" {
			continue
		}

		if !strings.EqualFold(cryptoUtils.NormalizeStarknetAddress(liquidityProvider), cryptoUtils.NormalizeStarknetAddress(providerAddress)) {
			continue
		}

		// Safely extract block_number and transaction_hash
		blockNumberFloat, ok := eventMap["block_number"].(float64)
		if !ok {
			continue
		}
		blockNumber := int64(blockNumberFloat)

		txHash, ok := eventMap["transaction_hash"].(string)
		if !ok || txHash == "" {
			continue
		}

		// Safely extract non_indexed_params
		nonIndexedParams, ok := eventParams["non_indexed_params"].(map[string]interface{})
		if !ok || nonIndexedParams == nil {
			continue
		}

		// Safely extract required fields
		settlePercent, ok := nonIndexedParams["settle_percent"].(decimal.Decimal)
		if !ok {
			continue
		}

		rebatePercent, ok := nonIndexedParams["rebate_percent"].(decimal.Decimal)
		if !ok {
			continue
		}

		splitOrderId, ok := nonIndexedParams["split_order_id"].(string)
		if !ok || splitOrderId == "" {
			continue
		}

		orderId, ok := indexedParams["order_id"].(string)
		if !ok || orderId == "" {
			continue
		}

		settledEvent := &types.OrderSettledEvent{
			BlockNumber:       blockNumber,
			TxHash:            txHash,
			SplitOrderId:      splitOrderId,
			OrderId:           orderId,
			LiquidityProvider: liquidityProvider,
			SettlePercent:     settlePercent,
			RebatePercent:     rebatePercent,
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
		err := common.ProcessSettledOrders(ctx, network, orderIds, orderIdToEvent)
		if err != nil {
			logger.Errorf("Failed to process OrderSettled events: %v", err)
		} else {
			if network.ChainID != 56 && network.ChainID != 1135 {
				logger.Infof("Successfully processed %d OrderSettled events for provider %s", len(orderSettledEvents), providerAddress)
			}
		}
	}
	eventCounts.OrderSettled = len(orderSettledEvents)

	return eventCounts, nil
}

// transformVoyagerTransferToRPCFormat converts Transfer event in Voyager format to RPC event format
func (s *IndexerStarknet) transformVoyagerTransferToRPCFormat(transfer map[string]interface{}) map[string]interface{} {
	// Voyager format: txHash, transferFrom, transferTo, blockNumber, transferValue, etc.
	// RPC format: transaction_hash, block_number, decoded.non_indexed_params (from, to, value)
	txHash, _ := transfer["txHash"].(string)
	blockNumber, _ := transfer["blockNumber"].(float64)
	transferFrom, _ := transfer["transferFrom"].(string)
	transferTo, _ := transfer["transferTo"].(string)
	transferValue, _ := transfer["transferValue"].(string)
	tokenDecimals, _ := transfer["tokenDecimals"].(float64)

	if tokenDecimals <= 0 {
		logger.WithFields(logger.Fields{
			"TxHash":        txHash,
			"TokenDecimals": tokenDecimals,
		}).Warnf("token decimals must be greater than zero to process transfer value")
		return nil
	}
	if transferValue == "" {
		logger.WithFields(logger.Fields{
			"TxHash": txHash,
		}).Warnf("transfer value is empty")
		return nil
	}
	decimalValue, err := decimal.NewFromString(transferValue)
	if err != nil {
		logger.WithFields(logger.Fields{
			"TxHash":        txHash,
			"TransferValue": transferValue,
			"Error":         err.Error(),
		}).Warnf("invalid transfer value format")
		return nil
	}
	rawValueDecimals := u.ToSubunit(decimalValue, int8(tokenDecimals))

	logger.WithFields(logger.Fields{
		"TxHash":      txHash,
		"BlockNumber": blockNumber,
		"From":        cryptoUtils.NormalizeStarknetAddress(transferFrom),
		"To":          cryptoUtils.NormalizeStarknetAddress(transferTo),
		"Value":       rawValueDecimals.String(),
	}).Infof("Transforming Voyager transfer to RPC format")

	// Create RPC-formatted event
	rpcEvent := map[string]interface{}{
		"transaction_hash": txHash,
		"block_number":     blockNumber,
		"topics":           u.TransferStarknetSelector,
		"decoded": map[string]interface{}{
			"non_indexed_params": map[string]interface{}{
				"from":  cryptoUtils.NormalizeStarknetAddress(transferFrom),
				"to":    cryptoUtils.NormalizeStarknetAddress(transferTo),
				"value": rawValueDecimals.String(),
			},
			"indexed_params": map[string]interface{}{},
		},
	}

	return rpcEvent
}

// transformVoyagerEventToRPCFormat converts a Gateway event in Voyagerformat to RPC event format
func (s *IndexerStarknet) transformVoyagerEventToRPCFormat(event map[string]interface{}) (map[string]interface{}, error) {
	// Voyager format: transactionHash, blockNumber, name, dataDecoded, keyDecoded, fromAddress
	// RPC format: transaction_hash, block_number, decoded.indexed_params, decoded.non_indexed_params

	transactionHash, _ := event["transactionHash"].(string)
	blockNumber, _ := event["blockNumber"].(float64)
	name, _ := event["name"].(string)
	dataDecoded, _ := event["dataDecoded"].([]interface{})
	keyDecoded, _ := event["keyDecoded"].([]interface{})
	fromAddress, _ := event["fromAddress"].(string)
	keys, _ := event["keys"].([]interface{})

	if len(keys) == 0 {
		return nil, fmt.Errorf("event has no keys")
	}

	indexedParams := make(map[string]interface{})
	nonIndexedParams := make(map[string]interface{})
	// Key is expected to be a string
	topics, ok := keys[0].(string)
	if !ok {
		return nil, fmt.Errorf("failed to assert keys[0] as string")
	}

	switch topics {
	case u.OrderCreatedStarknetSelector:
		for _, keyItem := range keyDecoded {
			if keyMap, ok := keyItem.(map[string]interface{}); ok {
				keyName, _ := keyMap["name"].(string)
				keyValue := keyMap["value"]
				switch keyName {
				case "sender", "token":
					indexedParams[keyName] = keyValue
				case "amount":
					orderAmount, err := u.ParseStringAsDecimals(keyValue.(string))
					if err != nil {
						return nil, fmt.Errorf("failed to parse order amount: %v", err)
					}
					indexedParams[keyName] = orderAmount
				default:
					indexedParams[keyName] = keyValue
				}
			}
		}

		for _, dataItem := range dataDecoded {
			if dataMap, ok := dataItem.(map[string]interface{}); ok {
				dataName, _ := dataMap["name"].(string)
				dataValue := dataMap["value"]
				dataType, _ := dataMap["type"].(string)

				switch dataName {
				case "protocol_fee", "rate":
					valueDecimals, err := u.ParseStringAsDecimals(dataValue.(string))
					if err != nil {
						return nil, fmt.Errorf("failed to parse %s: %v", dataName, err)
					}
					nonIndexedParams[dataName] = valueDecimals
				case "order_id":
					nonIndexedParams[dataName] = dataValue
				case "message_hash":
					// Handle ByteArray type specially
					if dataType == "core::byte_array::ByteArray" {
						if byteArrayMap, ok := dataValue.(map[string]interface{}); ok {
							messageHash, err := u.ParseByteArrayFromJSON(byteArrayMap)
							if err != nil {
								nonIndexedParams[dataName] = dataValue
							} else {
								nonIndexedParams[dataName] = messageHash
							}
						} else {
							nonIndexedParams[dataName] = dataValue
						}
					} else {
						nonIndexedParams[dataName] = dataValue
					}
				}
			}
		}

	case u.OrderSettledStarknetSelector:
		for _, keyItem := range keyDecoded {
			if keyMap, ok := keyItem.(map[string]interface{}); ok {
				keyName, _ := keyMap["name"].(string)
				keyValue, _ := keyMap["value"].(string)
				indexedParams[keyName] = keyValue
			}
		}

		for _, dataItem := range dataDecoded {
			if dataMap, ok := dataItem.(map[string]interface{}); ok {
				dataName, _ := dataMap["name"].(string)
				dataValue := dataMap["value"]
				switch dataName {
				case "split_order_id":
					nonIndexedParams[dataName] = dataValue
				case "settle_percent", "rebate_percent":
					percentValue, err := u.ParseStringAsDecimals(dataValue.(string))
					if err != nil {
						return nil, fmt.Errorf("failed to parse %s: %v", dataName, err)
					}
					nonIndexedParams[dataName] = percentValue
				default:
					nonIndexedParams[dataName] = dataValue
				}
			}
		}

	case u.OrderRefundedStarknetSelector:
		for _, keyItem := range keyDecoded {
			if keyMap, ok := keyItem.(map[string]interface{}); ok {
				keyName, _ := keyMap["name"].(string)
				keyValue, _ := keyMap["value"].(string)
				indexedParams[keyName] = keyValue
			}
		}

		for _, dataItem := range dataDecoded {
			if dataMap, ok := dataItem.(map[string]interface{}); ok {
				dataName, _ := dataMap["name"].(string)
				dataValue, _ := dataMap["value"].(string)
				feeValue, err := u.ParseStringAsDecimals(dataValue)
				if err != nil {
					return nil, fmt.Errorf("failed to parse %s: %v", dataName, err)
				}
				nonIndexedParams[dataName] = feeValue
			}
		}

	}

	// Create RPC-formatted event
	rpcEvent := map[string]interface{}{
		"transaction_hash": transactionHash,
		"block_number":     blockNumber,
		"name":             name,
		"topics":           topics,
		"address":          cryptoUtils.NormalizeStarknetAddress(fromAddress),
		"decoded": map[string]interface{}{
			"indexed_params":     indexedParams,
			"non_indexed_params": nonIndexedParams,
		},
	}

	return rpcEvent, nil
}

// transformRPCEventToTransferFormat converts RPC event format (from GetEventsByTransactionHash) to RPC transfer format
// This is needed when processing transaction hash events that should be treated as transfers
func (s *IndexerStarknet) transformRPCEventToTransferFormat(event map[string]interface{}) map[string]interface{} {
	// RPC event format: transaction_hash, block_number, decoded.indexed_params, decoded.non_indexed_params
	// RPC transfer format: transaction_hash, block_number, topics, decoded.non_indexed_params (from, to, value)
	needsTransformation, _ := event["needs_transformation"].(bool)
	if !needsTransformation {
		return event
	}

	transactionHash, _ := event["transactionHash"].(string)
	blockNumber, _ := event["blockNumber"].(float64)
	topics, _ := event["selector"].(string)

	// Check if this is a Transfer event
	if topics != u.TransferStarknetSelector {
		logger.WithFields(logger.Fields{
			"TxHash": transactionHash,
			"Topics": topics,
		}).Warnf("Event is not a Transfer event, skipping transformation")
		return nil
	}

	dataDecoded, _ := event["dataDecoded"].([]interface{})
	keys, _ := event["keys"].([]interface{})

	if len(keys) == 0 {
		return nil
	}

	nonIndexedParams := make(map[string]interface{})

	for _, keyItem := range dataDecoded {
		if keyMap, ok := keyItem.(map[string]interface{}); ok {
			keyName, _ := keyMap["name"].(string)
			keyValue, _ := keyMap["value"].(string)
			switch keyName {
			case "from", "to":
				nonIndexedParams[keyName] = keyValue
			case "value":
				transferAmount, err := u.ParseStringAsDecimals(keyValue)
				if err != nil {
					logger.WithFields(logger.Fields{
						"TxHash": transactionHash,
						"Value":  keyValue,
						"Error":  err.Error(),
					}).Warnf("Failed to parse transfer value")
					return nil
				}
				nonIndexedParams[keyName] = transferAmount
			}
		}
	}

	// Extract transfer fields
	from, _ := nonIndexedParams["from"].(string)
	to, _ := nonIndexedParams["to"].(string)
	value, _ := nonIndexedParams["value"].(decimal.Decimal)

	if from == "" || to == "" || value.IsZero() {
		logger.WithFields(logger.Fields{
			"TxHash": transactionHash,
			"From":   from,
			"To":     to,
			"Value":  value,
		}).Warnf("Missing required transfer fields in RPC event")
		return nil
	}

	// Create RPC transfer format
	rpcTransfer := map[string]interface{}{
		"transaction_hash": transactionHash,
		"block_number":     blockNumber,
		"topics":           topics,
		"decoded": map[string]interface{}{
			"non_indexed_params": map[string]interface{}{
				"from":  cryptoUtils.NormalizeStarknetAddress(from),
				"to":    cryptoUtils.NormalizeStarknetAddress(to),
				"value": value,
			},
			"indexed_params": map[string]interface{}{},
		},
	}

	return rpcTransfer
}
