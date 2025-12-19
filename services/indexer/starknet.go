package indexer

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/NethermindEth/juno/core/felt"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/services/order"
	starknetService "github.com/paycrest/aggregator/services/starknet"
	"github.com/paycrest/aggregator/types"
	u "github.com/paycrest/aggregator/utils"
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

	if txHash != "" {
		// Process specific transaction
		counts, err := s.indexReceiveAddressByTransaction(ctx, token, txHash, userAccountAddress)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to index receive address by transaction: %w", err)
		}
		return counts, nil
	}

	// Determine chunk size based on whether block range is provided
	var ChunkSize int
	if fromBlock == 0 && toBlock == 0 {
		// No block range - get last 5 transactions
		ChunkSize = 5
	} else {
		// Block range provided - get up to 100 transactions in range
		ChunkSize = 100
	}

	// Use Voyager service to get token transfers (handles RPC fallback internally)
	transfers, err := s.voyagerService.GetAddressTokenTransfers(ctx, token.ContractAddress, ChunkSize, fromBlock, toBlock, "", userAccountAddress)
	if err != nil {
		logger.WithFields(logger.Fields{
			"error": fmt.Sprintf("%v", err),
			"Token": token.Symbol,
			"UserAddress":   userAccountAddress,
		}).Error("Failed to get token transfers for token")
		return eventCounts, fmt.Errorf("failed to get token transfers for token %s: %w", token.Symbol, err)
	}
	logger.WithFields(logger.Fields{
		"Token":         token.Symbol,
		"UserAddress":   userAccountAddress,
		"TransferCount": len(transfers),
	}).Infof("Voyager: after transfer")
	// Transform Voyager transfers to RPC format for processing
	transactions := make([]map[string]interface{}, len(transfers))
	for i, transfer := range transfers {
		// Use transformation function from Voyager service
		transactions[i] = services.TransformVoyagerTransferToRPCFormat(transfer)
	}

	if len(transactions) == 0 {
		logger.Infof("No transactions found in block range %d-%d for address: %s", fromBlock, toBlock, userAccountAddress)
		return eventCounts, nil
	}

	transferEventCount, err := s.processReceiveAddressByTransactionEvents(ctx, token, transactions, userAccountAddress)
	if err != nil {
		logger.WithFields(logger.Fields{
			"error": fmt.Sprintf("%v", err),
			"Token": token.Symbol,
			"UserAddress":   userAccountAddress,
		}).Error("Failed to process receive address by transaction events")
		return eventCounts, fmt.Errorf("failed to index receive address by transaction: %w", err)
	}
	logger.WithFields(logger.Fields{
		"Token":         token.Symbol,
		"UserAddress":   userAccountAddress,
		"TransferCount": transferEventCount.Transfer,
	}).Infof("Processed transfer events for receive address")
	eventCounts.Transfer += transferEventCount.Transfer

	for _, tx := range transactions {
		txHash, ok := tx["transaction_hash"].(string)
		if !ok || txHash == "" {
			continue
		}
		gatewayEventCount, err := s.indexGatewayByTransaction(ctx, token.Edges.Network, txHash)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to index gateway by transaction: %w", err)
		}
		eventCounts.OrderCreated += gatewayEventCount.OrderCreated
	}

	return eventCounts, nil
}

// indexReceiveAddressByTransaction processes a specific transaction for receive address transfers
func (s *IndexerStarknet) indexReceiveAddressByTransaction(ctx context.Context, token *ent.Token, txHash string, userAccountAddress string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}
	if txHash == "" {
		return eventCounts, fmt.Errorf("transaction hash is required")
	}

	// Use Voyager service to get events by transaction hash (handles RPC fallback internally)
	events, err := s.voyagerService.GetEventsByTransactionHash(ctx, txHash, 100)
	if err != nil && err.Error() != "no events found" {
		return eventCounts, fmt.Errorf("error getting transfer events for token %s in transaction %s: %w", token.Symbol, txHash[:10]+"...", err)
	}

	// Filter for transfer events from this token contract and transform to RPC format
	transactions := []map[string]interface{}{}
	for _, event := range events {
		// Check if event is from the token contract
		fromAddr, ok := event["fromAddress"].(string)
		if !ok {
			// Try RPC format
			fromAddr, ok = event["from_address"].(string)
		}
		if ok && strings.EqualFold(fromAddr, token.ContractAddress) {
			// Check if it's a transfer event (name or selector)
			name, _ := event["name"].(string)
			if name == "Transfer" || name == "" {
				// Transform Voyager event to RPC format if needed
				if _, hasDecoded := event["decoded"]; !hasDecoded {
					// This is a Voyager transfer event, transform it
					event = services.TransformVoyagerTransferToRPCFormat(event)
				}
				transactions = append(transactions, event)
			}
		}
	}

	transferEventsCounts, err := s.processReceiveAddressByTransactionEvents(ctx, token, transactions, userAccountAddress)
	if err != nil {
		return eventCounts, fmt.Errorf("failed to index receive address by transaction: %w", err)
	}
	eventCounts.Transfer += transferEventsCounts.Transfer

	for _, tx := range transactions {
		txHash, ok := tx["transaction_hash"].(string)
		if !ok || txHash == "" {
			continue
		}
		gatewayEventCount, err := s.indexGatewayByTransaction(ctx, token.Edges.Network, txHash)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to index gateway by transaction: %w", err)
		}
		eventCounts.OrderCreated += gatewayEventCount.OrderCreated
	}

	return eventCounts, nil
}

// processReceiveAddressByTransactionEvents processes a specific transaction for receive address transfers
func (s *IndexerStarknet) processReceiveAddressByTransactionEvents(ctx context.Context, token *ent.Token, transferEvents []map[string]interface{}, userAccountAddress string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}
	if len(transferEvents) == 0 {
		return eventCounts, nil
	}
	logger.Infof("Processing %d transfer events for token %s", len(transferEvents), token.Symbol)
	// Process transfer events
	for _, eventMap := range transferEvents {
		decoded, ok := eventMap["decoded"].(map[string]interface{})
		if !ok || decoded == nil {
			continue
		}
		nonIndexedParams, ok := decoded["non_indexed_params"].(map[string]interface{})
		if !ok || nonIndexedParams == nil {
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
			continue
		}

		var valueStr string
		if bigIntVal, ok := nonIndexedParams["value"].(*big.Int); ok {
			valueStr = bigIntVal.String()
		} else if feltVal, ok := nonIndexedParams["value"].(*felt.Felt); ok {
			valueStr = feltVal.BigInt(big.NewInt(0)).String()
		} else if strVal, ok := nonIndexedParams["value"].(string); ok {
			valueStr = strVal
		} else {
			logger.Errorf("Unexpected type for 'value' parameter in transfer event")
			continue
		}
		if valueStr == "" {
			continue
		}

		// Filter by userAccountAddress - only process transfers to the specified address
		if userAccountAddress != "" && !strings.EqualFold(toStr, userAccountAddress) {
			continue
		}

		// Skip if transfer is from gateway contract
		if strings.EqualFold(fromStr, token.Edges.Network.GatewayContractAddress) {
			continue
		}

		// Parse transfer value
		transferValue, err := decimal.NewFromString(valueStr)
		if err != nil {
			logger.Errorf("Error parsing transfer value for token %s: %v", token.Symbol, err)
			continue
		}

		// Safely extract block_number and transaction_hash
		blockNumberRaw, ok := eventMap["block_number"].(float64)
		if !ok {
			continue
		}
		blockNumber := int64(blockNumberRaw)

		txHashFromEvent, ok := eventMap["transaction_hash"].(string)
		if !ok || txHashFromEvent == "" {
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
			"Token":       token.Symbol,
			"UserAddress": userAccountAddress,
			"ToAddress":   toStr,
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

func extractUint64AsString(val interface{}) (string, bool) {
	if uintVal, ok := val.(uint64); ok {
		return fmt.Sprintf("%d", uintVal), true
	}
	return "", false
}

func (s *IndexerStarknet) indexGatewayByTransaction(ctx context.Context, network *ent.Network, txHash string) (*types.EventCounts, error) {
	// Find OrderCreated events for this transaction
	eventCounts := &types.EventCounts{}

	if txHash == "" {
		return eventCounts, fmt.Errorf("transaction hash is required")
	}

	// Use Voyager service to get events by transaction hash (handles RPC fallback internally)
	events, err := s.voyagerService.GetEventsByTransactionHash(ctx, txHash, 100)
	if err != nil && err.Error() != "no events found" {
		return eventCounts, fmt.Errorf("error getting gateway events for transaction %s: %w", txHash[:10]+"...", err)
	}

	// Filter for gateway contract events and transform to RPC format
	gatewayContractTransactions := []map[string]interface{}{}
	for _, event := range events {
		fromAddr, ok := event["fromAddress"].(string)
		if !ok {
			// Try RPC format
			fromAddr, ok = event["from_address"].(string)
		}
		if ok && strings.EqualFold(fromAddr, network.GatewayContractAddress) {
			// Transform Voyager event to RPC format if needed
			if _, hasDecoded := event["decoded"]; !hasDecoded {
				// This is a Voyager event, transform it
				event = services.TransformVoyagerEventToRPCFormat(event)
				// Update from_address to match the filtered address
				if fromAddr != "" {
					event["from_address"] = fromAddr
				}
			}
			gatewayContractTransactions = append(gatewayContractTransactions, event)
		}
	}

	// Process all events in a single pass
	orderCreatedEvents := []*types.OrderCreatedEvent{}
	orderSettledEvents := []*types.OrderSettledEvent{}
	orderRefundedEvents := []*types.OrderRefundedEvent{}

	for _, eventMap := range gatewayContractTransactions {
		decoded, ok := eventMap["decoded"].(map[string]interface{})
		if !ok || decoded == nil {
			continue
		}
		eventParams := decoded
		if eventParams["non_indexed_params"] == nil {
			continue
		}

		// Convert eventSignature from *felt.Felt to hex string for comparison
		eventSignature, ok := eventMap["topics"].(string)
		if !ok {
			continue
		}

		// Safely extract block_number and transaction_hash
		blockNumberRaw, ok := eventMap["block_number"].(float64)
		if !ok {
			continue
		}
		blockNumber := int64(blockNumberRaw)

		txHashFromEvent, ok := eventMap["transaction_hash"].(string)
		if !ok || txHashFromEvent == "" {
			continue
		}

		// Safely extract indexed_params and non_indexed_params
		indexedParams, ok := eventParams["indexed_params"].(map[string]interface{})
		if !ok || indexedParams == nil {
			continue
		}

		nonIndexedParams, ok := eventParams["non_indexed_params"].(map[string]interface{})
		if !ok || nonIndexedParams == nil {
			continue
		}

		switch eventSignature {
		case u.OrderCreatedStarknetSelector:
			amountStr, ok := indexedParams["amount"].(string)
			if !ok || amountStr == "" {
				continue
			}
			orderAmount, err := decimal.NewFromString(amountStr)
			if err != nil {
				continue
			}

			protocolFeeStr, ok := nonIndexedParams["protocol_fee"].(string)
			if !ok || protocolFeeStr == "" {
				continue
			}
			protocolFee, err := decimal.NewFromString(protocolFeeStr)
			if err != nil {
				continue
			}

			rateStr, ok := nonIndexedParams["rate"].(string)
			if !ok || rateStr == "" {
				continue
			}
			rate, err := decimal.NewFromString(rateStr)
			if err != nil {
				continue
			}

			tokenStr, ok := indexedParams["token"].(string)
			if !ok || tokenStr == "" {
				continue
			}

			orderIDStr, ok := nonIndexedParams["order_id"].(string)
			if !ok || orderIDStr == "" {
				continue
			}

			// Extract messageHash (string)
			messageHashStr, ok := nonIndexedParams["message_hash"].(string)
			if !ok || messageHashStr == "" {
				continue
			}

			// Extract sender (string)
			senderStr, ok := indexedParams["sender"].(string)
			if !ok || senderStr == "" {
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
			settlePercentStr, ok := extractUint64AsString(nonIndexedParams["settle_percent"])
			if !ok || settlePercentStr == "" {
				continue
			}
			settlePercent, err := decimal.NewFromString(settlePercentStr)
			if err != nil {
				continue
			}

			// Extract rebatePercent (uint64)
			rebatePercentStr, ok := extractUint64AsString(nonIndexedParams["rebate_percent"])
			if !ok || rebatePercentStr == "" {
				continue
			}
			rebatePercent, err := decimal.NewFromString(rebatePercentStr)
			if err != nil {
				continue
			}

			// Extract splitOrderId (felt.Felt -> hex string)
			splitOrderIDStr, ok := nonIndexedParams["split_order_id"].(string)
			if !ok || splitOrderIDStr == "" {
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
			// Extract fee (big.Int)
			feeStr, ok := nonIndexedParams["fee"].(string)
			if !ok || feeStr == "" {
				continue
			}
			fee, err := decimal.NewFromString(feeStr)
			if err != nil {
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

	if txHash != "" {
		counts, err := s.indexGatewayByTransaction(ctx, network, txHash)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to get transaction receipt: %w", err)
		}

		return counts, nil
	}

	// Determine limit based on whether block range is provided
	var limit int
	if fromBlock == 0 && toBlock == 0 {
		// No block range - get last 10 events
		limit = 10
	} else {
		// Block range provided - get up to 100 events in range
		limit = 100
	}

	// Use Voyager service to get gateway events (handles RPC fallback internally)
	events, err := s.voyagerService.GetContractEvents(ctx, address, limit, fromBlock, toBlock)
	if err != nil {
		return eventCounts, fmt.Errorf("failed to get gateway events: %w", err)
	}

	// Transform Voyager events to RPC format for processing
	transactions := make([]map[string]interface{}, len(events))
	for i, event := range events {
		// Use transformation function from Voyager service
		transactions[i] = services.TransformVoyagerEventToRPCFormat(event)
	}
	if len(transactions) == 0 {
		return eventCounts, nil
	}

	for _, tx := range transactions {
		// Handle both Voyager format (transactionHash) and RPC format (transaction_hash)
		txHash, ok := tx["transaction_hash"].(string)
		if !ok {
			// Try Voyager format
			txHash, ok = tx["transactionHash"].(string)
		}
		if !ok || txHash == "" {
			continue
		}
		gatewayEventCount, err := s.indexGatewayByTransaction(ctx, network, txHash)
		if err != nil {
			logger.Errorf("Failed to index gateway by transaction %s: %v", txHash[:10]+"...", err)
		}
		eventCounts.OrderCreated += gatewayEventCount.OrderCreated
	}

	return eventCounts, nil
}

// IndexProviderAddress indexes settlement events from providers
func (s *IndexerStarknet) IndexProviderAddress(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64, txHash string) (*types.EventCounts, error) {
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

	// Determine limit based on whether block range is provided
	var limit int
	if fromBlock == 0 && toBlock == 0 {
		// No block range - get last 20 transfers
		limit = 20
	} else {
		// Block range provided - get up to 100 transfers in range
		limit = 100
	}

	// Use Voyager transfers endpoint with from filter to get transfers from gateway to provider
	// This directly returns transfers from gateway contract to provider address
	transfers, err := s.voyagerService.GetAddressTokenTransfers(ctx, "", limit, fromBlock, toBlock, network.GatewayContractAddress, address)
	if err != nil {
		return eventCounts, fmt.Errorf("failed to get provider transfers: %w", err)
	}

	// Process transfers to identify OrderSettled vs OrderRefunded using txOperations field
	for _, transfer := range transfers {
		txOperations, ok := transfer["txOperations"].(string)
		if !ok {
			continue
		}

		// Check if transfer is for OrderSettled (contains "settle") or OrderRefunded (contains "refund")
		if strings.Contains(txOperations, "settle") {
			eventCounts.OrderSettled++
		} else if strings.Contains(txOperations, "refund") {
			eventCounts.OrderRefunded++
		}
	}

	return eventCounts, nil
}

// indexProviderAddressByTransaction processes a specific transaction for provider address OrderSettled events
func (s *IndexerStarknet) indexProviderAddressByTransaction(ctx context.Context, network *ent.Network, providerAddress string, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}
	if txHash == "" {
		return eventCounts, fmt.Errorf("transaction hash is required")
	}

	// Use Voyager service to get events by transaction hash (handles RPC fallback internally)
	allEvents, err := s.voyagerService.GetEventsByTransactionHash(ctx, txHash, 100)
	if err != nil {
		if err.Error() == "no events found" {
			return eventCounts, nil // No events found for this transaction
		}
		return eventCounts, fmt.Errorf("error getting events for transaction %s: %w", txHash[:10]+"...", err)
	}

	// Filter for OrderSettled events from gateway contract and transform to RPC format
	events := []map[string]interface{}{}
	for _, event := range allEvents {
		fromAddr, ok := event["fromAddress"].(string)
		if !ok {
			// Try RPC format
			fromAddr, ok = event["from_address"].(string)
		}
		if !ok || !strings.EqualFold(fromAddr, network.GatewayContractAddress) {
			continue
		}
		name, _ := event["name"].(string)
		if name == "OrderSettled" {
			// Transform Voyager event to RPC format if needed
			if _, hasDecoded := event["decoded"]; !hasDecoded {
				// This is a Voyager event, transform it
				event = services.TransformVoyagerEventToRPCFormat(event)
				// Update from_address to match the filtered address
				if fromAddr != "" {
					event["from_address"] = fromAddr
				}
			}
			events = append(events, event)
		}
	}

	// Process OrderSettled events for the specific provider address
	orderSettledEvents := []*types.OrderSettledEvent{}

	for _, eventMap := range events {
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

		if !strings.EqualFold(liquidityProvider, providerAddress) {
			continue
		}

		// Safely extract block_number and transaction_hash
		blockNumberRaw, ok := eventMap["block_number"].(float64)
		if !ok {
			continue
		}
		blockNumber := int64(blockNumberRaw)

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
		settlePercentStr, ok := extractUint64AsString(nonIndexedParams["settle_percent"])
		if !ok || settlePercentStr == "" {
			continue
		}

		settlePercent, err := decimal.NewFromString(settlePercentStr)
		if err != nil {
			continue
		}

		rebatePercentStr, ok := extractUint64AsString(nonIndexedParams["rebate_percent"])
		if !ok || rebatePercentStr == "" {
			continue
		}

		rebatePercent, err := decimal.NewFromString(rebatePercentStr)
		if err != nil {
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
		err = common.ProcessSettledOrders(ctx, network, orderIds, orderIdToEvent)
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
