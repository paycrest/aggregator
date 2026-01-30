package indexer

import (
	"context"
	"fmt"
	"strings"

	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/common"
	explorer "github.com/paycrest/aggregator/services/explorer"
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
	voyagerService *explorer.VoyagerService
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
	voyagerService, err := explorer.NewVoyagerService()
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

	if txHash != "" {
		// Process specific transaction
		rpcTransactionHashReceipt, err := s.voyagerService.GetEventsByTransactionHashRPC(ctx, txHash)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to index receive address by transaction: %w", err)
		}
		transactionHashReceipt = append(transactionHashReceipt, rpcTransactionHashReceipt...)
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
			transformed := explorer.TransformVoyagerTransferToRPCFormat(transfer)
			if transformed == nil {
				logger.WithFields(logger.Fields{
					"Token":       token.Symbol,
					"UserAddress": userAccountAddress,
				}).Error("Failed to transform Voyager transfer to RPC format")
				continue
			}
			transactionHashReceipt = append(transactionHashReceipt, transformed)
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
	logger.WithFields(logger.Fields{
		"len of transfer: ": len(transferEvents),
		"account":           userAccountAddress,
	}).Infof("Getting voyager contract for receive events")

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

	if txHash != "" {
		rpcTransactionHashReceipt, err := s.voyagerService.GetEventsByTransactionHashRPC(ctx, txHash)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to get transaction receipt: %w", err)
		}
		transactionHashReceipt = append(transactionHashReceipt, rpcTransactionHashReceipt...)
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

	if len(transactionHashReceipt) == 0 && txHash == "" {
		// Use Voyager service to get gateway events (handles RPC fallback internally)
		events, err := s.voyagerService.GetContractEvents(ctx, address, limit, fromBlock, toBlock)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to get gateway events: %w", err)
		}

		for _, event := range events {
			transformed, err := explorer.TransformVoyagerEventToRPCFormat(event)
			if err != nil {
				logger.Errorf("Failed to transform Gateway Voyager event to RPC format: %v", err)
				continue
			}
			transactionHashReceipt = append(transactionHashReceipt, transformed)
		}
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

	if txHash != "" {
		// Index provider address events for this specific transaction
		rpcTransactionHashReceipt, err := s.voyagerService.GetEventsByTransactionHashRPC(ctx, txHash)
		if err != nil {
			logger.Errorf("Error processing provider address transaction %s: %v", txHash[:10]+"...", err)
			return eventCounts, err
		}
		transactionHashReceipt = append(transactionHashReceipt, rpcTransactionHashReceipt...)
	}

	// Determine limit based on whether block range is provided
	var limit int
	if fromBlock == 0 && toBlock == 0 {
		// No block range - get last 20 transfers
		limit = 10
	} else {
		// Block range provided - get up to 100 transfers in range
		limit = 100
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
				eventsByTx, err := s.voyagerService.GetEventsByTransactionHashRPC(ctx, txHash)
				if err != nil {
					logger.WithFields(logger.Fields{
						"provider": address,
						"txHash":   txHash,
						"error":    fmt.Sprintf("%v", err),
					}).Error("Failed to get provider transfer transaction receipt by hash")
					continue
				}
				transactionHashReceipt = append(transactionHashReceipt, eventsByTx...)
			}
		}
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
