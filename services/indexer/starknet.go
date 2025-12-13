package indexer

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/NethermindEth/juno/core/felt"
	"github.com/NethermindEth/starknet.go/utils"
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
	priorityQueue *services.PriorityQueueService
	order         types.OrderService
	client        *starknetService.Client
}

// NewIndexerStarknet creates a new instance of IndexerStarknet
func NewIndexerStarknet() (types.Indexer, error) {
	client, err := starknetService.NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create starknet client: %w", err)
	}
	orderService := order.NewOrderStarknet(client)
	priorityQueue := services.NewPriorityQueueService()

	return &IndexerStarknet{
		priorityQueue: priorityQueue,
		order:         orderService,
		client:        client,
	}, nil
}

// IndexReceiveAddress indexes transfer events to receive addresses
func (s *IndexerStarknet) IndexReceiveAddress(ctx context.Context, token *ent.Token, userAccountAddress string, fromBlock int64, toBlock int64, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}

	if txHash != "" {
		// Process specific transaction
		counts, err := s.indexReceiveAddressByTransaction(ctx, token, txHash, nil, userAccountAddress)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to index receive address by transaction: %w", err)
		}
		return counts, nil
	}

	var ChunkSize int
	if fromBlock == 0 && toBlock == 0 {
		ChunkSize = 5
		currentBlock, err := s.client.GetBlockNumber(ctx)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to get latest block number: %w", err)
		}
		toBlock = int64(currentBlock)
		fromBlock = int64(toBlock) - 5 // 4s per block and we want to read every 4seconds
		// Ensure fromBlock is not negative
		if fromBlock < 0 {
			fromBlock = 0
		}
	} else {
		ChunkSize = 100
	}

	tokenAddr, err := utils.HexToFelt(token.ContractAddress)
	if err != nil {
		return eventCounts, fmt.Errorf("invalid token address: %w", err)
	}

	transferSelectorFelt, _ := utils.HexToFelt(u.TransferStarknetSelector)
	transactions, err := s.client.GetEvents(
		ctx,
		tokenAddr,
		fromBlock,
		toBlock,
		[]*felt.Felt{transferSelectorFelt},
		ChunkSize,
	)
	if err != nil {
		return eventCounts, fmt.Errorf("failed to get transactions for token %s: %w", token.Symbol, err)
	}

	if len(transactions) == 0 {
		logger.Infof("No transactions found in block range %d-%d for address: %s", fromBlock, toBlock, userAccountAddress)
		return eventCounts, nil
	}

	transferEventCount, err := s.processReceiveAddressByTransactionEvents(ctx, token, transactions, userAccountAddress)
	if err != nil {
		return eventCounts, fmt.Errorf("failed to index receive address by transaction: %w", err)
	}
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
func (s *IndexerStarknet) indexReceiveAddressByTransaction(ctx context.Context, token *ent.Token, txHash string, transactionEvents map[string]interface{}, userAccountAddress string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}
	if txHash == "" {
		return eventCounts, fmt.Errorf("transaction hash is required")
	}

	txHashFelt, err := utils.HexToFelt(txHash)
	if err != nil {
		return eventCounts, fmt.Errorf("invalid transaction hash: %w", err)
	}
	tokenContractFelt, _ := utils.HexToFelt(token.ContractAddress)
	transferSelectorFelt, _ := utils.HexToFelt(u.TransferStarknetSelector)

	transactions, err := s.client.GetTransactionReceipt(
		ctx,
		txHashFelt,
		tokenContractFelt,
		[]*felt.Felt{transferSelectorFelt},
	)
	if err != nil && err.Error() != "no events found" {
		return eventCounts, fmt.Errorf("error getting transfer events for token %s in transaction %s: %w", token.Symbol, txHash[:10]+"...", err)
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

		err = common.ProcessTransfers(ctx, s.order, s.priorityQueue, []string{toStr}, addressToEvent, token)
		if err != nil {
			logger.Errorf("Error processing transfer for token %s: %v", token.Symbol, err)
			continue
		}

		// Increment transfer count for successful processing
		eventCounts.Transfer++
	}

	return eventCounts, nil
}

// Helper functions to extract values from event maps
func extractFeltAsString(val interface{}) (string, bool) {
	if feltVal, ok := val.(*felt.Felt); ok {
		return feltVal.String(), true
	}
	return "", false
}

func extractBigIntAsString(val interface{}) (string, bool) {
	if bigIntVal, ok := val.(*big.Int); ok {
		return bigIntVal.String(), true
	}
	if feltVal, ok := val.(*felt.Felt); ok {
		return feltVal.BigInt(big.NewInt(0)).String(), true
	}
	return "", false
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

	txHashFelt, err := utils.HexToFelt(txHash)
	if err != nil {
		return eventCounts, fmt.Errorf("invalid transaction hash: %w", err)
	}

	gatewayContractFelt, _ := utils.HexToFelt(network.GatewayContractAddress)

	gatewayContractTransactions, err := s.client.GetTransactionReceipt(
		ctx,
		txHashFelt,
		gatewayContractFelt,
		nil,
	)
	if err != nil && err.Error() != "no events found" {
		return eventCounts, fmt.Errorf("error getting gateway events for transaction %s: %w", txHash[:10]+"...", err)
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

	gatewayAddr, err := utils.HexToFelt(address)
	if err != nil {
		return eventCounts, fmt.Errorf("invalid gateway address: %w", err)
	}

	// Determine block range
	var fromBlockNum, toBlockNum uint64
	if txHash != "" {
		counts, err := s.indexGatewayByTransaction(ctx, network, txHash)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to get transaction receipt: %w", err)
		}

		return counts, nil
	}

	// Use provided block range or get latest
	if fromBlock == 0 && toBlock == 0 {
		latest, err := s.client.GetBlockNumber(ctx)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to get latest block: %w", err)
		}
		toBlockNum = latest
		// Index last 100 blocks by default
		if latest > 100 {
			fromBlockNum = latest - 100
		} else {
			fromBlockNum = 0
		}
	} else {
		fromBlockNum = uint64(fromBlock)
		toBlockNum = uint64(toBlock)
	}

	transactions, err := s.client.GetEvents(
		ctx,
		gatewayAddr,
		int64(fromBlockNum),
		int64(toBlockNum),
		nil,
		100,
	)
	if err != nil {
		return eventCounts, fmt.Errorf("failed to get gateway events: %w", err)
	}
	if len(transactions) == 0 {
		logger.Infof("No gateway events found in block range %d-%d for address: %s", fromBlockNum, toBlockNum, address)
		return eventCounts, nil
	}

	for _, tx := range transactions {
		txHash, ok := tx["transaction_hash"].(string)
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
	return s.IndexGateway(ctx, network, network.GatewayContractAddress, fromBlock, toBlock, txHash)
}

// indexProviderAddressByTransaction processes a specific transaction for provider address OrderSettled events
func (s *IndexerStarknet) indexProviderAddressByTransaction(ctx context.Context, network *ent.Network, providerAddress string, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}
	if txHash == "" {
		return eventCounts, fmt.Errorf("transaction hash is required")
	}

	txHashFelt, err := utils.HexToFelt(txHash)
	if err != nil {
		return eventCounts, fmt.Errorf("invalid transaction hash: %w", err)
	}

	gatewayContractFelt, err := utils.HexToFelt(network.GatewayContractAddress)
	if err != nil {
		return eventCounts, fmt.Errorf("invalid gateway contract address: %w", err)
	}
	orderSettledSelectorFelt, err := utils.HexToFelt(u.OrderSettledStarknetSelector)
	if err != nil {
		return eventCounts, fmt.Errorf("invalid order settled selector felt: %w", err)
	}

	// Get OrderSettled events for this transaction
	events, err := s.client.GetTransactionReceipt(
		ctx,
		txHashFelt,
		gatewayContractFelt,
		[]*felt.Felt{orderSettledSelectorFelt},
	)
	if err != nil {
		if err.Error() == "no events found" {
			return eventCounts, nil // No OrderSettled events found for this transaction
		}
		return eventCounts, fmt.Errorf("error getting OrderSettled events for transaction %s: %w", txHash[:10]+"...", err)
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
