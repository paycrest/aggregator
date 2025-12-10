package indexer

import (
	"context"
	"fmt"
	"strings"

	"github.com/NethermindEth/juno/core/felt"
	"github.com/NethermindEth/starknet.go/utils"
	ethcommon "github.com/ethereum/go-ethereum/common"
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
func NewIndexerStarknet(ctx context.Context) (types.Indexer, error) {
	priorityQueue := services.NewPriorityQueueService()
	orderService, err := order.NewOrderStarknet(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create order service: %w", err)
	}
	client, err := starknetService.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create starknet client: %w", err)
	}

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
		counts, err := s.indexReceiveAddressByTransaction(ctx, token, txHash, nil)
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

	transferEventCount, err := s.processReceiveAddressByTransactionEvents(ctx, token, transactions)
	if err != nil {
		return eventCounts, fmt.Errorf("failed to index receive address by transaction: %w", err)
	}
	eventCounts.Transfer += transferEventCount.Transfer

	for _, tx := range transactions {
		txHash, ok := tx["hash"].(string)
		if !ok {
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
func (s *IndexerStarknet) indexReceiveAddressByTransaction(ctx context.Context, token *ent.Token, txHash string, transactionEvents map[string]interface{}) (*types.EventCounts, error) {
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

	transferEventsCounts, err := s.processReceiveAddressByTransactionEvents(ctx, token, transactions)
	if err != nil {
		return eventCounts, fmt.Errorf("failed to index receive address by transaction: %w", err)
	}
	eventCounts.Transfer += transferEventsCounts.Transfer
	
	for _, tx := range transactions {
		txHash, ok := tx["hash"].(string)
		if !ok {
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
func (s *IndexerStarknet) processReceiveAddressByTransactionEvents(ctx context.Context, token *ent.Token, transferEvents []map[string]interface{}) (*types.EventCounts, error) {
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

		// Safely extract transfer data
		fromStr, ok := nonIndexedParams["from"].(string)
		if !ok || fromStr == "" {
			continue
		}

		toStr, ok := nonIndexedParams["to"].(string)
		if !ok || toStr == "" {
			continue
		}

		valueStr, ok := nonIndexedParams["value"].(string)
		if !ok || valueStr == "" {
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
	orderCreatedSelectorFelt, _ := utils.HexToFelt(u.OrderCreatedStarknetSelector)

	gatewayContractTransactions, err := s.client.GetTransactionReceipt(
		ctx,
		txHashFelt,
		gatewayContractFelt,
		[]*felt.Felt{orderCreatedSelectorFelt},
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
		
		eventSignature := eventMap["topics"]

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
			// Safely extract required fields for OrderCreated
			amountStr, ok := indexedParams["amount"].(string)
			if !ok || amountStr == "" {
				continue
			}
			orderAmount, err := decimal.NewFromString(amountStr)
			if err != nil {
				continue
			}

			protocolFeeStr, ok := nonIndexedParams["protocolFee"].(string)
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

			orderIdStr, ok := nonIndexedParams["orderId"].(string)
			if !ok || orderIdStr == "" {
				continue
			}

			messageHashStr, ok := nonIndexedParams["messageHash"].(string)
			if !ok || messageHashStr == "" {
				continue
			}

			senderStr, ok := indexedParams["sender"].(string)
			if !ok || senderStr == "" {
				continue
			}

			createdEvent := &types.OrderCreatedEvent{
				BlockNumber: blockNumber,
				TxHash:      txHashFromEvent,
				Token:       ethcommon.HexToAddress(tokenStr).Hex(),
				Amount:      orderAmount,
				ProtocolFee: protocolFee,
				OrderId:     orderIdStr,
				Rate:        rate.Div(decimal.NewFromInt(100)),
				MessageHash: messageHashStr,
				Sender:      ethcommon.HexToAddress(senderStr).Hex(),
			}
			orderCreatedEvents = append(orderCreatedEvents, createdEvent)

		case u.OrderSettledStarknetSelector:
			// Safely extract required fields for OrderSettled
			settlePercentStr, ok := nonIndexedParams["settlePercent"].(string)
			if !ok || settlePercentStr == "" {
				continue
			}
			settlePercent, err := decimal.NewFromString(settlePercentStr)
			if err != nil {
				continue
			}

			rebatePercentStr, ok := nonIndexedParams["rebatePercent"].(string)
			if !ok || rebatePercentStr == "" {
				continue
			}
			rebatePercent, err := decimal.NewFromString(rebatePercentStr)
			if err != nil {
				continue
			}

			splitOrderIdStr, ok := nonIndexedParams["splitOrderId"].(string)
			if !ok || splitOrderIdStr == "" {
				continue
			}

			orderIdStr, ok := indexedParams["orderId"].(string)
			if !ok || orderIdStr == "" {
				continue
			}

			liquidityProviderStr, ok := indexedParams["liquidityProvider"].(string)
			if !ok || liquidityProviderStr == "" {
				continue
			}

			settledEvent := &types.OrderSettledEvent{
				BlockNumber:       blockNumber,
				TxHash:            txHashFromEvent,
				SplitOrderId:      splitOrderIdStr,
				OrderId:           orderIdStr,
				LiquidityProvider: ethcommon.HexToAddress(liquidityProviderStr).Hex(),
				SettlePercent:     settlePercent,
				RebatePercent:     rebatePercent,
			}
			orderSettledEvents = append(orderSettledEvents, settledEvent)

		case u.OrderRefundedStarknetSelector:
			// Safely extract required fields for OrderRefunded
			feeStr, ok := nonIndexedParams["fee"].(string)
			if !ok || feeStr == "" {
				continue
			}
			fee, err := decimal.NewFromString(feeStr)
			if err != nil {
				continue
			}

			orderIdStr, ok := indexedParams["orderId"].(string)
			if !ok || orderIdStr == "" {
				continue
			}

			refundedEvent := &types.OrderRefundedEvent{
				BlockNumber: blockNumber,
				TxHash:      txHashFromEvent,
				OrderId:     orderIdStr,
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
		err := common.ProcessCreatedOrders(ctx, network, orderIds, orderIdToEvent, s.order, s.priorityQueue)
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
		err := common.ProcessRefundedOrders(ctx, network, orderIds, orderIdToEvent)
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
		if latest > 20 {
			fromBlockNum = latest - 100
		} else {
			fromBlockNum = 0
		}
	} else {
		fromBlockNum = uint64(fromBlock)
		toBlockNum = uint64(toBlock)
	}

	orderCreatedSelectorFelt, _ := utils.HexToFelt(u.OrderCreatedStarknetSelector)

	transactions, err := s.client.GetEvents(
		ctx,
		gatewayAddr,
		int64(fromBlockNum),
		int64(toBlockNum),
		[]*felt.Felt{orderCreatedSelectorFelt},
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
		txHash, ok := tx["hash"].(string)
		if !ok {
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
	
	gatewayContractFelt, _ := utils.HexToFelt(network.GatewayContractAddress)
	orderSettledSelectorFelt, _ := utils.HexToFelt(u.OrderSettledStarknetSelector)

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
		liquidityProvider, ok := indexedParams["liquidityProvider"].(string)
		if !ok || liquidityProvider == "" {
			continue
		}
		liquidityProvider = ethcommon.HexToAddress(liquidityProvider).Hex()
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
		settlePercentStr, ok := nonIndexedParams["settlePercent"].(string)
		if !ok || settlePercentStr == "" {
			continue
		}

		settlePercent, err := decimal.NewFromString(settlePercentStr)
		if err != nil {
			continue
		}

		splitOrderId, ok := nonIndexedParams["splitOrderId"].(string)
		if !ok || splitOrderId == "" {
			continue
		}

		orderId, ok := indexedParams["orderId"].(string)
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
