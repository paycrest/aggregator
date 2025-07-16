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

// IndexTransfer indexes transfers to the receive address for EVM networks.
func (s *IndexerEVM) IndexTransfer(ctx context.Context, token *ent.Token, address string, fromBlock int64, toBlock int64, txHash string) error {
	var events []interface{}
	var err error

	// If only address is provided (no txHash, no block range), fetch user's transaction history
	if address != "" && txHash == "" && fromBlock == 0 && toBlock == 0 {
		return s.indexTransferByUserAddress(ctx, token, address)
	}

	// If address is provided with block range, fetch user's transactions within that range
	if address != "" && txHash == "" && (fromBlock > 0 || toBlock > 0) {
		return s.indexTransferByUserAddressInRange(ctx, token, address, fromBlock, toBlock)
	}

	// Check if this is BNB Smart Chain (chain ID 56) - use RPC instead of Thirdweb Insight
	if token.Edges.Network.ChainID == 56 {
		eventSignature := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" // Transfer
		var topics []string

		if address != "" {
			topics = append(topics, address)
		}

		events, err = s.engineService.GetContractEventsRPC(
			ctx,
			token.Edges.Network.RPCEndpoint,
			token.ContractAddress,
			fromBlock,
			toBlock,
			eventSignature,
			topics,
			txHash,
		)
	} else {
		// Use Thirdweb Insight for other networks
		var eventPayload map[string]string
		if txHash != "" {
			eventPayload = map[string]string{
				"filter_topic_0":          "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", // Transfer
				"filter_transaction_hash": txHash,
				"decode":                  "true",
			}
		} else {
			eventPayload = map[string]string{
				"filter_block_number_gte": fmt.Sprintf("%d", fromBlock),
				"filter_block_number_lte": fmt.Sprintf("%d", toBlock),
				"filter_topic_0":          "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", // Transfer
				"sort_by":                 "block_number",
				"sort_order":              "desc",
				"decode":                  "true",
				"limit":                   "500",
			}
			if address != "" {
				eventPayload["filter_topic_2"] = address
			}
		}

		events, err = s.engineService.GetContractEvents(ctx, token.Edges.Network.ChainID, token.ContractAddress, eventPayload)
	}

	if err != nil {
		return fmt.Errorf("ProcessTransfer.getTransferEventData: %w", err)
	}

	unknownAddresses := []string{}
	addressToEvent := make(map[string]*types.TokenTransferEvent)

	// Parse transfer event data
	for _, event := range events {
		eventParams := event.(map[string]interface{})["decoded"].(map[string]interface{})
		if eventParams["non_indexed_params"] == nil {
			continue
		}

		transferValue, err := decimal.NewFromString(eventParams["non_indexed_params"].(map[string]interface{})["value"].(string))
		if err != nil {
			logger.Errorf("Error parsing transfer value: %v %v", err, eventParams["non_indexed_params"].(map[string]interface{}))
			continue
		}
		toAddress := ethcommon.HexToAddress(eventParams["indexed_params"].(map[string]interface{})["to"].(string)).Hex()
		fromAddress := ethcommon.HexToAddress(eventParams["indexed_params"].(map[string]interface{})["from"].(string)).Hex()

		if strings.EqualFold(fromAddress, token.Edges.Network.GatewayContractAddress) {
			continue
		}

		transferEvent := &types.TokenTransferEvent{
			BlockNumber: int64(event.(map[string]interface{})["block_number"].(float64)),
			TxHash:      event.(map[string]interface{})["transaction_hash"].(string),
			From:        fromAddress,
			To:          toAddress,
			Value:       transferValue.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(token.Decimals)))),
		}

		unknownAddresses = append(unknownAddresses, toAddress)
		addressToEvent[toAddress] = transferEvent
	}

	if len(unknownAddresses) == 0 {
		return nil
	}

	err = common.ProcessTransfers(ctx, s.order, s.priorityQueue, unknownAddresses, addressToEvent, token)
	if err != nil {
		return fmt.Errorf("IndexTransfer.processTransfers: %w", err)
	}

	return nil
}

// indexTransferByUserAddress indexes transfer events from a user's transaction history
func (s *IndexerEVM) indexTransferByUserAddress(ctx context.Context, token *ent.Token, userAddress string) error {
	// Get user's transaction history (last 10 transactions by default)
	transactions, err := s.engineService.GetUserTransactionHistory(ctx, token.Edges.Network.ChainID, userAddress, 10, 0, 0)
	if err != nil {
		return fmt.Errorf("failed to get user transaction history: %w", err)
	}

	if len(transactions) == 0 {
		logger.Infof("No transactions found for address: %s", userAddress)
		return nil
	}

	logger.Infof("Processing %d transactions for address: %s", len(transactions), userAddress)

	// Process each transaction to find transfer events
	for i, tx := range transactions {
		txHash := tx["hash"].(string)
		logger.Infof("Processing transaction %d/%d: %s", i+1, len(transactions), txHash[:10]+"...")

		// Index transfer events for this specific transaction
		err := s.IndexTransfer(ctx, token, userAddress, 0, 0, txHash)
		if err != nil {
			logger.Errorf("Error processing transaction %s: %v", txHash[:10]+"...", err)
			continue // Skip transactions with errors
		}
	}

	return nil
}

// indexTransferByUserAddressInRange indexes transfer events from a user's transaction history within a block range
func (s *IndexerEVM) indexTransferByUserAddressInRange(ctx context.Context, token *ent.Token, userAddress string, fromBlock int64, toBlock int64) error {
	// Get user's transaction history filtered by block range using API
	transactions, err := s.engineService.GetUserTransactionHistory(ctx, token.Edges.Network.ChainID, userAddress, 100, fromBlock, toBlock)
	if err != nil {
		return fmt.Errorf("failed to get user transaction history: %w", err)
	}

	if len(transactions) == 0 {
		logger.Infof("No transactions found in block range %d-%d for address: %s", fromBlock, toBlock, userAddress)
		return nil
	}

	logger.Infof("Processing %d transactions in block range %d-%d for address: %s", len(transactions), fromBlock, toBlock, userAddress)

	// Process each transaction to find transfer events
	for i, tx := range transactions {
		txHash := tx["hash"].(string)
		logger.Infof("Processing transaction %d/%d: %s", i+1, len(transactions), txHash[:10]+"...")

		// Index transfer events for this specific transaction
		err := s.IndexTransfer(ctx, token, userAddress, 0, 0, txHash)
		if err != nil {
			logger.Errorf("Error processing transaction %s: %v", txHash[:10]+"...", err)
			continue // Skip transactions with errors
		}
	}

	return nil
}

// IndexOrderCreated indexes orders created in the Gateway contract for EVM networks.
func (s *IndexerEVM) IndexOrderCreated(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64, txHash string) error {
	var events []interface{}
	var err error

	// If only address is provided (no txHash, no block range), fetch user's transaction history
	if address != "" && txHash == "" && fromBlock == 0 && toBlock == 0 {
		return s.indexOrderCreatedByUserAddress(ctx, network, address)
	}

	// If address is provided with block range, fetch user's transactions within that range
	if address != "" && txHash == "" && (fromBlock > 0 || toBlock > 0) {
		return s.indexOrderCreatedByUserAddressInRange(ctx, network, address, fromBlock, toBlock)
	}

	// Check if this is BNB Smart Chain (chain ID 56) - use RPC instead of Thirdweb Insight
	if network.ChainID == 56 {
		eventSignature := "0x40ccd1ceb111a3c186ef9911e1b876dc1f789ed331b86097b3b8851055b6a137" // OrderCreated
		var topics []string

		events, err = s.engineService.GetContractEventsRPC(
			ctx,
			network.RPCEndpoint,
			network.GatewayContractAddress,
			fromBlock,
			toBlock,
			eventSignature,
			topics,
			txHash,
		)
	} else {
		// Use Thirdweb Insight for other networks
		var eventPayload map[string]string
		if txHash != "" {
			eventPayload = map[string]string{
				"filter_topic_0":          "0x40ccd1ceb111a3c186ef9911e1b876dc1f789ed331b86097b3b8851055b6a137", // OrderCreated
				"filter_transaction_hash": txHash,
				"decode":                  "true",
			}
		} else {
			eventPayload = map[string]string{
				"filter_block_number_gte": fmt.Sprintf("%d", fromBlock),
				"filter_block_number_lte": fmt.Sprintf("%d", toBlock),
				"filter_topic_0":          "0x40ccd1ceb111a3c186ef9911e1b876dc1f789ed331b86097b3b8851055b6a137", // OrderCreated
				"sort_by":                 "block_number",
				"sort_order":              "desc",
				"decode":                  "true",
				"limit":                   "500",
			}
		}

		events, err = s.engineService.GetContractEvents(ctx, network.ChainID, network.GatewayContractAddress, eventPayload)
	}

	if err != nil {
		return fmt.Errorf("IndexOrderCreated.getEvents: %w", err)
	}

	txHashes := []string{}
	hashToEvent := make(map[string]*types.OrderCreatedEvent)

	for _, event := range events {
		eventParams := event.(map[string]interface{})["decoded"].(map[string]interface{})

		if eventParams["non_indexed_params"] == nil {
			continue
		}

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
			BlockNumber: int64(event.(map[string]interface{})["block_number"].(float64)),
			TxHash:      event.(map[string]interface{})["transaction_hash"].(string),
			Token:       ethcommon.HexToAddress(eventParams["indexed_params"].(map[string]interface{})["token"].(string)).Hex(),
			Amount:      orderAmount,
			ProtocolFee: protocolFee,
			OrderId:     eventParams["non_indexed_params"].(map[string]interface{})["orderId"].(string),
			Rate:        rate.Div(decimal.NewFromInt(100)),
			MessageHash: eventParams["non_indexed_params"].(map[string]interface{})["messageHash"].(string),
			Sender:      ethcommon.HexToAddress(eventParams["indexed_params"].(map[string]interface{})["sender"].(string)).Hex(),
		}

		txHashes = append(txHashes, createdEvent.TxHash)
		hashToEvent[createdEvent.TxHash] = createdEvent
	}

	if len(txHashes) == 0 {
		return nil
	}

	err = common.ProcessCreatedOrders(ctx, network, txHashes, hashToEvent, s.order, s.priorityQueue)
	if err != nil {
		return fmt.Errorf("IndexOrderCreated.processCreatedOrders: %w", err)
	}

	return nil
}

// indexOrderCreatedByUserAddress indexes OrderCreated events from a user's transaction history
func (s *IndexerEVM) indexOrderCreatedByUserAddress(ctx context.Context, network *ent.Network, userAddress string) error {
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

	// Process each transaction to find OrderCreated events
	for i, tx := range transactions {
		txHash := tx["hash"].(string)
		logger.Infof("Processing transaction %d/%d: %s", i+1, len(transactions), txHash[:10]+"...")

		// Index OrderCreated events for this specific transaction
		err := s.IndexOrderCreated(ctx, network, userAddress, 0, 0, txHash)
		if err != nil {
			logger.Errorf("Error processing transaction %s: %v", txHash[:10]+"...", err)
			continue // Skip transactions with errors
		}
	}

	return nil
}

// indexOrderCreatedByUserAddressInRange indexes OrderCreated events from a user's transaction history within a block range
func (s *IndexerEVM) indexOrderCreatedByUserAddressInRange(ctx context.Context, network *ent.Network, userAddress string, fromBlock int64, toBlock int64) error {
	// Get user's transaction history filtered by block range using API
	transactions, err := s.engineService.GetUserTransactionHistory(ctx, network.ChainID, userAddress, 100, fromBlock, toBlock)
	if err != nil {
		return fmt.Errorf("failed to get user transaction history: %w", err)
	}

	if len(transactions) == 0 {
		logger.Infof("No transactions found in block range %d-%d for address: %s", fromBlock, toBlock, userAddress)
		return nil
	}

	logger.Infof("Processing %d transactions in block range %d-%d for address: %s", len(transactions), fromBlock, toBlock, userAddress)

	// Process each transaction to find OrderCreated events
	for i, tx := range transactions {
		txHash := tx["hash"].(string)
		logger.Infof("Processing transaction %d/%d: %s", i+1, len(transactions), txHash[:10]+"...")

		// Index OrderCreated events for this specific transaction
		err := s.IndexOrderCreated(ctx, network, userAddress, 0, 0, txHash)
		if err != nil {
			logger.Errorf("Error processing transaction %s: %v", txHash[:10]+"...", err)
			continue // Skip transactions with errors
		}
	}

	return nil
}

// IndexOrderSettled indexes orders settled in the Gateway contract for EVM networks.
func (s *IndexerEVM) IndexOrderSettled(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64, txHash string) error {
	var events []interface{}
	var err error

	// If only address is provided (no txHash, no block range), fetch user's transaction history
	if address != "" && txHash == "" && fromBlock == 0 && toBlock == 0 {
		return s.indexOrderSettledByUserAddress(ctx, network, address)
	}

	// If address is provided with block range, fetch user's transactions within that range
	if address != "" && txHash == "" && (fromBlock > 0 || toBlock > 0) {
		return s.indexOrderSettledByUserAddressInRange(ctx, network, address, fromBlock, toBlock)
	}

	// Check if this is BNB Smart Chain (chain ID 56) - use RPC instead of Thirdweb Insight
	if network.ChainID == 56 {
		eventSignature := "0x98ece21e01a01cbe1d1c0dad3b053c8fbd368f99be78be958fcf1d1d13fd249a" // OrderSettled
		var topics []string

		events, err = s.engineService.GetContractEventsRPC(
			ctx,
			network.RPCEndpoint,
			network.GatewayContractAddress,
			fromBlock,
			toBlock,
			eventSignature,
			topics,
			txHash,
		)
	} else {
		// Use Thirdweb Insight for other networks
		var eventPayload map[string]string
		if txHash != "" {
			eventPayload = map[string]string{
				"filter_topic_0":          "0x98ece21e01a01cbe1d1c0dad3b053c8fbd368f99be78be958fcf1d1d13fd249a", // OrderSettled
				"filter_transaction_hash": txHash,
				"decode":                  "true",
			}
		} else {
			eventPayload = map[string]string{
				"filter_block_number_gte": fmt.Sprintf("%d", fromBlock),
				"filter_block_number_lte": fmt.Sprintf("%d", toBlock),
				"filter_topic_0":          "0x98ece21e01a01cbe1d1c0dad3b053c8fbd368f99be78be958fcf1d1d13fd249a", // OrderSettled
				"sort_by":                 "block_number",
				"sort_order":              "desc",
				"decode":                  "true",
				"limit":                   "500",
			}
		}

		events, err = s.engineService.GetContractEvents(ctx, network.ChainID, network.GatewayContractAddress, eventPayload)
	}

	if err != nil {
		return fmt.Errorf("IndexOrderSettled.getEvents: %w %v %v", err, events, network.GatewayContractAddress)
	}

	txHashes := []string{}
	hashToEvent := make(map[string]*types.OrderSettledEvent)

	for _, event := range events {
		eventParams := event.(map[string]interface{})["decoded"].(map[string]interface{})

		if eventParams["non_indexed_params"] == nil {
			continue
		}

		settlePercent, err := decimal.NewFromString(eventParams["non_indexed_params"].(map[string]interface{})["settlePercent"].(string))
		if err != nil {
			continue
		}
		settledEvent := &types.OrderSettledEvent{
			BlockNumber:       int64(event.(map[string]interface{})["block_number"].(float64)),
			TxHash:            event.(map[string]interface{})["transaction_hash"].(string),
			SplitOrderId:      eventParams["non_indexed_params"].(map[string]interface{})["splitOrderId"].(string),
			OrderId:           eventParams["indexed_params"].(map[string]interface{})["orderId"].(string),
			LiquidityProvider: ethcommon.HexToAddress(eventParams["indexed_params"].(map[string]interface{})["liquidityProvider"].(string)).Hex(),
			SettlePercent:     settlePercent,
		}

		txHashes = append(txHashes, settledEvent.TxHash)
		hashToEvent[settledEvent.TxHash] = settledEvent
	}

	if len(txHashes) == 0 {
		return nil
	}

	err = common.ProcessSettledOrders(ctx, network, txHashes, hashToEvent)
	if err != nil {
		return fmt.Errorf("IndexOrderSettled.processSettledOrders: %w", err)
	}

	return nil
}

// indexOrderSettledByUserAddress indexes OrderSettled events from a user's transaction history
func (s *IndexerEVM) indexOrderSettledByUserAddress(ctx context.Context, network *ent.Network, userAddress string) error {
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

	// Process each transaction to find OrderSettled events
	for i, tx := range transactions {
		txHash := tx["hash"].(string)
		logger.Infof("Processing transaction %d/%d: %s", i+1, len(transactions), txHash[:10]+"...")

		// Index OrderSettled events for this specific transaction
		err := s.IndexOrderSettled(ctx, network, userAddress, 0, 0, txHash)
		if err != nil {
			logger.Errorf("Error processing transaction %s: %v", txHash[:10]+"...", err)
			continue // Skip transactions with errors
		}
	}

	return nil
}

// indexOrderSettledByUserAddressInRange indexes OrderSettled events from a user's transaction history within a block range
func (s *IndexerEVM) indexOrderSettledByUserAddressInRange(ctx context.Context, network *ent.Network, userAddress string, fromBlock int64, toBlock int64) error {
	// Get user's transaction history filtered by block range using API
	transactions, err := s.engineService.GetUserTransactionHistory(ctx, network.ChainID, userAddress, 100, fromBlock, toBlock)
	if err != nil {
		return fmt.Errorf("failed to get user transaction history: %w", err)
	}

	if len(transactions) == 0 {
		logger.Infof("No transactions found in block range %d-%d for address: %s", fromBlock, toBlock, userAddress)
		return nil
	}

	logger.Infof("Processing %d transactions in block range %d-%d for address: %s", len(transactions), fromBlock, toBlock, userAddress)

	// Process each transaction to find OrderSettled events
	for i, tx := range transactions {
		txHash := tx["hash"].(string)
		logger.Infof("Processing transaction %d/%d: %s", i+1, len(transactions), txHash[:10]+"...")

		// Index OrderSettled events for this specific transaction
		err := s.IndexOrderSettled(ctx, network, userAddress, 0, 0, txHash)
		if err != nil {
			logger.Errorf("Error processing transaction %s: %v", txHash[:10]+"...", err)
			continue // Skip transactions with errors
		}
	}

	return nil
}

// IndexOrderRefunded indexes orders refunded in the Gateway contract for EVM networks.
func (s *IndexerEVM) IndexOrderRefunded(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64, txHash string) error {
	var events []interface{}
	var err error

	// If only address is provided (no txHash, no block range), fetch user's transaction history
	if address != "" && txHash == "" && fromBlock == 0 && toBlock == 0 {
		return s.indexOrderRefundedByUserAddress(ctx, network, address)
	}

	// If address is provided with block range, fetch user's transactions within that range
	if address != "" && txHash == "" && (fromBlock > 0 || toBlock > 0) {
		return s.indexOrderRefundedByUserAddressInRange(ctx, network, address, fromBlock, toBlock)
	}

	// Check if this is BNB Smart Chain (chain ID 56) - use RPC instead of Thirdweb Insight
	if network.ChainID == 56 {
		eventSignature := "0x0736fe428e1747ca8d387c2e6fa1a31a0cde62d3a167c40a46ade59a3cdc828e" // OrderRefunded
		var topics []string

		events, err = s.engineService.GetContractEventsRPC(
			ctx,
			network.RPCEndpoint,
			network.GatewayContractAddress,
			fromBlock,
			toBlock,
			eventSignature,
			topics,
			txHash,
		)
	} else {
		// Use Thirdweb Insight for other networks
		var eventPayload map[string]string
		if txHash != "" {
			eventPayload = map[string]string{
				"filter_topic_0":          "0x0736fe428e1747ca8d387c2e6fa1a31a0cde62d3a167c40a46ade59a3cdc828e", // OrderRefunded
				"filter_transaction_hash": txHash,
				"decode":                  "true",
			}
		} else {
			eventPayload = map[string]string{
				"filter_block_number_gte": fmt.Sprintf("%d", fromBlock),
				"filter_block_number_lte": fmt.Sprintf("%d", toBlock),
				"filter_topic_0":          "0x0736fe428e1747ca8d387c2e6fa1a31a0cde62d3a167c40a46ade59a3cdc828e", // OrderRefunded
				"sort_by":                 "block_number",
				"sort_order":              "desc",
				"decode":                  "true",
				"limit":                   "500",
			}
		}

		events, err = s.engineService.GetContractEvents(ctx, network.ChainID, network.GatewayContractAddress, eventPayload)
	}

	if err != nil {
		return fmt.Errorf("IndexOrderRefunded.getEvents: %w", err)
	}

	txHashes := []string{}
	hashToEvent := make(map[string]*types.OrderRefundedEvent)

	for _, event := range events {
		eventParams := event.(map[string]interface{})["decoded"].(map[string]interface{})
		if eventParams["non_indexed_params"] == nil {
			continue
		}

		fee, err := decimal.NewFromString(eventParams["non_indexed_params"].(map[string]interface{})["fee"].(string))
		if err != nil {
			continue
		}

		refundedEvent := &types.OrderRefundedEvent{
			BlockNumber: int64(event.(map[string]interface{})["block_number"].(float64)),
			TxHash:      event.(map[string]interface{})["transaction_hash"].(string),
			OrderId:     eventParams["indexed_params"].(map[string]interface{})["orderId"].(string),
			Fee:         fee,
		}

		txHashes = append(txHashes, refundedEvent.TxHash)
		hashToEvent[refundedEvent.TxHash] = refundedEvent
	}

	if len(txHashes) == 0 {
		return nil
	}

	err = common.ProcessRefundedOrders(ctx, network, txHashes, hashToEvent)
	if err != nil {
		return fmt.Errorf("IndexOrderRefunded.processRefundedOrders: %w", err)
	}

	return nil
}

// indexOrderRefundedByUserAddress indexes OrderRefunded events from a user's transaction history
func (s *IndexerEVM) indexOrderRefundedByUserAddress(ctx context.Context, network *ent.Network, userAddress string) error {
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

	// Process each transaction to find OrderRefunded events
	for i, tx := range transactions {
		txHash := tx["hash"].(string)
		logger.Infof("Processing transaction %d/%d: %s", i+1, len(transactions), txHash[:10]+"...")

		// Index OrderRefunded events for this specific transaction
		err := s.IndexOrderRefunded(ctx, network, userAddress, 0, 0, txHash)
		if err != nil {
			logger.Errorf("Error processing transaction %s: %v", txHash[:10]+"...", err)
			continue // Skip transactions with errors
		}
	}

	return nil
}

// indexOrderRefundedByUserAddressInRange indexes OrderRefunded events from a user's transaction history within a block range
func (s *IndexerEVM) indexOrderRefundedByUserAddressInRange(ctx context.Context, network *ent.Network, userAddress string, fromBlock int64, toBlock int64) error {
	// Get user's transaction history filtered by block range using API
	transactions, err := s.engineService.GetUserTransactionHistory(ctx, network.ChainID, userAddress, 100, fromBlock, toBlock)
	if err != nil {
		return fmt.Errorf("failed to get user transaction history: %w", err)
	}

	if len(transactions) == 0 {
		logger.Infof("No transactions found in block range %d-%d for address: %s", fromBlock, toBlock, userAddress)
		return nil
	}

	logger.Infof("Processing %d transactions in block range %d-%d for address: %s", len(transactions), fromBlock, toBlock, userAddress)

	// Process each transaction to find OrderRefunded events
	for i, tx := range transactions {
		txHash := tx["hash"].(string)
		logger.Infof("Processing transaction %d/%d: %s", i+1, len(transactions), txHash[:10]+"...")

		// Index OrderRefunded events for this specific transaction
		err := s.IndexOrderRefunded(ctx, network, userAddress, 0, 0, txHash)
		if err != nil {
			logger.Errorf("Error processing transaction %s: %v", txHash[:10]+"...", err)
			continue // Skip transactions with errors
		}
	}

	return nil
}
