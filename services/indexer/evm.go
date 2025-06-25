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
	// Get Transfer event data
	eventPayload := map[string]string{}
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

	events, err := s.engineService.GetContractEvents(ctx, token.Edges.Network.ChainID, token.ContractAddress, eventPayload)
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

// IndexOrderCreated indexes orders created in the Gateway contract for EVM networks.
func (s *IndexerEVM) IndexOrderCreated(ctx context.Context, network *ent.Network, fromBlock int64, toBlock int64, txHash string) error {
	// Get OrderCreated event data
	eventPayload := map[string]string{}
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

	events, err := s.engineService.GetContractEvents(ctx, network.ChainID, network.GatewayContractAddress, eventPayload)
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

// IndexOrderSettled indexes orders settled in the Gateway contract for EVM networks.
func (s *IndexerEVM) IndexOrderSettled(ctx context.Context, network *ent.Network, fromBlock int64, toBlock int64, txHash string) error {
	// Get OrderSettled event data
	eventPayload := map[string]string{}
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

	events, err := s.engineService.GetContractEvents(ctx, network.ChainID, network.GatewayContractAddress, eventPayload)
	if err != nil {
		return fmt.Errorf("IndexOrderSettled.getEvents: %w %v", err, events)
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

// IndexOrderRefunded indexes orders settled in the Gateway contract for EVM networks.
func (s *IndexerEVM) IndexOrderRefunded(ctx context.Context, network *ent.Network, fromBlock int64, toBlock int64, txHash string) error {
	// Get OrderRefunded event data
	eventPayload := map[string]string{}
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

	events, err := s.engineService.GetContractEvents(ctx, network.ChainID, network.GatewayContractAddress, eventPayload)
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

		refundFee, err := decimal.NewFromString(eventParams["non_indexed_params"].(map[string]interface{})["fee"].(string))
		if err != nil {
			continue
		}

		refundedEvent := &types.OrderRefundedEvent{
			BlockNumber: int64(event.(map[string]interface{})["block_number"].(float64)),
			TxHash:      event.(map[string]interface{})["transaction_hash"].(string),
			OrderId:     eventParams["indexed_params"].(map[string]interface{})["orderId"].(string),
			Fee:         refundFee,
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
