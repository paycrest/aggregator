package indexer

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/shopspring/decimal"
	"github.com/NethermindEth/juno/core/felt"
	"github.com/NethermindEth/starknet.go/rpc"
	"github.com/NethermindEth/starknet.go/utils"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/services/order"
	u "github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils/logger"
	starknetService "github.com/paycrest/aggregator/services/starknet"
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
	orderService := order.NewOrderStarknet()
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
func (s *IndexerStarknet) IndexReceiveAddress(ctx context.Context, token *ent.Token, address string, fromBlock int64, toBlock int64, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}

	tokenAddr, err := utils.HexToFelt(token.ContractAddress)
	if err != nil {
		return eventCounts, fmt.Errorf("invalid token address: %w", err)
	}

	receiveAddr, err := utils.HexToFelt(address)
	if err != nil {
		return eventCounts, fmt.Errorf("invalid receive address: %w", err)
	}

	// Determine block range
	var fromBlockNum, toBlockNum uint64
	if fromBlock == 0 && toBlock == 0 {
		latest, err := s.client.GetBlockNumber(ctx)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to get latest block: %w", err)
		}
		toBlockNum = latest
		if latest > 100 {
			fromBlockNum = latest - 100
		} else {
			fromBlockNum = 0
		}
	} else {
		fromBlockNum = uint64(fromBlock)
		toBlockNum = uint64(toBlock)
	}

	// Create event filter for Transfer events to this address
	eventFilter := rpc.EventFilter{
		FromBlock: rpc.BlockID{Number: &fromBlockNum},
		ToBlock:   rpc.BlockID{Number: &toBlockNum},
		Address:   tokenAddr,
		Keys: [][]*felt.Felt{
			{starknetService.TransferSelector}, // Event selector
			{},                                 // from (any)
			{receiveAddr},                      // to (our receive address)
		},
	}

	// Fetch events
	eventsChunk, err := s.client.GetEvents(ctx, eventFilter, 100)
	if err != nil {
		return eventCounts, fmt.Errorf("failed to get transfer events: %w", err)
	}

	// Process transfer events
	addressToEvent := make(map[string]*types.TokenTransferEvent)

	for _, event := range eventsChunk.Events {
		parsed, err := s.parseTransferEvent(event, token.Decimals)
		if err != nil {
			logger.Errorf("Failed to parse Transfer event: %v", err)
			continue
		}

		toAddr := starknetService.FeltToHex(parsed.To)
		addressToEvent[toAddr] = &types.TokenTransferEvent{
			BlockNumber: int64(parsed.BlockNumber),
			TxHash:      starknetService.FeltToHex(parsed.TxHash),
			From:        starknetService.FeltToHex(parsed.From),
			To:          toAddr,
			Value:       decimal.NewFromBigInt(parsed.Amount, -int32(token.Decimals)),
		}
		eventCounts.Transfer++
	}

	// Process transfers
	if len(addressToEvent) > 0 {
		addresses := make([]string, 0, len(addressToEvent))
		for addr := range addressToEvent {
			addresses = append(addresses, addr)
		}

		err = common.ProcessTransfers(ctx, s.order, s.priorityQueue, addresses, addressToEvent, token)
		if err != nil {
			logger.Errorf("Error processing transfers: %v", err)
		}
	}

	logger.WithFields(logger.Fields{
		"Transfer": eventCounts.Transfer,
	}).Info("IndexerStarknet.IndexReceiveAddress: Completed transfer event indexing")

	return eventCounts, nil
}

// indexReceiveAddressByTransaction processes a specific transaction for receive address transfers
func (s *IndexerStarknet) indexReceiveAddressByTransaction(ctx context.Context, token *ent.Token, txHash string, transactionEvents map[string]interface{}) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}
	orderCreatedEvents := []*types.OrderCreatedEvent{}

	var gatewayEvents []interface{}

	txHashFelt, err := utils.HexToFelt(txHash)
	if err != nil {
		return eventCounts, fmt.Errorf("invalid transaction hash: %w", err)
	}
	tokenContractFelt, _ := utils.HexToFelt(token.ContractAddress)
	gatewayContractFelt, _ := utils.HexToFelt(token.Edges.Network.GatewayContractAddress)
	transferSelectorFelt, _ := utils.HexToFelt(u.TransferStarknetSelector)
	orderCreatedSelectorFelt, _ := utils.HexToFelt(u.OrderCreatedStarknetSelector)

	transferEvents, err := s.client.GetTransactionReceipt(
		ctx,
		txHashFelt,
		tokenContractFelt,
		[]*felt.Felt{transferSelectorFelt},
	)
	if err != nil && err.Error() != "no events found" {
		return eventCounts, fmt.Errorf("error getting transfer events for token %s in transaction %s: %w", token.Symbol, txHash[:10]+"...", err)
	}

	// Find OrderCreated events for this transaction
	gatewayEvents, err = s.client.GetTransactionReceipt(
		ctx,
		txHashFelt,
		gatewayContractFelt,
		[]*felt.Felt{orderCreatedSelectorFelt},
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

		// Safely extract indexed_params and non_indexed_params
		indexedParams, ok := eventParams["indexed_params"].(map[string]interface{})
		if !ok || indexedParams == nil {
			continue
		}

		nonIndexedParams, ok := eventParams["non_indexed_params"].(map[string]interface{})
		if !ok || nonIndexedParams == nil {
			continue
		}

		// Safely extract required fields
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
			TxHash:      txHash,
			Token:       ethcommon.HexToAddress(tokenStr).Hex(),
			Amount:      orderAmount,
			ProtocolFee: protocolFee,
			OrderId:     orderIdStr,
			Rate:        rate.Div(decimal.NewFromInt(100)),
			MessageHash: messageHashStr,
			Sender:      ethcommon.HexToAddress(senderStr).Hex(),
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
		err := common.ProcessCreatedOrders(ctx, token.Edges.Network, orderIds, orderIdToEvent, s.order, s.priorityQueue)
		if err != nil {
			logger.Errorf("Failed to process OrderCreated events: %v", err)
		} else {
			if token.Edges.Network.ChainID != 56 && token.Edges.Network.ChainID != 1135 {
				logger.Infof("Successfully processed %d OrderCreated events", len(orderCreatedEvents))
			}
		}
		eventCounts.OrderCreated = len(orderCreatedEvents)
	}

	return eventCounts, nil
}

// IndexGateway indexes all gateway events (OrderCreated, OrderSettled, OrderRefunded)
func (s *IndexerStarknet) IndexGateway(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}

	// Initialize client
	if err := s.initClient(ctx, network); err != nil {
		return eventCounts, err
	}

	gatewayAddr, err := utils.HexToFelt(address)
	if err != nil {
		return eventCounts, fmt.Errorf("invalid gateway address: %w", err)
	}

	// Determine block range
	var fromBlockNum, toBlockNum uint64
	if txHash != "" {
		// For specific transaction, get the block it was in
		txHashFelt, err := utils.HexToFelt(txHash)
		if err != nil {
			return eventCounts, fmt.Errorf("invalid transaction hash: %w", err)
		}

		receipt, err := s.client.GetTransactionReceipt(ctx, txHashFelt)
		if err != nil {
			return eventCounts, fmt.Errorf("failed to get transaction receipt: %w", err)
		}

		// Get block number from receipt
		switch r := receipt.(type) {
		case *rpc.InvokeTransactionReceipt:
			fromBlockNum = r.BlockNumber
			toBlockNum = r.BlockNumber
		case *rpc.DeployAccountTransactionReceipt:
			fromBlockNum = r.BlockNumber
			toBlockNum = r.BlockNumber
		default:
			return eventCounts, fmt.Errorf("unsupported receipt type")
		}
	} else {
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
	}

	logger.WithFields(logger.Fields{
		"NetworkIdentifier": network.Identifier,
		"GatewayAddress":    address,
		"FromBlock":         fromBlockNum,
		"ToBlock":           toBlockNum,
		"TxHash":            txHash,
	}).Info("IndexerStarknet.IndexGateway: Starting gateway event indexing")

	// Create event filter for all Gateway events
	eventFilter := rpc.EventFilter{
		FromBlock: rpc.BlockID{Number: &fromBlockNum},
		ToBlock:   rpc.BlockID{Number: &toBlockNum},
		Address:   gatewayAddr,
		Keys: [][]*felt.Felt{
			{
				starknetService.OrderCreatedSelector,
				starknetService.OrderSettledSelector,
				starknetService.OrderRefundedSelector,
			},
		},
	}

	// If specific tx hash, add it to filter
	if txHash != "" {
		// Starknet RPC doesn't support filtering by tx hash directly
		// We'll filter in memory after fetching
	}

	// Fetch events
	eventsChunk, err := s.client.GetEvents(ctx, eventFilter, 100)
	if err != nil {
		return eventCounts, fmt.Errorf("failed to get events: %w", err)
	}

	// Process events
	orderCreatedEvents := make(map[string]*starknetService.OrderCreatedEvent)
	orderSettledEvents := make(map[string]*starknetService.OrderSettledEvent)
	orderRefundedEvents := make(map[string]*starknetService.OrderRefundedEvent)

	for _, event := range eventsChunk.Events {
		// If filtering by tx hash, skip events from other transactions
		if txHash != "" && !strings.EqualFold(starknetService.FeltToHex(event.TransactionHash), txHash) {
			continue
		}

		if len(event.Keys) == 0 {
			continue
		}

		eventSelector := event.Keys[0]

		switch {
		case eventSelector.Equal(starknetService.OrderCreatedSelector):
			parsed, err := s.parseOrderCreatedEvent(event)
			if err != nil {
				logger.Errorf("Failed to parse OrderCreated event: %v", err)
				continue
			}
			orderCreatedEvents[starknetService.FeltToHex(event.TransactionHash)] = parsed
			eventCounts.OrderCreated++

		case eventSelector.Equal(starknetService.OrderSettledSelector):
			parsed, err := s.parseOrderSettledEvent(event)
			if err != nil {
				logger.Errorf("Failed to parse OrderSettled event: %v", err)
				continue
			}
			orderSettledEvents[starknetService.FeltToHex(event.TransactionHash)] = parsed
			eventCounts.OrderSettled++

		case eventSelector.Equal(starknetService.OrderRefundedSelector):
			parsed, err := s.parseOrderRefundedEvent(event)
			if err != nil {
				logger.Errorf("Failed to parse OrderRefunded event: %v", err)
				continue
			}
			orderRefundedEvents[starknetService.FeltToHex(event.TransactionHash)] = parsed
			eventCounts.OrderRefunded++
		}
	}

	// Process OrderCreated events
	if len(orderCreatedEvents) > 0 {
		txHashes := make([]string, 0, len(orderCreatedEvents))
		for hash := range orderCreatedEvents {
			txHashes = append(txHashes, hash)
		}

		// Convert to common format
		hashToEvent := make(map[string]*types.OrderCreatedEvent)
		for hash, evt := range orderCreatedEvents {
			hashToEvent[hash] = &types.OrderCreatedEvent{
				BlockNumber: int64(evt.BlockNumber),
				TxHash:      hash,
				Token:       starknetService.FeltToHex(evt.Token),
				Amount:      decimal.NewFromBigInt(evt.Amount, 0),
				ProtocolFee: decimal.NewFromBigInt(evt.ProtocolFee, 0),
				OrderId:     starknetService.FeltToHex(evt.OrderID),
				Rate:        decimal.NewFromBigInt(evt.Rate, -2), // Rate is in basis points
				MessageHash: evt.MessageHash,
				Sender:      starknetService.FeltToHex(evt.Sender),
			}
		}

		err = common.ProcessCreatedOrders(ctx, network, txHashes, hashToEvent, s.order, s.priorityQueue)
		if err != nil {
			logger.Errorf("Error processing created orders: %v", err)
		}
	}

	// Process OrderSettled events
	if len(orderSettledEvents) > 0 {
		for _, evt := range orderSettledEvents {
			settledEvent := &types.OrderSettledEvent{
				BlockNumber:       int64(evt.BlockNumber),
				TxHash:            starknetService.FeltToHex(evt.TxHash),
				SplitOrderId:      starknetService.FeltToHex(evt.SplitOrderID),
				OrderId:           starknetService.FeltToHex(evt.OrderID),
				LiquidityProvider: starknetService.FeltToHex(evt.LiquidityProvider),
				SettlePercent:     decimal.NewFromInt(int64(evt.SettlePercent)),
				RebatePercent:     decimal.NewFromInt(int64(evt.RebatePercent)),
			}

			// Get message hash for the order
			// This would require querying the order from database
			// For now, pass empty string
			err = common.UpdateOrderStatusSettled(ctx, network, settledEvent, "")
			if err != nil {
				logger.Errorf("Error updating settled order: %v", err)
			}
		}
	}

	// Process OrderRefunded events
	if len(orderRefundedEvents) > 0 {
		for _, evt := range orderRefundedEvents {
			refundedEvent := &types.OrderRefundedEvent{
				BlockNumber: int64(evt.BlockNumber),
				TxHash:      starknetService.FeltToHex(evt.TxHash),
				Fee:         decimal.NewFromBigInt(evt.Fee, 0),
				OrderId:     starknetService.FeltToHex(evt.OrderID),
			}

			// Get message hash for the order
			err = common.UpdateOrderStatusRefunded(ctx, network, refundedEvent, "")
			if err != nil {
				logger.Errorf("Error updating refunded order: %v", err)
			}
		}
	}

	logger.WithFields(logger.Fields{
		"OrderCreated":  eventCounts.OrderCreated,
		"OrderSettled":  eventCounts.OrderSettled,
		"OrderRefunded": eventCounts.OrderRefunded,
	}).Info("IndexerStarknet.IndexGateway: Completed gateway event indexing")

	return eventCounts, nil
}

// IndexProviderAddress indexes settlement events from providers
func (s *IndexerStarknet) IndexProviderAddress(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64, txHash string) (*types.EventCounts, error) {
	// For Starknet, provider address indexing is same as gateway indexing
	// since settlements happen through the gateway contract
	return s.IndexGateway(ctx, network, network.GatewayContractAddress, fromBlock, toBlock, txHash)
}

// parseOrderCreatedEvent parses OrderCreated event from raw event data
func (s *IndexerStarknet) parseOrderCreatedEvent(event rpc.EmittedEvent) (*starknetService.OrderCreatedEvent, error) {
	if len(event.Keys) < 4 {
		return nil, fmt.Errorf("invalid OrderCreated event: insufficient keys")
	}

	sender := event.Keys[1]
	token := event.Keys[2]
	amountLow := event.Keys[3]

	if len(event.Data) < 4 {
		return nil, fmt.Errorf("invalid OrderCreated event: insufficient data")
	}

	// Parse u256 amount (low, high)
	amountHigh := event.Data[4]
	amount := starknetService.U256FromFelts(amountLow, amountHigh)

	// Parse protocol_fee (u256)
	protocolFeeLow := event.Data[0]
	protocolFeeHigh := event.Data[1]
	protocolFee := starknetService.U256FromFelts(protocolFeeLow, protocolFeeHigh)

	orderID := event.Data[2]

	// Parse rate (u128)
	rateLow := event.Data[3]
	rateBytes := rateLow.Bytes()
	rate := new(big.Int).SetBytes(rateBytes[:])

	// Parse ByteArray message_hash starting at index 4
	messageHash := ""
	if len(event.Data) > 4 {
		messageHash = starknetService.ParseByteArray(event.Data[4:])
	}

	return &starknetService.OrderCreatedEvent{
		Sender:      sender,
		Token:       token,
		Amount:      amount,
		ProtocolFee: protocolFee,
		OrderID:     orderID,
		Rate:        rate,
		MessageHash: messageHash,
		BlockNumber: event.BlockNumber,
		TxHash:      event.TransactionHash,
	}, nil
}

// parseOrderSettledEvent parses OrderSettled event from raw event data
func (s *IndexerStarknet) parseOrderSettledEvent(event rpc.EmittedEvent) (*starknetService.OrderSettledEvent, error) {
	if len(event.Keys) < 3 {
		return nil, fmt.Errorf("invalid OrderSettled event: insufficient keys")
	}

	orderID := event.Keys[1]
	liquidityProvider := event.Keys[2]

	if len(event.Data) < 3 {
		return nil, fmt.Errorf("invalid OrderSettled event: insufficient data")
	}

	splitOrderID := event.Data[0]
	settlePercent := event.Data[1].BigInt(big.NewInt(0)).Uint64()
	rebatePercent := event.Data[2].BigInt(big.NewInt(0)).Uint64()

	return &starknetService.OrderSettledEvent{
		SplitOrderID:      splitOrderID,
		OrderID:           orderID,
		LiquidityProvider: liquidityProvider,
		SettlePercent:     settlePercent,
		RebatePercent:     rebatePercent,
		BlockNumber:       event.BlockNumber,
		TxHash:            event.TransactionHash,
	}, nil
}

// parseOrderRefundedEvent parses OrderRefunded event from raw event data
func (s *IndexerStarknet) parseOrderRefundedEvent(event rpc.EmittedEvent) (*starknetService.OrderRefundedEvent, error) {
	if len(event.Keys) < 2 {
		return nil, fmt.Errorf("invalid OrderRefunded event: insufficient keys")
	}

	orderID := event.Keys[1]

	if len(event.Data) < 2 {
		return nil, fmt.Errorf("invalid OrderRefunded event: insufficient data")
	}

	// Parse u256 fee
	feeLow := event.Data[0]
	feeHigh := event.Data[1]
	fee := starknetService.U256FromFelts(feeLow, feeHigh)

	return &starknetService.OrderRefundedEvent{
		Fee:         fee,
		OrderID:     orderID,
		BlockNumber: event.BlockNumber,
		TxHash:      event.TransactionHash,
	}, nil
}

// parseTransferEvent parses Transfer event from raw event data
func (s *IndexerStarknet) parseTransferEvent(event rpc.EmittedEvent, decimals int) (*starknetService.TokenTransferEvent, error) {
	if len(event.Keys) < 3 {
		return nil, fmt.Errorf("invalid Transfer event: insufficient keys")
	}

	from := event.Keys[1]
	to := event.Keys[2]

	if len(event.Data) < 2 {
		return nil, fmt.Errorf("invalid Transfer event: insufficient data")
	}

	// Parse u256 amount
	amountLow := event.Data[0]
	amountHigh := event.Data[1]
	amount := starknetService.U256FromFelts(amountLow, amountHigh)

	return &starknetService.TokenTransferEvent{
		From:        from,
		To:          to,
		Amount:      amount,
		BlockNumber: event.BlockNumber,
		TxHash:      event.TransactionHash,
	}, nil
}
