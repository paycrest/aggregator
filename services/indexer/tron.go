package indexer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/services/contracts"
	"github.com/paycrest/aggregator/services/order"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

// IndexerTron performs blockchain to database extract, transform, load (ETL) operations.
type IndexerTron struct {
	priorityQueue *services.PriorityQueueService
	order         types.OrderService
}

// NewIndexerTron creates a new instance of IndexerTron.
func NewIndexerTron() types.Indexer {
	priorityQueue := services.NewPriorityQueueService()
	orderService := order.NewOrderTron()

	return &IndexerTron{
		priorityQueue: priorityQueue,
		order:         orderService,
	}
}

// IndexReceiveAddress indexes transfers to receive/linked addresses from user transaction history
func (s *IndexerTron) IndexReceiveAddress(ctx context.Context, token *ent.Token, address string, fromBlock int64, toBlock int64, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}

	// If txHash is provided, process that specific transaction
	if txHash != "" {
		err := s.indexReceiveAddressByTransaction(ctx, token, txHash)
		if err != nil {
			return eventCounts, err
		}
		// For transaction-specific indexing, we can't determine exact counts without parsing events
		// Return empty counts for now
		return eventCounts, nil
	}

	// If only address is provided (no txHash, no block range), fetch user's transaction history
	if address != "" && fromBlock == 0 && toBlock == 0 {
		err := s.indexReceiveAddressByUserAddress(ctx, token, address)
		return eventCounts, err
	}

	// If address is provided with block range, fetch user's transactions within that range
	if address != "" && (fromBlock > 0 || toBlock > 0) {
		err := s.indexReceiveAddressByUserAddressInRange(ctx, token, address, fromBlock, toBlock)
		return eventCounts, err
	}

	// If only block range is provided, this is not applicable for receive address indexing
	return eventCounts, fmt.Errorf("receive address indexing requires an address parameter")
}

// indexReceiveAddressByTransaction processes a specific transaction for receive address transfers
func (s *IndexerTron) indexReceiveAddressByTransaction(ctx context.Context, token *ent.Token, txHash string) error {
	// For Tron, we need to get the transaction info and look for transfer events
	res, err := fastshot.NewClient(token.Edges.Network.RPCEndpoint).
		Config().SetTimeout(15 * time.Second).
		Build().POST("/wallet/gettransactioninfobyid").
		Body().AsJSON(map[string]interface{}{
		"value": txHash,
	}).
		Send()
	if err != nil {
		return fmt.Errorf("error getting transaction info for token %s: %w", token.Symbol, err)
	}

	// Check for HTTP errors first (preserving original logic)
	if res.StatusCode() >= 500 { // Return on server errors
		return fmt.Errorf("%d", res.StatusCode())
	}
	if res.StatusCode() >= 400 { // Return on client errors
		return fmt.Errorf("%d", res.StatusCode())
	}

	// Parse JSON response using fastshot's RawBody method
	body, err := io.ReadAll(res.RawBody())
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return fmt.Errorf("error parsing transaction response for token %s: %w", token.Symbol, err)
	}

	// Process transfer events from this transaction
	for _, event := range data["log"].([]interface{}) {
		eventData := event.(map[string]interface{})
		eventSignature := eventData["topics"].([]interface{})[0].(string)

		// Check if this is a transfer event for this token contract
		if eventSignature == utils.TransferEventSignature && eventData["address"].(string) == token.ContractAddress {
			// Extract transfer data
			fromAddress := utils.ParseTopicToTronAddress(eventData["topics"].([]interface{})[1].(string))
			toAddress := utils.ParseTopicToTronAddress(eventData["topics"].([]interface{})[2].(string))
			valueStr := eventData["data"].(string)

			// Skip if transfer is from gateway contract
			if strings.EqualFold(fromAddress, token.Edges.Network.GatewayContractAddress) {
				continue
			}

			// Parse transfer value (data field contains the value as hex)
			transferValueBytes, err := hex.DecodeString(valueStr)
			if err != nil {
				logger.Errorf("Error parsing transfer value for token %s: %v", token.Symbol, err)
				continue
			}
			transferValue := new(big.Int).SetBytes(transferValueBytes)

			// Create transfer event
			transferEvent := &types.TokenTransferEvent{
				BlockNumber: int64(data["blockNumber"].(float64)),
				TxHash:      data["id"].(string),
				From:        fromAddress,
				To:          toAddress,
				Value:       utils.FromSubunit(transferValue, int8(token.Decimals)),
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
		}
	}

	return nil
}

// indexReceiveAddressByUserAddress processes user's transaction history for receive address transfers
func (s *IndexerTron) indexReceiveAddressByUserAddress(ctx context.Context, token *ent.Token, userAddress string) error {
	// For Tron, we need to implement a different approach since we don't have user transaction history
	// This would require implementing a way to get user's transaction history from Tron network
	// For now, we'll log that this is not implemented
	logger.Infof("User address indexing not implemented for Tron network: %s", userAddress)
	return nil
}

// indexReceiveAddressByUserAddressInRange processes user's transaction history within a block range for receive address transfers
func (s *IndexerTron) indexReceiveAddressByUserAddressInRange(ctx context.Context, token *ent.Token, userAddress string, fromBlock int64, toBlock int64) error {
	// For Tron, we need to implement a different approach since we don't have user transaction history
	// This would require implementing a way to get user's transaction history from Tron network
	// For now, we'll log that this is not implemented
	logger.Infof("User address indexing with block range not implemented for Tron network: %s (%d-%d)", userAddress, fromBlock, toBlock)
	return nil
}

// IndexGateway indexes all Gateway contract events (OrderCreated, OrderSettled, OrderRefunded) in a single call
func (s *IndexerTron) IndexGateway(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}
	if txHash != "" {
		// If txHash is provided, get transaction info directly
		res, err := fastshot.NewClient(network.RPCEndpoint).
			Config().SetTimeout(15 * time.Second).
			Build().POST("/wallet/gettransactioninfobyid").
			Body().AsJSON(map[string]interface{}{
			"value": txHash,
		}).
			Send()
		if err != nil {
			return eventCounts, fmt.Errorf("IndexGateway.getTransaction: %w", err)
		}

		// Check for HTTP errors first (preserving original logic)
		if res.StatusCode() >= 500 { // Return on server errors
			return eventCounts, fmt.Errorf("%d", res.StatusCode())
		}
		if res.StatusCode() >= 400 { // Return on client errors
			return eventCounts, fmt.Errorf("%d", res.StatusCode())
		}

		// Parse JSON response using fastshot's RawBody method
		body, err := io.ReadAll(res.RawBody())
		if err != nil {
			return eventCounts, fmt.Errorf("failed to read response body: %w", err)
		}

		var data map[string]interface{}
		err = json.Unmarshal(body, &data)
		if err != nil {
			return eventCounts, fmt.Errorf("IndexGateway.parseJSONResponse: %w", err)
		}

		// Process all events from this transaction
		orderCreatedEvents := []*types.OrderCreatedEvent{}
		orderSettledEvents := []*types.OrderSettledEvent{}
		orderRefundedEvents := []*types.OrderRefundedEvent{}

		for _, event := range data["log"].([]interface{}) {
			eventData := event.(map[string]interface{})
			eventSignature := eventData["topics"].([]interface{})[0].(string)

			switch eventSignature {
			case "40ccd1ceb111a3c186ef9911e1b876dc1f789ed331b86097b3b8851055b6a137": // OrderCreated
				unpackedEventData, err := utils.UnpackEventData(eventData["data"].(string), contracts.GatewayMetaData.ABI, "OrderCreated")
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":   fmt.Sprintf("%v", err),
						"TxHash":  data["id"].(string),
						"Network": network.Identifier,
					}).Errorf("Failed to unpack OrderCreated event data for %s", network.Identifier)
					continue
				}

				orderAmount := utils.ParseTopicToBigInt(eventData["topics"].([]interface{})[3].(string))
				protocolFee := unpackedEventData[0].(*big.Int)
				rate := unpackedEventData[1].(*big.Int)
				orderId := unpackedEventData[2].(string)
				messageHash := unpackedEventData[3].(string)

				createdEvent := &types.OrderCreatedEvent{
					BlockNumber: int64(data["blockNumber"].(float64)),
					TxHash:      data["id"].(string),
					Token:       utils.ParseTopicToTronAddress(eventData["topics"].([]interface{})[2].(string)),
					Amount:      utils.FromSubunit(orderAmount, 0),
					ProtocolFee: utils.FromSubunit(protocolFee, 0),
					OrderId:     orderId,
					Rate:        utils.FromSubunit(rate, 0),
					MessageHash: messageHash,
					Sender:      utils.ParseTopicToTronAddress(eventData["topics"].([]interface{})[1].(string)),
				}
				orderCreatedEvents = append(orderCreatedEvents, createdEvent)

			case "98ece21e01a01cbe1d1c0dad3b053c8fbd368f99be78be958fcf1d1d13fd249a": // OrderSettled
				unpackedEventData, err := utils.UnpackEventData(eventData["data"].(string), contracts.GatewayMetaData.ABI, "OrderSettled")
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":   fmt.Sprintf("%v", err),
						"TxHash":  data["id"].(string),
						"Network": network.Identifier,
					}).Errorf("Failed to unpack OrderSettled event data for %s", network.Identifier)
					continue
				}

				splitOrderId := unpackedEventData[0].(string)
				settlePercent := unpackedEventData[1].(*big.Int)
				eventOrderId := utils.ParseTopicToByte32Flexible(eventData["topics"].([]interface{})[1])
				liquidityProvider := utils.ParseTopicToTronAddress(eventData["topics"].([]interface{})[2].(string))

				settledEvent := &types.OrderSettledEvent{
					BlockNumber:       int64(data["blockNumber"].(float64)),
					TxHash:            data["id"].(string),
					SplitOrderId:      splitOrderId,
					OrderId:           fmt.Sprintf("0x%v", hex.EncodeToString(eventOrderId[:])),
					LiquidityProvider: liquidityProvider,
					SettlePercent:     utils.FromSubunit(settlePercent, 0),
				}
				orderSettledEvents = append(orderSettledEvents, settledEvent)

			case "0736fe428e1747ca8d387c2e6fa1a31a0cde62d3a167c40a46ade59a3cdc828e": // OrderRefunded
				unpackedEventData, err := utils.UnpackEventData(eventData["data"].(string), contracts.GatewayMetaData.ABI, "OrderRefunded")
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":   fmt.Sprintf("%v", err),
						"TxHash":  data["id"].(string),
						"Network": network.Identifier,
					}).Errorf("Failed to unpack OrderRefunded event data for %s", network.Identifier)
					continue
				}

				fee := unpackedEventData[0].(*big.Int)
				eventOrderId := utils.ParseTopicToByte32Flexible(eventData["topics"].([]interface{})[1])

				refundedEvent := &types.OrderRefundedEvent{
					BlockNumber: int64(data["blockNumber"].(float64)),
					TxHash:      data["id"].(string),
					OrderId:     fmt.Sprintf("0x%v", hex.EncodeToString(eventOrderId[:])),
					Fee:         utils.FromSubunit(fee, 0),
				}
				orderRefundedEvents = append(orderRefundedEvents, refundedEvent)
			}
		}

		// Process all events
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

		return eventCounts, nil
	}

	// For block range queries, Tron doesn't support getting all events in one call
	// so we need to make separate API calls for each event type
	// This is a limitation of the Tron API - it doesn't support filtering by multiple event signatures

	// Index OrderCreated events
	if err := s.indexOrderCreatedByBlockRange(ctx, network, fromBlock, toBlock); err != nil {
		logger.WithFields(logger.Fields{
			"Error":        fmt.Sprintf("%v", err),
			"NetworkParam": network.Identifier,
			"FromBlock":    fromBlock,
			"ToBlock":      toBlock,
			"EventType":    "OrderCreated",
		}).Errorf("Failed to index OrderCreated events")
	}

	// Index OrderSettled events
	if err := s.indexOrderSettledByBlockRange(ctx, network, fromBlock, toBlock); err != nil {
		logger.WithFields(logger.Fields{
			"Error":        fmt.Sprintf("%v", err),
			"NetworkParam": network.Identifier,
			"FromBlock":    fromBlock,
			"ToBlock":      toBlock,
			"EventType":    "OrderSettled",
		}).Errorf("Failed to index OrderSettled events")
	}

	// Index OrderRefunded events
	if err := s.indexOrderRefundedByBlockRange(ctx, network, fromBlock, toBlock); err != nil {
		logger.WithFields(logger.Fields{
			"Error":        fmt.Sprintf("%v", err),
			"NetworkParam": network.Identifier,
			"FromBlock":    fromBlock,
			"ToBlock":      toBlock,
			"EventType":    "OrderRefunded",
		}).Errorf("Failed to index OrderRefunded events")
	}

	return eventCounts, nil
}

// IndexProviderAddress indexes OrderSettled events for a provider address
func (s *IndexerTron) IndexProviderAddress(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64, txHash string) (*types.EventCounts, error) {
	eventCounts := &types.EventCounts{}

	// For Tron, we need to implement a different approach since we don't have provider address transaction history
	// This would require implementing a way to get provider's transaction history from Tron network
	// For now, we'll log that this is not implemented
	logger.Infof("Provider address indexing not implemented for Tron network: %s", address)
	return eventCounts, nil
}

// indexOrderCreatedByBlockRange indexes OrderCreated events for a block range
func (s *IndexerTron) indexOrderCreatedByBlockRange(ctx context.Context, network *ent.Network, fromBlock int64, toBlock int64) error {
	res, err := fastshot.NewClient(network.RPCEndpoint).
		Config().SetTimeout(15 * time.Second).
		Build().GET(fmt.Sprintf("/v1/contracts/%s/events", network.GatewayContractAddress)).
		Query().AddParams(map[string]string{
		"min_block_timestamp": strconv.FormatInt(fromBlock, 10),
		"max_block_timestamp": strconv.FormatInt(toBlock, 10),
		"order_by":            "block_timestamp,asc",
		"limit":               "200",
	}).
		Send()
	if err != nil {
		return fmt.Errorf("indexOrderCreatedByBlockRange.getEvents: %w", err)
	}
	// Check for HTTP errors first (preserving original logic)
	if res.StatusCode() >= 500 { // Return on server errors
		return fmt.Errorf("%d", res.StatusCode())
	}
	if res.StatusCode() >= 400 { // Return on client errors
		return fmt.Errorf("%d", res.StatusCode())
	}

	// Parse JSON response using fastshot's RawBody method
	body, err := io.ReadAll(res.RawBody())
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return fmt.Errorf("indexOrderCreatedByBlockRange.parseJSONResponse: %w", err)
	}
	txHashes := []string{}
	hashToEvent := make(map[string]*types.OrderCreatedEvent)
	for _, r := range data["data"].([]interface{}) {
		if r.(map[string]interface{})["event_name"].(string) == "OrderCreated" {
			res, err := fastshot.NewClient(network.RPCEndpoint).
				Config().SetTimeout(15 * time.Second).
				Build().POST("/wallet/gettransactioninfobyid").
				Body().AsJSON(map[string]interface{}{"value": r.(map[string]interface{})["transaction_id"].(string)}).
				Send()
			if err != nil {
				return fmt.Errorf("indexOrderCreatedByBlockRange.getTransaction: %w", err)
			}
			// Check for HTTP errors first (preserving original logic)
			if res.StatusCode() >= 500 { // Return on server errors
				return fmt.Errorf("%d", res.StatusCode())
			}
			if res.StatusCode() >= 400 { // Return on client errors
				return fmt.Errorf("%d", res.StatusCode())
			}

			// Parse JSON response using fastshot's RawBody method
			body, err := io.ReadAll(res.RawBody())
			if err != nil {
				return fmt.Errorf("failed to read response body: %w", err)
			}

			var data map[string]interface{}
			err = json.Unmarshal(body, &data)
			if err != nil {
				return fmt.Errorf("indexOrderCreatedByBlockRange.parseJSONResponse: %w", err)
			}
			for _, event := range data["log"].([]interface{}) {
				eventData := event.(map[string]interface{})
				if eventData["topics"].([]interface{})[0] == "40ccd1ceb111a3c186ef9911e1b876dc1f789ed331b86097b3b8851055b6a137" {
					unpackedEventData, err := utils.UnpackEventData(eventData["data"].(string), contracts.GatewayMetaData.ABI, "OrderCreated")
					if err != nil {
						continue
					}
					eventOrderId := unpackedEventData[1].([32]byte)
					createdEvent := &types.OrderCreatedEvent{
						BlockNumber: int64(data["blockNumber"].(float64)),
						TxHash:      data["id"].(string),
						Token:       utils.ParseTopicToTronAddress(eventData["topics"].([]interface{})[2].(string)),
						Amount:      utils.FromSubunit(utils.ParseTopicToBigInt(eventData["topics"].([]interface{})[3].(string)), 0),
						ProtocolFee: utils.FromSubunit(unpackedEventData[0].(*big.Int), 0),
						OrderId:     fmt.Sprintf("0x%v", hex.EncodeToString(eventOrderId[:])),
						Rate:        utils.FromSubunit(unpackedEventData[2].(*big.Int), 2),
						MessageHash: unpackedEventData[3].(string),
						Sender:      utils.ParseTopicToTronAddress(eventData["topics"].([]interface{})[1].(string)),
					}
					txHashes = append(txHashes, createdEvent.TxHash)
					hashToEvent[createdEvent.TxHash] = createdEvent
					break
				}
			}
		}
	}
	if len(txHashes) == 0 {
		return nil
	}
	err = common.ProcessCreatedOrders(ctx, network, txHashes, hashToEvent, s.order, s.priorityQueue)
	if err != nil {
		return fmt.Errorf("indexOrderCreatedByBlockRange.processCreatedOrders: %w", err)
	}
	return nil
}

// indexOrderSettledByBlockRange indexes OrderSettled events for a block range
func (s *IndexerTron) indexOrderSettledByBlockRange(ctx context.Context, network *ent.Network, fromBlock int64, toBlock int64) error {
	res, err := fastshot.NewClient(network.RPCEndpoint).
		Config().SetTimeout(15 * time.Second).
		Build().GET(fmt.Sprintf("/v1/contracts/%s/events", network.GatewayContractAddress)).
		Query().AddParams(map[string]string{
		"min_block_timestamp": strconv.FormatInt(fromBlock, 10),
		"max_block_timestamp": strconv.FormatInt(toBlock, 10),
		"order_by":            "block_timestamp,asc",
		"limit":               "200",
	}).
		Send()
	if err != nil {
		return fmt.Errorf("indexOrderSettledByBlockRange.getEvents: %w", err)
	}
	// Check for HTTP errors first (preserving original logic)
	if res.StatusCode() >= 500 { // Return on server errors
		return fmt.Errorf("%d", res.StatusCode())
	}
	if res.StatusCode() >= 400 { // Return on client errors
		return fmt.Errorf("%d", res.StatusCode())
	}

	// Parse JSON response using fastshot's RawBody method
	body, err := io.ReadAll(res.RawBody())
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return fmt.Errorf("indexOrderSettledByBlockRange.parseJSONResponse: %w", err)
	}
	txHashes := []string{}
	hashToEvent := make(map[string]*types.OrderSettledEvent)
	for _, r := range data["data"].([]interface{}) {
		if r.(map[string]interface{})["event_name"].(string) == "OrderSettled" {
			res, err := fastshot.NewClient(network.RPCEndpoint).
				Config().SetTimeout(15 * time.Second).
				Build().POST("/wallet/gettransactioninfobyid").
				Body().AsJSON(map[string]interface{}{"value": r.(map[string]interface{})["transaction_id"].(string)}).
				Send()
			if err != nil {
				return fmt.Errorf("indexOrderSettledByBlockRange.getTransaction: %w", err)
			}
			// Check for HTTP errors first (preserving original logic)
			if res.StatusCode() >= 500 { // Return on server errors
				return fmt.Errorf("%d", res.StatusCode())
			}
			if res.StatusCode() >= 400 { // Return on client errors
				return fmt.Errorf("%d", res.StatusCode())
			}

			// Parse JSON response using fastshot's RawBody method
			body, err := io.ReadAll(res.RawBody())
			if err != nil {
				return fmt.Errorf("failed to read response body: %w", err)
			}

			var data map[string]interface{}
			err = json.Unmarshal(body, &data)
			if err != nil {
				return fmt.Errorf("indexOrderSettledByBlockRange.parseJSONResponse: %w", err)
			}
			for _, event := range data["log"].([]interface{}) {
				eventData := event.(map[string]interface{})
				if eventData["topics"].([]interface{})[0] == "98ece21e01a01cbe1d1c0dad3b053c8fbd368f99be78be958fcf1d1d13fd249a" {
					unpackedEventData, err := utils.UnpackEventData(eventData["data"].(string), contracts.GatewayMetaData.ABI, "OrderSettled")
					if err != nil {
						continue
					}
					splitOrderId := unpackedEventData[0].(string)
					settlePercent := unpackedEventData[1].(*big.Int)
					eventOrderId := utils.ParseTopicToByte32Flexible(eventData["topics"].([]interface{})[1])
					liquidityProvider := utils.ParseTopicToTronAddress(eventData["topics"].([]interface{})[2].(string))
					settledEvent := &types.OrderSettledEvent{
						BlockNumber:       int64(data["blockNumber"].(float64)),
						TxHash:            data["id"].(string),
						SplitOrderId:      splitOrderId,
						OrderId:           fmt.Sprintf("0x%v", hex.EncodeToString(eventOrderId[:])),
						LiquidityProvider: liquidityProvider,
						SettlePercent:     utils.FromSubunit(settlePercent, 0),
					}
					txHashes = append(txHashes, settledEvent.TxHash)
					hashToEvent[settledEvent.TxHash] = settledEvent
					break
				}
			}
		}
	}
	if len(txHashes) == 0 {
		return nil
	}
	err = common.ProcessSettledOrders(ctx, network, txHashes, hashToEvent)
	if err != nil {
		return fmt.Errorf("indexOrderSettledByBlockRange.processSettledOrders: %w", err)
	}
	return nil
}

// indexOrderRefundedByBlockRange indexes OrderRefunded events for a block range
func (s *IndexerTron) indexOrderRefundedByBlockRange(ctx context.Context, network *ent.Network, fromBlock int64, toBlock int64) error {
	res, err := fastshot.NewClient(network.RPCEndpoint).
		Config().SetTimeout(15 * time.Second).
		Build().GET(fmt.Sprintf("/v1/contracts/%s/events", network.GatewayContractAddress)).
		Query().AddParams(map[string]string{
		"min_block_timestamp": strconv.FormatInt(fromBlock, 10),
		"max_block_timestamp": strconv.FormatInt(toBlock, 10),
		"order_by":            "block_timestamp,asc",
		"limit":               "200",
	}).
		Send()
	if err != nil {
		return fmt.Errorf("indexOrderRefundedByBlockRange.getEvents: %w", err)
	}
	// Check for HTTP errors first (preserving original logic)
	if res.StatusCode() >= 500 { // Return on server errors
		return fmt.Errorf("%d", res.StatusCode())
	}
	if res.StatusCode() >= 400 { // Return on client errors
		return fmt.Errorf("%d", res.StatusCode())
	}

	// Parse JSON response using fastshot's RawBody method
	body, err := io.ReadAll(res.RawBody())
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return fmt.Errorf("indexOrderRefundedByBlockRange.parseJSONResponse: %w", err)
	}
	txHashes := []string{}
	hashToEvent := make(map[string]*types.OrderRefundedEvent)
	for _, r := range data["data"].([]interface{}) {
		if r.(map[string]interface{})["event_name"].(string) == "OrderRefunded" {
			res, err := fastshot.NewClient(network.RPCEndpoint).
				Config().SetTimeout(15 * time.Second).
				Build().POST("/wallet/gettransactioninfobyid").
				Body().AsJSON(map[string]interface{}{"value": r.(map[string]interface{})["transaction_id"].(string)}).
				Send()
			if err != nil {
				return fmt.Errorf("indexOrderRefundedByBlockRange.getTransaction: %w", err)
			}
			// Check for HTTP errors first (preserving original logic)
			if res.StatusCode() >= 500 { // Return on server errors
				return fmt.Errorf("%d", res.StatusCode())
			}
			if res.StatusCode() >= 400 { // Return on client errors
				return fmt.Errorf("%d", res.StatusCode())
			}

			// Parse JSON response using fastshot's RawBody method
			body, err := io.ReadAll(res.RawBody())
			if err != nil {
				return fmt.Errorf("failed to read response body: %w", err)
			}

			var data map[string]interface{}
			err = json.Unmarshal(body, &data)
			if err != nil {
				return fmt.Errorf("indexOrderRefundedByBlockRange.parseJSONResponse: %w", err)
			}
			for _, event := range data["log"].([]interface{}) {
				eventData := event.(map[string]interface{})
				if eventData["topics"].([]interface{})[0] == "0736fe428e1747ca8d387c2e6fa1a31a0cde62d3a167c40a46ade59a3cdc828e" {
					unpackedEventData, err := utils.UnpackEventData(eventData["data"].(string), contracts.GatewayMetaData.ABI, "OrderRefunded")
					if err != nil {
						continue
					}
					fee := unpackedEventData[0].(*big.Int)
					eventOrderId := utils.ParseTopicToByte32Flexible(eventData["topics"].([]interface{})[1])
					refundedEvent := &types.OrderRefundedEvent{
						BlockNumber: int64(data["blockNumber"].(float64)),
						TxHash:      data["id"].(string),
						OrderId:     fmt.Sprintf("0x%v", hex.EncodeToString(eventOrderId[:])),
						Fee:         utils.FromSubunit(fee, 0),
					}
					txHashes = append(txHashes, refundedEvent.TxHash)
					hashToEvent[refundedEvent.TxHash] = refundedEvent
					break
				}
			}
		}
	}
	if len(txHashes) == 0 {
		return nil
	}
	err = common.ProcessRefundedOrders(ctx, network, txHashes, hashToEvent)
	if err != nil {
		return fmt.Errorf("indexOrderRefundedByBlockRange.processRefundedOrders: %w", err)
	}
	return nil
}
