package indexer

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/services/contracts"
	"github.com/paycrest/aggregator/services/order"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

var orderConf = config.OrderConfig()

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

// IndexTransfer indexes transfers to the receive address for Tron network.
func (s *IndexerTron) IndexTransfer(ctx context.Context, token *ent.Token, address string, fromBlock int64, toBlock int64) error {
	res, err := fastshot.NewClient(token.Edges.Network.RPCEndpoint).
		Config().SetTimeout(15 * time.Second).
		Build().GET(fmt.Sprintf("/v1/contracts/%s/events", token.ContractAddress)).
		Query().AddParams(map[string]string{
		"only_confirmed":      "true",
		"min_block_timestamp": strconv.FormatInt(fromBlock, 10),
		"max_block_timestamp": strconv.FormatInt(toBlock, 10),
		"order_by":            "block_timestamp,asc",
		"limit":               "200",
	}).
		Send()
	if err != nil {
		return fmt.Errorf("IndexTransfer.getTransferEventData: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return fmt.Errorf("IndexTransfer.parseJSONResponse: %w", err)
	}

	unknownAddresses := []string{}
	addressToEvent := make(map[string]*types.TokenTransferEvent)

	for _, r := range data["data"].([]interface{}) {
		if r.(map[string]interface{})["event_name"].(string) == "Transfer" {
			fromAddress := r.(map[string]interface{})["result"].(map[string]interface{})["from"].(string)

			if strings.EqualFold(fromAddress, token.Edges.Network.GatewayContractAddress) {
				continue
			}

			transferValue, err := decimal.NewFromString(r.(map[string]interface{})["result"].(map[string]interface{})["value"].(string))
			if err != nil {
				return fmt.Errorf("IndexTransfer.decimal.NewFromString: %w", err)
			}

			transferEvent := &types.TokenTransferEvent{
				BlockNumber: int64(r.(map[string]interface{})["block_number"].(float64)),
				TxHash:      r.(map[string]interface{})["transaction_id"].(string),
				From:        fromAddress,
				To:          r.(map[string]interface{})["result"].(map[string]interface{})["to"].(string),
				Value:       transferValue.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(token.Decimals)))),
			}

			unknownAddresses = append(unknownAddresses, transferEvent.To)
			addressToEvent[transferEvent.To] = transferEvent
		}
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

// IndexOrderCreated indexes orders created in the Gateway contract for the Tron network.
func (s *IndexerTron) IndexOrderCreated(ctx context.Context, network *ent.Network, fromBlock int64, toBlock int64) error {
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
		return fmt.Errorf("IndexOrderCreated.getEvents: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return fmt.Errorf("IndexOrderCreated.parseJSONResponse: %w", err)
	}

	txHashes := []string{}
	hashToEvent := make(map[string]*types.OrderCreatedEvent)

	for _, r := range data["data"].([]interface{}) {
		if r.(map[string]interface{})["event_name"].(string) == "OrderCreated" {
			// fetch the transaction
			res, err = fastshot.NewClient(network.RPCEndpoint).
				Config().SetTimeout(15 * time.Second).
				Build().POST("/wallet/gettransactioninfobyid").
				Body().AsJSON(map[string]interface{}{
				"value": r.(map[string]interface{})["transaction_id"].(string),
			}).
				Send()
			if err != nil {
				return fmt.Errorf("IndexOrderCreated.getTransaction: %w", err)
			}

			data, err := utils.ParseJSONResponse(res.RawResponse)
			if err != nil {
				return fmt.Errorf("IndexOrderCreated.parseJSONResponse: %w", err)
			}

			// Parse event data
			for _, event := range data["log"].([]interface{}) {
				eventData := event.(map[string]interface{})
				if eventData["topics"].([]interface{})[0] == "40ccd1ceb111a3c186ef9911e1b876dc1f789ed331b86097b3b8851055b6a137" {
					unpackedEventData, err := utils.UnpackEventData(eventData["data"].(string), contracts.GatewayMetaData.ABI, "OrderCreated")
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error":   fmt.Sprintf("%v", err),
							"TxHash":  data["id"].(string),
							"Network": network.Identifier,
						}).Errorf("Failed to unpack event data for %s", network.Identifier)
						return err
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
		return fmt.Errorf("IndexOrderCreated.processCreatedOrders: %w", err)
	}

	return nil
}

// IndexOrderSettled indexes orders settled in the Gateway contract for the Tron network.
func (s *IndexerTron) IndexOrderSettled(ctx context.Context, network *ent.Network, fromBlock int64, toBlock int64) error {
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
		return fmt.Errorf("IndexOrderSettled.getEvents: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return fmt.Errorf("IndexOrderSettled.parseJSONResponse: %w", err)
	}

	txHashes := []string{}
	hashToEvent := make(map[string]*types.OrderSettledEvent)

	for _, r := range data["data"].([]interface{}) {
		if r.(map[string]interface{})["event_name"].(string) == "OrderSettled" {
			// fetch the transaction
			res, err = fastshot.NewClient(network.RPCEndpoint).
				Config().SetTimeout(15 * time.Second).
				Build().POST("/wallet/gettransactioninfobyid").
				Body().AsJSON(map[string]interface{}{
				"value": r.(map[string]interface{})["transaction_id"].(string),
			}).
				Send()
			if err != nil {
				return fmt.Errorf("IndexOrderSettled.getTransaction: %w", err)
			}

			data, err := utils.ParseJSONResponse(res.RawResponse)
			if err != nil {
				return fmt.Errorf("IndexOrderSettled.parseJSONResponse: %w", err)
			}

			// Parse event data
			for _, event := range data["log"].([]interface{}) {
				eventData := event.(map[string]interface{})
				if eventData["topics"].([]interface{})[0] == "98ece21e01a01cbe1d1c0dad3b053c8fbd368f99be78be958fcf1d1d13fd249a" {
					unpackedEventData, err := utils.UnpackEventData(eventData["data"].(string), contracts.GatewayMetaData.ABI, "OrderSettled")
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error":   fmt.Sprintf("%v", err),
							"TxHash":  data["id"].(string),
							"Network": network.Identifier,
						}).Errorf("Failed to unpack event data for %s", network.Identifier)
						return err
					}

					eventSplitOrderId := unpackedEventData[0].([32]byte)
					eventOrderId := utils.ParseTopicToByte32(eventData["topics"].([]interface{})[1].(string))
					settledEvent := &types.OrderSettledEvent{
						BlockNumber:       int64(data["blockNumber"].(float64)),
						TxHash:            data["id"].(string),
						SplitOrderId:      fmt.Sprintf("0x%v", hex.EncodeToString(eventSplitOrderId[:])),
						OrderId:           fmt.Sprintf("0x%v", hex.EncodeToString(eventOrderId[:])),
						LiquidityProvider: utils.ParseTopicToTronAddress(eventData["topics"].([]interface{})[2].(string)),
						SettlePercent:     decimal.NewFromBigInt(unpackedEventData[1].(*big.Int), 0),
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
		return fmt.Errorf("IndexOrderSettled.processSettledOrders: %w", err)
	}

	return nil
}

// IndexOrderRefunded indexes orders settled in the Gateway contract for the Tron network.
func (s *IndexerTron) IndexOrderRefunded(ctx context.Context, network *ent.Network, fromBlock int64, toBlock int64) error {
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
		return fmt.Errorf("IndexOrderRefunded.getEvents: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return fmt.Errorf("IndexOrderRefunded.parseJSONResponse: %w", err)
	}

	txHashes := []string{}
	hashToEvent := make(map[string]*types.OrderRefundedEvent)

	for _, r := range data["data"].([]interface{}) {
		if r.(map[string]interface{})["event_name"].(string) == "OrderCreated" {
			// fetch the transaction
			res, err = fastshot.NewClient(network.RPCEndpoint).
				Config().SetTimeout(15 * time.Second).
				Build().POST("/wallet/gettransactioninfobyid").
				Body().AsJSON(map[string]interface{}{
				"value": r.(map[string]interface{})["transaction_id"].(string),
			}).
				Send()
			if err != nil {
				return fmt.Errorf("IndexOrderRefunded.getTransaction: %w", err)
			}

			data, err := utils.ParseJSONResponse(res.RawResponse)
			if err != nil {
				return fmt.Errorf("IndexOrderRefunded.parseJSONResponse: %w", err)
			}

			// Parse event data
			for _, event := range data["log"].([]interface{}) {
				eventData := event.(map[string]interface{})
				if eventData["topics"].([]interface{})[0] == "0736fe428e1747ca8d387c2e6fa1a31a0cde62d3a167c40a46ade59a3cdc828e" {
					unpackedEventData, err := utils.UnpackEventData(eventData["data"].(string), contracts.GatewayMetaData.ABI, "OrderRefunded")
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error":   fmt.Sprintf("%v", err),
							"TxHash":  data["id"].(string),
							"Network": network.Identifier,
						}).Errorf("Failed to unpack event data for %s", network.Identifier)
						return err
					}

					eventOrderId := utils.ParseTopicToByte32(eventData["topics"].([]interface{})[1].(string))
					refundedEvent := &types.OrderRefundedEvent{
						BlockNumber: int64(data["blockNumber"].(float64)),
						TxHash:      data["id"].(string),
						OrderId:     fmt.Sprintf("0x%v", hex.EncodeToString(eventOrderId[:])),
						Fee:         utils.FromSubunit(unpackedEventData[0].(*big.Int), 0),
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
		return fmt.Errorf("IndexOrderRefunded.processRefundedOrders: %w", err)
	}

	return nil
}
