package indexer

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/services/contracts"
	"github.com/paycrest/aggregator/services/order"
	"github.com/paycrest/aggregator/storage"
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
func (s *IndexerTron) IndexTransfer(ctx context.Context, rpcClient types.RPCClient, order *ent.PaymentOrder, token *ent.Token, fromBlock int64, toBlock int64) error {
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
			fmt.Println(r.(map[string]interface{})["result"].(map[string]interface{})["to"].(string))
			fmt.Println(r.(map[string]interface{})["result"].(map[string]interface{}))

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

	// Process receive addresses and update their status
	if err := common.ProcessReceiveAddresses(ctx, s.order, s.priorityQueue, unknownAddresses, addressToEvent); err != nil {
		return err
	}

	// Process linked addresses and create payment orders
	if err := common.ProcessLinkedAddresses(ctx, s.order, unknownAddresses, addressToEvent, token); err != nil {
		return err
	}

	return nil
}

// IndexOrderCreated indexes orders created in the Gateway contract for the Tron network.
func (s *IndexerTron) IndexOrderCreated(ctx context.Context, rpcClient types.RPCClient, order *ent.PaymentOrder, network *ent.Network, fromBlock int64, toBlock int64) error {
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
							"Error": fmt.Sprintf("%v", err),
						}).Errorf("Failed to unpack event data for %s", order.Edges.Token.Edges.Network.Identifier)
						return err
					}

					eventOrderId := unpackedEventData[1].([32]byte)
					createdEvent := &types.OrderCreatedEvent{
						BlockNumber: int64(data["blockNumber"].(float64)),
						TxHash:      data["id"].(string),
						Token:       utils.ParseTopicToTronAddress(eventData["topics"].([]interface{})[2].(string)),
						Amount:      utils.FromSubunit(utils.ParseTopicToBigInt(eventData["topics"].([]interface{})[3].(string)), order.Edges.Token.Decimals),
						ProtocolFee: utils.FromSubunit(unpackedEventData[0].(*big.Int), order.Edges.Token.Decimals),
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

	orders, err := storage.Client.PaymentOrder.
		Query().
		Where(paymentorder.TxHashIn(txHashes...)).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithRecipient().
		All(ctx)
	if err != nil {
		logger.Infof("IndexOrderCreated.fetchOrders: %v", err)
		return fmt.Errorf("IndexOrderCreated.fetchOrders: %w", err)
	}

	var wg sync.WaitGroup
	for _, order := range orders {
		createdEvent, ok := hashToEvent[order.TxHash]
		if !ok {
			continue
		}

		wg.Add(1)
		go func(order *ent.PaymentOrder, createdEvent *types.OrderCreatedEvent) {
			defer wg.Done()

			createdEvent.Amount = createdEvent.Amount.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(order.Edges.Token.Decimals))))
			createdEvent.ProtocolFee = createdEvent.ProtocolFee.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(order.Edges.Token.Decimals))))

			err := common.CreateLockPaymentOrder(ctx, order.Edges.Token.Edges.Network, createdEvent, s.order.RefundOrder, s.priorityQueue.AssignLockPaymentOrder)
			if err != nil {
				if !strings.Contains(fmt.Sprintf("%v", err), "duplicate key value violates unique constraint") {
					logger.WithFields(logger.Fields{
						"Error":   fmt.Sprintf("%v", err),
						"OrderID": createdEvent.OrderId,
					}).Errorf("Failed to create lock payment order when indexing order created events for %s", order.Edges.Token.Edges.Network.Identifier)
				}
				return
			}

			// Update payment order with txHash
			_, err = order.Update().
				SetGatewayID(createdEvent.OrderId).
				SetRate(order.Rate).
				SetStatus(paymentorder.StatusPending).
				Save(ctx)
			if err != nil {
				return
			}

			// Refetch payment order
			paymentOrder, err := storage.Client.PaymentOrder.
				Query().
				Where(paymentorder.IDEQ(order.ID)).
				WithSenderProfile().
				Only(ctx)
			if err != nil {
				return
			}

			// Send webhook notifcation to sender
			err = utils.SendPaymentOrderWebhook(ctx, paymentOrder)
			if err != nil {
				return
			}
		}(order, createdEvent)
	}
	wg.Wait()

	return nil
}

// IndexOrderSettled indexes orders settled in the Gateway contract for the Tron network.
func (s *IndexerTron) IndexOrderSettled(ctx context.Context, rpcClient types.RPCClient, order *ent.LockPaymentOrder, network *ent.Network, fromBlock int64, toBlock int64) error {
	events, err := s.fetchLatestOrderEvents(
		order.Edges.Token.Edges.Network.RPCEndpoint,
		order.Edges.Token.Edges.Network.Identifier,
		order.TxHash,
	)
	if err != nil {
		return fmt.Errorf("IndexOrderSettled.fetchLatestOrderEvents: %v", err)
	}

	for _, event := range events {
		eventData := event.(map[string]interface{})
		if eventData["event_name"] == "OrderSettled" && eventData["contract_address"] == order.Edges.Token.Edges.Network.GatewayContractAddress {
			client := fastshot.NewClient(order.Edges.Token.Edges.Network.RPCEndpoint).
				Config().SetTimeout(30*time.Second).
				Header().Add("TRON_PRO_API_KEY", orderConf.TronProApiKey)

			res, err := client.Build().POST("/wallet/gettransactioninfobyid").
				Body().AsJSON(map[string]interface{}{"value": order.TxHash}).
				Retry().Set(3, 1*time.Second).
				Send()
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":  fmt.Sprintf("%v", err),
					"TxHash": order.TxHash,
				}).Errorf("Failed to fetch trx info by id for %s", order.Edges.Token.Edges.Network.Identifier)
				return err
			}

			data, err := utils.ParseJSONResponse(res.RawResponse)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
				}).Errorf("Failed to parse JSON response for %s", order.Edges.Token.Edges.Network.Identifier)
				return err
			}

			logger.WithFields(logger.Fields{
				"TxHash": order.TxHash,
				"Data":   data,
			}).Infof("Index Order settlment for %s", order.Edges.Token.Edges.Network.Identifier)

			// Parse event data
			for _, event := range data["log"].([]interface{}) {
				eventData := event.(map[string]interface{})
				if eventData["topics"].([]interface{})[0] == "98ece21e01a01cbe1d1c0dad3b053c8fbd368f99be78be958fcf1d1d13fd249a" {
					unpackedEventData, err := utils.UnpackEventData(eventData["data"].(string), contracts.GatewayMetaData.ABI, "OrderSettled")
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error":   fmt.Sprintf("%v", err),
							"OrderID": order.ID.String(),
						}).Errorf("Failed to unpack event data for %s", order.Edges.Token.Edges.Network.Identifier)
						return err
					}

					eventSplitOrderId := unpackedEventData[0].([32]byte)
					eventOrderId := utils.ParseTopicToByte32(eventData["topics"].([]interface{})[1].(string))
					event := &types.OrderSettledEvent{
						BlockNumber:       int64(data["blockNumber"].(float64)),
						TxHash:            data["id"].(string),
						SplitOrderId:      fmt.Sprintf("0x%v", hex.EncodeToString(eventSplitOrderId[:])),
						OrderId:           fmt.Sprintf("0x%v", hex.EncodeToString(eventOrderId[:])),
						LiquidityProvider: utils.ParseTopicToTronAddress(eventData["topics"].([]interface{})[2].(string)),
						SettlePercent:     decimal.NewFromBigInt(unpackedEventData[1].(*big.Int), 0),
					}

					err = common.UpdateOrderStatusSettled(ctx, order.Edges.Token.Edges.Network, event)
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error":   fmt.Sprintf("%v", err),
							"OrderID": order.ID.String(),
						}).Errorf("Failed to update order status settlement when indexing order settled events for %s", order.Edges.Token.Edges.Network.Identifier)
					}

					break
				}
			}

			break
		}
	}

	return nil
}

// IndexOrderRefunded indexes orders settled in the Gateway contract for the Tron network.
func (s *IndexerTron) IndexOrderRefunded(ctx context.Context, rpcClient types.RPCClient, order *ent.LockPaymentOrder, network *ent.Network, fromBlock int64, toBlock int64) error {
	events, err := s.fetchLatestOrderEvents(
		order.Edges.Token.Edges.Network.RPCEndpoint,
		order.Edges.Token.Edges.Network.Identifier,
		order.TxHash,
	)
	if err != nil {
		return fmt.Errorf("IndexOrderRefunded.fetchLatestOrderEvents: %v", err)
	}

	for _, event := range events {
		eventData := event.(map[string]interface{})
		if eventData["event_name"] == "OrderRefunded" && eventData["contract_address"] == order.Edges.Token.Edges.Network.GatewayContractAddress {
			client := fastshot.NewClient(order.Edges.Token.Edges.Network.RPCEndpoint).
				Config().SetTimeout(30*time.Second).
				Header().Add("TRON_PRO_API_KEY", orderConf.TronProApiKey)

			res, err := client.Build().POST("/wallet/gettransactioninfobyid").
				Body().AsJSON(map[string]interface{}{"value": order.TxHash}).
				Retry().Set(3, 1*time.Second).
				Send()
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":  fmt.Sprintf("%v", err),
					"TxHash": order.TxHash,
				}).Errorf("Failed to fetch event logs for %s", order.Edges.Token.Edges.Network.Identifier)
				return err
			}

			data, err := utils.ParseJSONResponse(res.RawResponse)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":    fmt.Sprintf("%v", err),
					"Response": data,
				}).Errorf("Failed to parse JSON response for %s after fetching event logs", order.Edges.Token.Edges.Network.Identifier)
				return err
			}

			logger.WithFields(logger.Fields{
				"TxHash": order.TxHash,
				"Data":   data,
			}).Infof("Index Order refund for %s", order.Edges.Token.Edges.Network.Identifier)

			// Parse event data
			for _, event := range data["log"].([]interface{}) {
				eventData := event.(map[string]interface{})
				if eventData["topics"].([]interface{})[0] == "0736fe428e1747ca8d387c2e6fa1a31a0cde62d3a167c40a46ade59a3cdc828e" {
					unpackedEventData, err := utils.UnpackEventData(eventData["data"].(string), contracts.GatewayMetaData.ABI, "OrderRefunded")
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error": fmt.Sprintf("%v", err),
						}).Errorf("Failed to unpack event data for %s after fetching event logs", order.Edges.Token.Edges.Network.Identifier)
						return err
					}

					eventOrderId := utils.ParseTopicToByte32(eventData["topics"].([]interface{})[1].(string))
					event := &types.OrderRefundedEvent{
						BlockNumber: int64(data["blockNumber"].(float64)),
						TxHash:      data["id"].(string),
						OrderId:     fmt.Sprintf("0x%v", hex.EncodeToString(eventOrderId[:])),
						Fee:         utils.FromSubunit(unpackedEventData[0].(*big.Int), order.Edges.Token.Decimals),
					}

					err = common.UpdateOrderStatusRefunded(ctx, order.Edges.Token.Edges.Network, event)
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error":   fmt.Sprintf("%v", err),
							"OrderID": event.OrderId,
							"TxHash":  event.TxHash,
						}).Errorf("Failed to update order status refund when indexing order refunded events for %s", order.Edges.Token.Edges.Network.Identifier)
					}

					break
				}
			}

			break
		}
	}

	return nil
}

// fetchLatestOrderEvents fetches the latest events of the given order from the Tron network.
func (s *IndexerTron) fetchLatestOrderEvents(rpcEndpoint, network, txHash string) ([]interface{}, error) {
	var err error

	if !strings.HasPrefix(network, "tron") {
		return nil, fmt.Errorf("invalid network identifier: %s", network)
	}

	client := fastshot.NewClient(rpcEndpoint).
		Config().SetTimeout(30*time.Second).
		Header().Add("TRON_PRO_API_KEY", orderConf.TronProApiKey)

	// TODO: should we include '?only_confirmed=true' in the URL?
	res, err := client.Build().
		GET(fmt.Sprintf("/v1/transactions/%s/events", txHash)).
		Retry().Set(3, 1*time.Second).
		Send()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":  fmt.Sprintf("%v", err),
			"TxHash": txHash,
		}).Errorf("Failed to fetch txn event logs for %s", network)
		return nil, err
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Response": data,
		}).Errorf("Failed to parse JSON response for %s after fetching event logs", network)
		return nil, err
	}

	if data["success"].(bool) {
		return data["data"].([]interface{}), nil
	}

	return nil, fmt.Errorf("failed to fetch txn event logs: %v", data["error"])
}
