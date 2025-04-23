package services

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/google/uuid"
	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/linkedaddress"
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/provisionbucket"
	"github.com/paycrest/aggregator/ent/receiveaddress"
	"github.com/paycrest/aggregator/ent/senderprofile"
	tokenEnt "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/transactionlog"
	"github.com/paycrest/aggregator/ent/user"
	"github.com/paycrest/aggregator/services/contracts"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

var orderConf = config.OrderConfig()
var serverConf = config.ServerConfig()

// Indexer is an interface for indexing blockchain data to the database.
type Indexer interface {
	IndexERC20Transfer(ctx context.Context, client types.RPCClient, order *ent.PaymentOrder, token *ent.Token, startBlock int64) error
	IndexTRC20Transfer(ctx context.Context, order *ent.PaymentOrder) error
	IndexOrderCreated(ctx context.Context, client types.RPCClient, network *ent.Network) error
	IndexOrderCreatedTron(ctx context.Context, order *ent.PaymentOrder) error
	IndexOrderSettled(ctx context.Context, client types.RPCClient, network *ent.Network) error
	IndexOrderSettledTron(ctx context.Context, order *ent.LockPaymentOrder) error
	IndexOrderRefunded(ctx context.Context, client types.RPCClient, network *ent.Network) error
	IndexOrderRefundedTron(ctx context.Context, order *ent.LockPaymentOrder) error
	HandleReceiveAddressValidity(ctx context.Context, client types.RPCClient, receiveAddress *ent.ReceiveAddress, paymentOrder *ent.PaymentOrder) error
	CreateLockPaymentOrder(ctx context.Context, client types.RPCClient, network *ent.Network, event *types.OrderCreatedEvent) error
	UpdateReceiveAddressStatus(ctx context.Context, client types.RPCClient, receiveAddress *ent.ReceiveAddress, paymentOrder *ent.PaymentOrder, event *types.TokenTransferEvent) (bool, error)
	UpdateOrderStatusSettled(ctx context.Context, network *ent.Network, event *types.OrderSettledEvent) error
	UpdateOrderStatusRefunded(ctx context.Context, network *ent.Network, event *types.OrderRefundedEvent) error
}

// IndexerService performs blockchain to database extract, transform, load (ETL) operations.
type IndexerService struct {
	priorityQueue *PriorityQueueService
	order         types.OrderService
}

// NewIndexerService creates a new instance of IndexerService.
func NewIndexerService(order types.OrderService) Indexer {
	priorityQueue := NewPriorityQueueService()

	return &IndexerService{
		priorityQueue: priorityQueue,
		order:         order,
	}
}

// IndexERC20Transfer indexes transfers to the receive address for an EVM network.
func (s *IndexerService) IndexERC20Transfer(ctx context.Context, client types.RPCClient, order *ent.PaymentOrder, token *ent.Token, startBlock int64) error {
	var err error
	var addressToWatch string

	if order != nil {
		token = order.Edges.Token
		addressToWatch = order.Edges.ReceiveAddress.Address
	}

	// Connect to RPC endpoint
	if client == nil {
		client, err = types.NewEthClient(token.Edges.Network.RPCEndpoint)
		if err != nil {
			return err
		}
	}

	// Initialize contract filterer
	filterer, err := contracts.NewERC20TokenFilterer(common.HexToAddress(token.ContractAddress), client)
	if err != nil {
		// Need to group by network
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Token": token.ContractAddress,
			"ReceiveAddress": addressToWatch,
		}).Errorf("Failed to index ERC20 transfers for %s", token.Edges.Network.Identifier)
		return err
	}

	// Fetch current block header
	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		// logger.Errorf("IndexERC20Transfer.HeaderByNumber: %v", err)
		return err
	}
	toBlock := header.Number.Uint64()

	// Fetch logs
	var iter *contracts.ERC20TokenTransferIterator

	addresses := []common.Address{}
	if startBlock == 0 {
		if addressToWatch != "" {
			fromBlock := int64(500)
			if token.Edges.Network.Identifier != "bnb-smart-chain" {
				fromBlock = 5000
			}
			addresses = []common.Address{common.HexToAddress(addressToWatch)}
			startBlock = int64(toBlock) - fromBlock
		} else {
			startBlock = int64(toBlock) - 100
		}
	}

	// if strings.Contains(token.Edges.Network.Identifier, "arbitrum") {
	// 	startBlock = 268964400
	// 	toBlock = 268964450
	// }

	iter, err = filterer.FilterTransfer(&bind.FilterOpts{
		Start: uint64(startBlock),
		End:   &toBlock,
	}, nil, addresses)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Token": token.ContractAddress,
			"ReceiveAddress": addressToWatch,
			"StartBlock": startBlock,
			"EndBlock": toBlock,
		}).Errorf("Failed to index ERC20 transfers for %s", token.Edges.Network.Identifier)
		return err
	}

	// Iterate over logs
	for iter.Next() {
		transferEvent := &types.TokenTransferEvent{
			BlockNumber: iter.Event.Raw.BlockNumber,
			TxHash:      iter.Event.Raw.TxHash.Hex(),
			From:        iter.Event.From.Hex(),
			To:          iter.Event.To.Hex(),
			Value:       iter.Event.Value,
		}

		if strings.EqualFold(transferEvent.From, token.Edges.Network.GatewayContractAddress) {
			continue
		}

		linkedAddress, err := db.Client.LinkedAddress.
			Query().
			Where(
				linkedaddress.AddressEQ(transferEvent.To),
			).
			Only(ctx)
		if err != nil {
			if !ent.IsNotFound(err) {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"Address": transferEvent.To,
				}).Errorf("Failed to query linked address when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
			}
		}

		// Create a new payment order from the transfer event to the linked address
		if linkedAddress != nil {
			orderAmount := utils.FromSubunit(transferEvent.Value, token.Decimals)
			// Check if the payment order already exists
			paymentOrderExists := true
			_, err := db.Client.PaymentOrder.
				Query().
				Where(
					paymentorder.FromAddress(transferEvent.From),
					paymentorder.AmountEQ(orderAmount),
					paymentorder.HasLinkedAddressWith(
						linkedaddress.AddressEQ(linkedAddress.Address),
						linkedaddress.LastIndexedBlockEQ(int64(transferEvent.BlockNumber)),
					),
				).
				WithSenderProfile().
				Only(ctx)
			if err != nil {
				if ent.IsNotFound(err) {
					// Payment order does not exist, no need to update
					paymentOrderExists = false
				} else {
					return fmt.Errorf("IndexERC20Transfer.fetchOrder: %v", err)
				}
			}

			if paymentOrderExists {
				continue
			}

			// Create payment order
			institution, err := utils.GetInstitutionByCode(ctx, linkedAddress.Institution)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"LinkedAddress": linkedAddress.Address,
					"LinkedAddressInstitution": linkedAddress.Institution,
				}).Errorf("Failed to get institution when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
				continue
			}

			// Get rate from priority queue
			if !strings.EqualFold(token.BaseCurrency, institution.Edges.FiatCurrency.Code) && !strings.EqualFold(token.BaseCurrency, "USD") {
				continue
			}
			var rateResponse decimal.Decimal
			if !strings.EqualFold(token.BaseCurrency, institution.Edges.FiatCurrency.Code) {
				rateResponse, err = utils.GetTokenRateFromQueue(token.Symbol, orderAmount, institution.Edges.FiatCurrency.Code, institution.Edges.FiatCurrency.MarketRate)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error": fmt.Sprintf("%v", err),
						"Token": token.Symbol,
						"LinkedAddressInstitution": linkedAddress.Institution,
						"Code": institution.Edges.FiatCurrency.Code,
					}).Errorf("Failed to get token rate when indexing ERC20 transfers for %s from queue", token.Edges.Network.Identifier)
					continue
				}
			} else {
				rateResponse = decimal.NewFromInt(1)
			}

			tx, err := db.Client.Tx(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"LinkedAddress": linkedAddress.Address,
				}).Errorf("Failed to create transaction when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
				continue
			}

			// transactionLog, err := tx.TransactionLog.
			// 	Create().
			// 	SetStatus(transactionlog.StatusOrderInitiated).
			// 	SetMetadata(
			// 		map[string]interface{}{
			// 			"LinkedAddress": linkedAddress.Address,
			// 		},
			// 	).
			// 	SetNetwork(token.Edges.Network.Identifier).
			// 	Save(ctx)
			// if err != nil {
			// 	logger.Errorf("IndexERC20Transfer.CreateTransactionLog: %v", err)
			// 	_ = tx.Rollback()
			// 	continue
			// }

			order, err := db.Client.PaymentOrder.
				Create().
				SetAmount(orderAmount).
				SetAmountPaid(orderAmount).
				SetAmountReturned(decimal.NewFromInt(0)).
				SetPercentSettled(decimal.NewFromInt(0)).
				SetNetworkFee(token.Edges.Network.Fee).
				SetProtocolFee(decimal.NewFromInt(0)).
				SetSenderFee(decimal.NewFromInt(0)).
				SetToken(token).
				SetRate(rateResponse).
				SetTxHash(transferEvent.TxHash).
				SetBlockNumber(int64(transferEvent.BlockNumber)).
				SetFromAddress(transferEvent.From).
				SetLinkedAddress(linkedAddress).
				SetReceiveAddressText(linkedAddress.Address).
				SetFeePercent(decimal.NewFromInt(0)).
				SetReturnAddress(linkedAddress.Address).
				// AddTransactions(transactionLog).
				Save(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"LinkedAddress": linkedAddress.Address,
				}).Errorf("Failed to create payment order when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
				_ = tx.Rollback()
				continue
			}

			_, err = tx.PaymentOrderRecipient.
				Create().
				SetInstitution(linkedAddress.Institution).
				SetAccountIdentifier(linkedAddress.AccountIdentifier).
				SetAccountName(linkedAddress.AccountName).
				SetPaymentOrder(order).
				Save(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"LinkedAddress": linkedAddress.Address,
				}).Errorf("Failed to create payment order recipient when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
				_ = tx.Rollback()
				continue
			}

			_, err = tx.LinkedAddress.
				UpdateOneID(linkedAddress.ID).
				SetTxHash(transferEvent.TxHash).
				SetLastIndexedBlock(int64(transferEvent.BlockNumber)).
				Save(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"LinkedAddress": linkedAddress.Address,
				}).Errorf("Failed to update linked address when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
				_ = tx.Rollback()
				continue
			}

			if err := tx.Commit(); err != nil {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"LinkedAddress": linkedAddress.Address,
				}).Errorf("Failed to commit transaction when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
				continue
			}

			err = s.order.CreateOrder(ctx, client, order.ID)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"OrderID": order.ID,
				}).Errorf("Failed to create order when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
				continue
			}

		} else if order != nil {
			// Process transfer event for receive address
			done, err := s.UpdateReceiveAddressStatus(ctx, client, order.Edges.ReceiveAddress, order, transferEvent)
			if err != nil {
				if !strings.Contains(fmt.Sprintf("%v", err), "Duplicate payment order") {
					logger.WithFields(logger.Fields{
						"Error": fmt.Sprintf("%v", err),
						"OrderID": order.ID,
					}).Errorf("Failed to update receive address status when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
				}
				continue
			}
			if done {
				return nil
			}
		}
	}

	return nil
}

// IndexTRC20Transfer indexes transfers to the receive address for Tron network.
func (s *IndexerService) IndexTRC20Transfer(ctx context.Context, order *ent.PaymentOrder) error {
	var err error

	if !strings.HasPrefix(order.Edges.Token.Edges.Network.Identifier, "tron") {
		return fmt.Errorf("IndexTRC20Transfer: invalid network identifier: %s", order.Edges.Token.Edges.Network.Identifier)
	}

	client := fastshot.NewClient(order.Edges.Token.Edges.Network.RPCEndpoint).
		Config().SetTimeout(30*time.Second).
		Header().Add("TRON_PRO_API_KEY", orderConf.TronProApiKey)

	// TODO: should we include '?only_confirmed=true' in the URL?
	res, err := client.Build().
		GET(fmt.Sprintf("/v1/accounts/%s/transactions/trc20", order.Edges.ReceiveAddress.Address)).
		Retry().Set(3, 1*time.Second).
		Send()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"OrderID": order.ID,
		}).Errorf("Failed to fetch TRC20 transfer for %s", order.Edges.Token.Edges.Network.Identifier)
		return err
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Response": data,
		}).Errorf("Failed to parse JSON response for TRC20 transfer for %s", order.Edges.Token.Edges.Network.Identifier)
		return err
	}

	if data["success"].(bool) {
		for _, event := range data["data"].([]interface{}) {
			eventData := event.(map[string]interface{})

			value, err := decimal.NewFromString(eventData["value"].(string))
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"Value": eventData["value"],
				}).Errorf("Failed to parse decimal value from TRC20 transfer for %s", order.Edges.Token.Edges.Network.Identifier)
				return err
			}

			amountPaid := utils.FromSubunit(value.BigInt(), order.Edges.Token.Decimals)
			amountToBePaid := order.Amount.Add(order.ProtocolFee).Add(order.SenderFee).Add(order.NetworkFee)

			if eventData["type"].(string) != "Transfer" && eventData["to"].(string) != order.Edges.ReceiveAddress.Address && amountPaid != amountToBePaid {
				return nil
			}

			res, err = client.Build().POST("/wallet/gettransactioninfobyid").
				Body().AsJSON(map[string]interface{}{"value": eventData["transaction_id"].(string)}).
				Retry().Set(3, 1*time.Second).
				Send()
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"TransactionID": eventData["transaction_id"],
				}).Errorf("Failed to fetch block number for TRC20 transfer for %s", order.Edges.Token.Edges.Network.Identifier)
				return err
			}

			data, err = utils.ParseJSONResponse(res.RawResponse)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"Response": data,
				}).Errorf("Failed to parse JSON response for TRC20 transfer for %s", order.Edges.Token.Edges.Network.Identifier)
				return err
			}

			if data["blockNumber"] != nil {
				transferEvent := &types.TokenTransferEvent{
					BlockNumber: uint64(data["blockNumber"].(float64)),
					TxHash:      eventData["transaction_id"].(string),
					From:        eventData["from"].(string),
					To:          eventData["to"].(string),
					Value:       value.BigInt(),
				}

				go func() {
					_, err := s.UpdateReceiveAddressStatus(ctx, nil, order.Edges.ReceiveAddress, order, transferEvent)
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error": fmt.Sprintf("%v", err),
							"OrderID": order.ID,
						}).Errorf("Failed to update receive address status when indexing TRC20 transfers for %s", order.Edges.Token.Edges.Network.Identifier)
					}
				}()
			}
		}
	}

	return nil
}

// IndexOrderCreated indexes deposits to the order contract for an EVM network.
func (s *IndexerService) IndexOrderCreated(ctx context.Context, client types.RPCClient, network *ent.Network) error {
	var err error

	// Connect to RPC endpoint
	if client == nil {
		client, err = types.NewEthClient(network.RPCEndpoint)
		if err != nil {
			return err
		}
	}

	// Initialize contract filterer
	filterer, err := contracts.NewGatewayFilterer(common.HexToAddress(network.GatewayContractAddress), client)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
		}).Errorf("Failed to create gateway filterer when indexing order created events for %s", network.Identifier)
		return err
	}

	// Fetch current block header
	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		if err != context.Canceled {
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
			}).Errorf("Failed to fetch current block header for %s when indexing order created events", network.Identifier)
		}
		return err
	}
	toBlock := header.Number.Uint64()

	// Fetch logs
	var iter *contracts.GatewayOrderCreatedIterator
	fromBlock := int64(100000)
	if network.Identifier == "bnb-smart-chain" {
		fromBlock = 10000
	}
	iter, err = filterer.FilterOrderCreated(&bind.FilterOpts{
		Start: uint64(int64(toBlock) - fromBlock),
		End:   &toBlock,
	}, nil, nil, nil)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Start": uint64(int64(toBlock) - fromBlock),
			"End":   toBlock,
		}).Errorf("Failed to filter order created events for %s when indexing order created events", network.Identifier)
		return err
	}

	// Iterate over logs
	for iter.Next() {
		event := &types.OrderCreatedEvent{
			BlockNumber: iter.Event.Raw.BlockNumber,
			TxHash:      iter.Event.Raw.TxHash.Hex(),
			Token:       iter.Event.Token.Hex(),
			Amount:      iter.Event.Amount,
			ProtocolFee: iter.Event.ProtocolFee,
			OrderId:     iter.Event.OrderId,
			Rate:        iter.Event.Rate,
			MessageHash: iter.Event.MessageHash,
		}

		err := s.CreateLockPaymentOrder(ctx, client, network, event)
		if err != nil {
			if !strings.Contains(fmt.Sprintf("%v", err), "duplicate key value violates unique constraint") {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"OrderID": event.OrderId,
				}).Errorf("Failed to create lock payment order when indexing order created events for %s", network.Identifier)
			}
			continue
		}
	}

	return nil
}

// IndexOrderCreatedTron indexes orders created in the Gateway contract for the Tron network.
func (s *IndexerService) IndexOrderCreatedTron(ctx context.Context, order *ent.PaymentOrder) error {
	events, err := s.fetchLatestOrderEvents(
		order.Edges.Token.Edges.Network.RPCEndpoint,
		order.Edges.Token.Edges.Network.Identifier,
		order.TxHash,
	)
	if err != nil {
		return fmt.Errorf("IndexOrderCreatedTron.fetchLatestOrderEvents: %v", err)
	}

	for _, event := range events {
		eventData := event.(map[string]interface{})
		if eventData["event_name"] == "OrderCreated" && eventData["contract_address"] == order.Edges.Token.Edges.Network.GatewayContractAddress {
			client := fastshot.NewClient(order.Edges.Token.Edges.Network.RPCEndpoint).
				Config().SetTimeout(30*time.Second).
				Header().Add("TRON_PRO_API_KEY", orderConf.TronProApiKey)

			res, err := client.Build().POST("/wallet/gettransactioninfobyid").
				Body().AsJSON(map[string]interface{}{"value": order.TxHash}).
				Retry().Set(3, 1*time.Second).
				Send()
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
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

					event := &types.OrderCreatedEvent{
						BlockNumber: uint64(data["blockNumber"].(float64)),
						TxHash:      data["id"].(string),
						Token:       utils.ParseTopicToTronAddress(eventData["topics"].([]interface{})[2].(string)),
						Amount:      utils.ParseTopicToBigInt(eventData["topics"].([]interface{})[3].(string)),
						ProtocolFee: unpackedEventData[0].(*big.Int),
						OrderId:     unpackedEventData[1].([32]byte),
						Rate:        unpackedEventData[2].(*big.Int),
						MessageHash: unpackedEventData[3].(string),
					}

					err = s.CreateLockPaymentOrder(ctx, nil, order.Edges.Token.Edges.Network, event)
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error": fmt.Sprintf("%v", err),
							"OrderID": event.OrderId,
						}).Errorf("Failed to create lock payment order when indexing order created events for %s", order.Edges.Token.Edges.Network.Identifier)
					}

					break
				}
			}

			break
		}
	}

	return nil
}

// IndexOrderSettled indexes order settlements for an EVM network.
func (s *IndexerService) IndexOrderSettled(ctx context.Context, client types.RPCClient, network *ent.Network) error {
	var err error

	// Connect to RPC endpoint
	if client == nil {
		client, err = types.NewEthClient(network.RPCEndpoint)
		if err != nil {
			return err
		}
	}

	// Initialize contract filterer
	filterer, err := contracts.NewGatewayFilterer(common.HexToAddress(network.GatewayContractAddress), client)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
		}).Errorf("Failed to filterer when indexing order created events for %s", network.Identifier)
		return err
	}

	// Filter logs from the oldest indexed to the latest
	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		if err != context.Canceled {
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
			}).Errorf("Failed to fetch header by number when indexing order created events for %s", network.Identifier)
		}
		return err
	}
	toBlock := header.Number.Uint64()

	// Fetch logs
	var iter *contracts.GatewayOrderSettledIterator
	iter, err = filterer.FilterOrderSettled(&bind.FilterOpts{
		Start: uint64(int64(toBlock) - 5000),
		End:   &toBlock,
	}, nil, nil)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Start": uint64(int64(toBlock) - 5000),
			"End":   toBlock,
		}).Errorf("Failed to filter order created events for %s when indexing order created events", network.Identifier)
		return err
	}

	// Iterate over logs
	for iter.Next() {
		settledEvent := &types.OrderSettledEvent{
			BlockNumber:       iter.Event.Raw.BlockNumber,
			TxHash:            iter.Event.Raw.TxHash.Hex(),
			SplitOrderId:      iter.Event.SplitOrderId,
			OrderId:           iter.Event.OrderId,
			LiquidityProvider: iter.Event.LiquidityProvider.Hex(),
			SettlePercent:     iter.Event.SettlePercent,
		}

		err := s.UpdateOrderStatusSettled(ctx, network, settledEvent)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
				"OrderID": settledEvent.OrderId,
			}).Errorf("Failed to update order status settlement when indexing order created events for %s", network.Identifier)
			continue
		}
	}

	return nil
}

// IndexOrderSettledTron indexes orders settled in the Gateway contract for the Tron network.
func (s *IndexerService) IndexOrderSettledTron(ctx context.Context, order *ent.LockPaymentOrder) error {
	events, err := s.fetchLatestOrderEvents(
		order.Edges.Token.Edges.Network.RPCEndpoint,
		order.Edges.Token.Edges.Network.Identifier,
		order.TxHash,
	)
	if err != nil {
		return fmt.Errorf("IndexOrderSettledTron.fetchLatestOrderEvents: %v", err)
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
					"Error": fmt.Sprintf("%v", err),
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
				"Data": data,
			}).Infof("Index Order settlment for %s", order.Edges.Token.Edges.Network.Identifier)

			// Parse event data
			for _, event := range data["log"].([]interface{}) {
				eventData := event.(map[string]interface{})
				if eventData["topics"].([]interface{})[0] == "98ece21e01a01cbe1d1c0dad3b053c8fbd368f99be78be958fcf1d1d13fd249a" {
					unpackedEventData, err := utils.UnpackEventData(eventData["data"].(string), contracts.GatewayMetaData.ABI, "OrderSettled")
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error": fmt.Sprintf("%v", err),
							"OrderID": order.ID,
						}).Errorf("Failed to unpack event data for %s", order.Edges.Token.Edges.Network.Identifier)
						return err
					}

					event := &types.OrderSettledEvent{
						BlockNumber:       uint64(data["blockNumber"].(float64)),
						TxHash:            data["id"].(string),
						SplitOrderId:      unpackedEventData[0].([32]byte),
						OrderId:           utils.ParseTopicToByte32(eventData["topics"].([]interface{})[1].(string)),
						LiquidityProvider: eventData["topics"].([]interface{})[2].(string),
						SettlePercent:     unpackedEventData[1].(*big.Int),
					}

					err = s.UpdateOrderStatusSettled(ctx, order.Edges.Token.Edges.Network, event)
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error": fmt.Sprintf("%v", err),
							"OrderID": order.ID,
						}).Errorf("Failed to update order status settlement when indexing order created events for %s", order.Edges.Token.Edges.Network.Identifier)
					}

					break
				}
			}

			break
		}
	}

	return nil
}

// IndexOrderRefunded indexes order refunds for an EVM network.
func (s *IndexerService) IndexOrderRefunded(ctx context.Context, client types.RPCClient, network *ent.Network) error {
	var err error

	// Connect to RPC endpoint
	if client == nil {
		client, err = types.NewEthClient(network.RPCEndpoint)
		if err != nil {
			return err
		}
	}

	// Initialize contract filterer
	filterer, err := contracts.NewGatewayFilterer(common.HexToAddress(network.GatewayContractAddress), client)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
		}).Errorf("Failed to filterer when indexing order created events for %s", network.Identifier)
		return err
	}

	// Filter logs from the oldest indexed to the latest
	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		if err != context.Canceled {
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
			}).Errorf("Failed to fetch header by number when indexing order created events for %s", network.Identifier)
		}
		return err
	}
	toBlock := header.Number.Uint64()

	// Fetch logs
	var iter *contracts.GatewayOrderRefundedIterator
	iter, err = filterer.FilterOrderRefunded(&bind.FilterOpts{
		Start: uint64(int64(toBlock) - 5000),
		End:   &toBlock,
	}, nil)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Start": uint64(int64(toBlock) - 5000),
			"End":   toBlock,
		}).Errorf("Failed to filter order created events for %s when indexing order created events", network.Identifier)
		return err
	}

	// Iterate over logs
	for iter.Next() {
		refundedEvent := &types.OrderRefundedEvent{
			BlockNumber: iter.Event.Raw.BlockNumber,
			TxHash:      iter.Event.Raw.TxHash.Hex(),
			Fee:         iter.Event.Fee,
			OrderId:     iter.Event.OrderId,
		}

		err := s.UpdateOrderStatusRefunded(ctx, network, refundedEvent)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
				"OrderID": refundedEvent.OrderId,
				"TxHash": refundedEvent.TxHash,
			}).Errorf("Failed to update order status refund when indexing order created events for %s", network.Identifier)
			continue
		}
	}

	return nil
}

// IndexOrderRefundedTron indexes orders settled in the Gateway contract for the Tron network.
func (s *IndexerService) IndexOrderRefundedTron(ctx context.Context, order *ent.LockPaymentOrder) error {
	events, err := s.fetchLatestOrderEvents(
		order.Edges.Token.Edges.Network.RPCEndpoint,
		order.Edges.Token.Edges.Network.Identifier,
		order.TxHash,
	)
	if err != nil {
		return fmt.Errorf("IndexOrderRefundedTron.fetchLatestOrderEvents: %v", err)
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
					"Error": fmt.Sprintf("%v", err),
					"TxHash": order.TxHash,
				}).Errorf("Failed to fetch event logs for %s", order.Edges.Token.Edges.Network.Identifier)
				return err
			}

			data, err := utils.ParseJSONResponse(res.RawResponse)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"Response": data,
				}).Errorf("Failed to parse JSON response for %s after fetching event logs", order.Edges.Token.Edges.Network.Identifier)
				return err
			}

			logger.WithFields(logger.Fields{
				"TxHash": order.TxHash,
				"Data": data,
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

					event := &types.OrderRefundedEvent{
						BlockNumber: uint64(data["blockNumber"].(float64)),
						TxHash:      data["id"].(string),
						OrderId:     eventData["topics"].([]interface{})[1].([32]byte),
						Fee:         unpackedEventData[0].(*big.Int),
					}

					err = s.UpdateOrderStatusRefunded(ctx, order.Edges.Token.Edges.Network, event)
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error": fmt.Sprintf("%v", err),
							"OrderID": event.OrderId,
							"TxHash": event.TxHash,
						}).Errorf("Failed to update order status refund when indexing order created events for %s", order.Edges.Token.Edges.Network.Identifier)
					}

					break
				}
			}

			break
		}
	}

	return nil
}

// HandleReceiveAddressValidity checks the validity of a receive address
func (s *IndexerService) HandleReceiveAddressValidity(ctx context.Context, client types.RPCClient, receiveAddress *ent.ReceiveAddress, paymentOrder *ent.PaymentOrder) error {
	if receiveAddress.ValidUntil.IsZero() {
		return nil
	}

	if receiveAddress.Status != receiveaddress.StatusUsed {
		validUntilIsFarGone := receiveAddress.ValidUntil.Before(time.Now().Add(-(5 * time.Minute)))
		isExpired := receiveAddress.ValidUntil.Before(time.Now())

		if validUntilIsFarGone {
			_, err := receiveAddress.
				Update().
				SetValidUntil(time.Now().Add(orderConf.ReceiveAddressValidity)).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("HandleReceiveAddressValidity.db: %v", err)
			}
		} else if isExpired && !strings.HasPrefix(paymentOrder.Edges.Recipient.Memo, "P#P") {
			// Receive address hasn't received payment after validity period, mark status as expired
			_, err := receiveAddress.
				Update().
				SetStatus(receiveaddress.StatusExpired).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("HandleReceiveAddressValidity.db: %v", err)
			}

			// Expire payment order
			_, err = paymentOrder.
				Update().
				SetStatus(paymentorder.StatusExpired).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("HandleReceiveAddressValidity.db: %v", err)
			}
		}
	}

	return nil
}

// CreateLockPaymentOrder saves a lock payment order in the database
func (s *IndexerService) CreateLockPaymentOrder(ctx context.Context, client types.RPCClient, network *ent.Network, event *types.OrderCreatedEvent) error {
	gatewayId := fmt.Sprintf("0x%v", hex.EncodeToString(event.OrderId[:]))

	// Check for existing address with txHash
	orderCount, err := db.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.Or(
				lockpaymentorder.TxHashEQ(event.TxHash),
				lockpaymentorder.GatewayIDEQ(gatewayId),
			),
			lockpaymentorder.HasTokenWith(
				tokenEnt.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		Count(ctx)
	if err != nil {
		return fmt.Errorf("CreateLockPaymentOrder.db: %v", err)
	}

	if orderCount > 0 {
		// This transfer has already been indexed
		return nil
	}

	go func() {
		timeToWait := 2 * time.Second

		time.Sleep(timeToWait)
		_ = utils.Retry(10, timeToWait, func() error {
			// Update payment order with the gateway ID
			paymentOrder, err := db.Client.PaymentOrder.
				Query().
				Where(
					paymentorder.TxHashEQ(event.TxHash),
				).
				Only(ctx)
			if err != nil {
				if ent.IsNotFound(err) {
					// Payment order does not exist, retry
					return fmt.Errorf("trigger retry")
				} else {
					return fmt.Errorf("CreateLockPaymentOrder.db: %v", err)
				}
			}

			_, err = db.Client.PaymentOrder.
				Update().
				Where(paymentorder.IDEQ(paymentOrder.ID)).
				SetBlockNumber(int64(event.BlockNumber)).
				SetGatewayID(gatewayId).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("CreateLockPaymentOrder.db: %v", err)
			}

			return nil
		})
	}()

	// Get token from db
	token, err := db.Client.Token.
		Query().
		Where(
			tokenEnt.ContractAddressEQ(event.Token),
			tokenEnt.HasNetworkWith(
				networkent.IDEQ(network.ID),
			),
		).
		WithNetwork().
		Only(ctx)
	if err != nil {
		return nil
	}

	// Get order recipient from message hash
	recipient, err := s.getOrderRecipientFromMessageHash(event.MessageHash)
	if err != nil {
		return nil
	}

	// Get provision bucket
	amountInDecimals := utils.FromSubunit(event.Amount, token.Decimals)
	institution, err := utils.GetInstitutionByCode(ctx, recipient.Institution)
	if err != nil {
		return nil
	}

	currency, err := db.Client.FiatCurrency.
		Query().
		Where(
			fiatcurrency.IsEnabledEQ(true),
			fiatcurrency.CodeEQ(institution.Edges.FiatCurrency.Code),
		).
		Only(ctx)
	if err != nil {
		return nil
	}

	rate := decimal.NewFromBigInt(event.Rate, -2)

	provisionBucket, isLessThanMin, err := s.getProvisionBucket(ctx, amountInDecimals.Mul(rate), currency)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Amount": amountInDecimals,
			"Currency": currency,
		}).Errorf("failed to fetch provision bucket when creating lock payment order")
	}

	// Create lock payment order fields
	lockPaymentOrder := types.LockPaymentOrderFields{
		Token:             token,
		Network:           network,
		GatewayID:         gatewayId,
		Amount:            amountInDecimals,
		Rate:              rate,
		BlockNumber:       int64(event.BlockNumber),
		TxHash:            event.TxHash,
		Institution:       recipient.Institution,
		AccountIdentifier: recipient.AccountIdentifier,
		AccountName:       recipient.AccountName,
		ProviderID:        recipient.ProviderID,
		Memo:              recipient.Memo,
		ProvisionBucket:   provisionBucket,
	}

	if isLessThanMin {
		err := s.handleCancellation(ctx, client, nil, &lockPaymentOrder, "Amount is less than the minimum bucket")
		if err != nil {
			return fmt.Errorf("failed to handle cancellation: %w", err)
		}
		return nil
	}

	// Handle private order checks
	isPrivate := false
	if lockPaymentOrder.ProviderID != "" {
		orderToken, err := db.Client.ProviderOrderToken.
			Query().
			Where(
				providerordertoken.NetworkEQ(token.Edges.Network.Identifier),
				providerordertoken.HasProviderWith(
					providerprofile.IDEQ(lockPaymentOrder.ProviderID),
					providerprofile.IsAvailableEQ(true),
				),
				providerordertoken.HasTokenWith(tokenEnt.IDEQ(token.ID)),
				providerordertoken.HasCurrencyWith(
					fiatcurrency.CodeEQ(institution.Edges.FiatCurrency.Code),
				),
			).
			WithProvider().
			Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				// Provider could not be available for several reasons
				// 1. Provider is not available
				// 2. Provider does not support the token
				// 3. Provider does not support the network
				// 4. Provider does not support the currency
				_ = s.handleCancellation(ctx, client, nil, &lockPaymentOrder, "Provider not available")
				return nil
			} else {
				return fmt.Errorf("%s - failed to fetch provider: %w", lockPaymentOrder.GatewayID, err)
			}
		}

		if orderToken.Edges.Provider.VisibilityMode == providerprofile.VisibilityModePrivate {
			normalizedAmount := lockPaymentOrder.Amount
			if strings.EqualFold(token.BaseCurrency, institution.Edges.FiatCurrency.Code) && token.BaseCurrency != "USD" {
				rateResponse, err := utils.GetTokenRateFromQueue("USDT", normalizedAmount, institution.Edges.FiatCurrency.Code, currency.MarketRate)
				if err != nil {
					return fmt.Errorf("failed to get token rate: %w", err)
				}
				normalizedAmount = lockPaymentOrder.Amount.Div(rateResponse)
			}

			if normalizedAmount.GreaterThan(orderToken.MaxOrderAmount) {
				err := s.handleCancellation(ctx, client, nil, &lockPaymentOrder, "Amount is greater than the maximum order amount of the provider")
				if err != nil {
					return fmt.Errorf("%s - failed to cancel order: %w", lockPaymentOrder.GatewayID, err)
				}
				return nil
			} else if normalizedAmount.LessThan(orderToken.MinOrderAmount) {
				err := s.handleCancellation(ctx, client, nil, &lockPaymentOrder, "Amount is less than the minimum order amount of the provider")
				if err != nil {
					return fmt.Errorf("%s - failed to cancel order: %w", lockPaymentOrder.GatewayID, err)
				}
				return nil
			}
		}
	}

	if provisionBucket == nil && !isPrivate {
		// Split lock payment order into multiple orders
		err = s.splitLockPaymentOrder(
			ctx, client, lockPaymentOrder, currency,
		)
		if err != nil {
			return fmt.Errorf("%s - failed to split lock payment order: %w", lockPaymentOrder.GatewayID, err)
		}
	} else {
		// Create LockPaymentOrder and recipient in a transaction
		tx, err := db.Client.Tx(ctx)
		if err != nil {
			return fmt.Errorf("%s failed to initiate db transaction %w", lockPaymentOrder.GatewayID, err)
		}

		var transactionLog *ent.TransactionLog
		_, err = tx.TransactionLog.
			Query().
			Where(
				transactionlog.StatusEQ(transactionlog.StatusOrderCreated),
				transactionlog.TxHashEQ(lockPaymentOrder.TxHash),
				transactionlog.GatewayIDEQ(lockPaymentOrder.GatewayID),
			).
			Only(ctx)
		if err != nil {
			if !ent.IsNotFound(err) {
				return fmt.Errorf("%s - failed to fetch transaction Log: %w", lockPaymentOrder.GatewayID, err)
			} else {
				transactionLog, err = tx.TransactionLog.
					Create().
					SetStatus(transactionlog.StatusOrderCreated).
					SetTxHash(lockPaymentOrder.TxHash).
					SetNetwork(network.Identifier).
					SetGatewayID(lockPaymentOrder.GatewayID).
					SetMetadata(
						map[string]interface{}{
							"Token":           lockPaymentOrder.Token,
							"GatewayID":       lockPaymentOrder.GatewayID,
							"Amount":          lockPaymentOrder.Amount,
							"Rate":            lockPaymentOrder.Rate,
							"Memo":            lockPaymentOrder.Memo,
							"ProvisionBucket": lockPaymentOrder.ProvisionBucket,
							"ProviderID":      lockPaymentOrder.ProviderID,
						}).
					Save(ctx)
				if err != nil {
					return fmt.Errorf("%s - failed to create transaction Log : %w", lockPaymentOrder.GatewayID, err)
				}
			}
		}

		// Create lock payment order in db
		orderBuilder := tx.LockPaymentOrder.
			Create().
			SetToken(lockPaymentOrder.Token).
			SetGatewayID(lockPaymentOrder.GatewayID).
			SetAmount(lockPaymentOrder.Amount).
			SetRate(lockPaymentOrder.Rate).
			SetOrderPercent(decimal.NewFromInt(100)).
			SetBlockNumber(lockPaymentOrder.BlockNumber).
			SetTxHash(lockPaymentOrder.TxHash).
			SetInstitution(lockPaymentOrder.Institution).
			SetAccountIdentifier(lockPaymentOrder.AccountIdentifier).
			SetAccountName(lockPaymentOrder.AccountName).
			SetMemo(lockPaymentOrder.Memo).
			SetProvisionBucket(lockPaymentOrder.ProvisionBucket)

		if lockPaymentOrder.ProviderID != "" {
			orderBuilder = orderBuilder.SetProviderID(lockPaymentOrder.ProviderID)
		}

		if transactionLog != nil {
			orderBuilder = orderBuilder.AddTransactions(transactionLog)
		}

		orderCreated, err := orderBuilder.Save(ctx)
		if err != nil {
			return fmt.Errorf("%s - failed to create lock payment order: %w", lockPaymentOrder.GatewayID, err)
		}

		// Commit the transaction
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("%s - failed to create lock payment order: %w", lockPaymentOrder.GatewayID, err)
		}

		// Check AML compliance
		if serverConf.Environment == "production" && !strings.HasPrefix(network.Identifier, "tron") {
			ok, err := s.checkAMLCompliance(network.RPCEndpoint, event.TxHash)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"endpoint": network.RPCEndpoint,
					"TxHash": event.TxHash,
				}).Errorf("Failed to check AML Compliance")
			}

			if !ok && err == nil {
				err := s.handleCancellation(ctx, client, orderCreated, nil, "AML compliance check failed")
				if err != nil {
					return fmt.Errorf("checkAMLCompliance.RefundOrder: %w", err)
				}
				return nil
			}
		}

		// Assign the lock payment order to a provider
		lockPaymentOrder.ID = orderCreated.ID
		_ = s.priorityQueue.AssignLockPaymentOrder(ctx, lockPaymentOrder)
	}

	return nil
}

// handleCancellation handles the cancellation of a lock payment order
func (s *IndexerService) handleCancellation(ctx context.Context, client types.RPCClient, createdLockPaymentOrder *ent.LockPaymentOrder, lockPaymentOrder *types.LockPaymentOrderFields, cancellationReason string) error {
	// lockPaymentOrder and createdLockPaymentOrder are mutually exclusive
	if (createdLockPaymentOrder == nil && lockPaymentOrder == nil) || (createdLockPaymentOrder != nil && lockPaymentOrder != nil) {
		return nil
	}

	if lockPaymentOrder != nil {
		orderBuilder := db.Client.LockPaymentOrder.
			Create().
			SetToken(lockPaymentOrder.Token).
			SetGatewayID(lockPaymentOrder.GatewayID).
			SetAmount(lockPaymentOrder.Amount).
			SetRate(lockPaymentOrder.Rate).
			SetOrderPercent(decimal.NewFromInt(100)).
			SetBlockNumber(lockPaymentOrder.BlockNumber).
			SetTxHash(lockPaymentOrder.TxHash).
			SetInstitution(lockPaymentOrder.Institution).
			SetAccountIdentifier(lockPaymentOrder.AccountIdentifier).
			SetAccountName(lockPaymentOrder.AccountName).
			SetMemo(lockPaymentOrder.Memo).
			SetProvisionBucket(lockPaymentOrder.ProvisionBucket).
			SetCancellationCount(3).
			SetCancellationReasons([]string{cancellationReason}).
			SetStatus(lockpaymentorder.StatusCancelled)

		if lockPaymentOrder.ProviderID != "" {
			orderBuilder = orderBuilder.
				SetProviderID(lockPaymentOrder.ProviderID)
		}

		order, err := orderBuilder.Save(ctx)
		if err != nil {
			return fmt.Errorf("%s - failed to create lock payment order: %w", lockPaymentOrder.GatewayID, err)
		}

		network, err := lockPaymentOrder.Token.QueryNetwork().Only(ctx)
		if err != nil {
			return fmt.Errorf("%s - failed to fetch network: %w", lockPaymentOrder.GatewayID, err)
		}

		err = s.order.RefundOrder(ctx, client, network, lockPaymentOrder.GatewayID)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
				"OrderID": order.ID,
				"OrderTrxHash": order.TxHash,
				"GatewayID": order.GatewayID,
			}).Errorf("Handle cancellation failed to refund order")
		}

	} else if createdLockPaymentOrder != nil {
		_, err := db.Client.LockPaymentOrder.
			Update().
			Where(
				lockpaymentorder.IDEQ(createdLockPaymentOrder.ID),
			).
			SetCancellationCount(3).
			SetCancellationReasons([]string{cancellationReason}).
			SetStatus(lockpaymentorder.StatusCancelled).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("%s - failed to update lock payment order: %w", createdLockPaymentOrder.GatewayID, err)
		}

		network, err := createdLockPaymentOrder.QueryToken().QueryNetwork().Only(ctx)
		if err != nil {
			return fmt.Errorf("%s - failed to fetch network: %w", createdLockPaymentOrder.GatewayID, err)
		}

		err = s.order.RefundOrder(ctx, client, network, createdLockPaymentOrder.GatewayID)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
				"OrderID": createdLockPaymentOrder.ID,
				"OrderTrxHash": createdLockPaymentOrder.TxHash,
				"GatewayID": createdLockPaymentOrder.GatewayID,
			}).Errorf("Handle cancellation failed to refund order")
		}
	}

	return nil
}

// UpdateOrderStatusRefunded updates the status of a payment order to refunded
func (s *IndexerService) UpdateOrderStatusRefunded(ctx context.Context, network *ent.Network, log *types.OrderRefundedEvent) error {
	gatewayId := fmt.Sprintf("0x%v", hex.EncodeToString(log.OrderId[:]))

	// Fetch payment order
	paymentOrderExists := true
	paymentOrder, err := db.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.GatewayIDEQ(gatewayId),
			paymentorder.HasTokenWith(
				tokenEnt.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		WithSenderProfile().
		WithLinkedAddress().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			// Payment order does not exist, no need to update
			paymentOrderExists = false
		} else {
			return fmt.Errorf("UpdateOrderStatusRefunded.fetchOrder: %v", err)
		}
	}

	tx, err := db.Client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusRefunded.dbtransaction %v", err)
	}

	// Attempt to update an existing log
	var transactionLog *ent.TransactionLog
	updatedLogRows, err := tx.TransactionLog.
		Update().
		Where(
			transactionlog.StatusEQ(transactionlog.StatusOrderRefunded),
			transactionlog.GatewayIDEQ(gatewayId),
			transactionlog.NetworkEQ(network.Identifier),
		).
		SetTxHash(log.TxHash).
		SetMetadata(
			map[string]interface{}{
				"GatewayID":       gatewayId,
				"TransactionData": log,
			}).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusRefunded.update: %v", err)
	}

	// If no rows were updated, create a new log
	if updatedLogRows == 0 {
		transactionLog, err = tx.TransactionLog.
			Create().
			SetStatus(transactionlog.StatusOrderRefunded).
			SetTxHash(log.TxHash).
			SetGatewayID(gatewayId).
			SetNetwork(network.Identifier).
			SetMetadata(
				map[string]interface{}{
					"GatewayID":       gatewayId,
					"TransactionData": log,
				}).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("UpdateOrderStatusRefunded.create: %v", err)
		}
	}

	// Aggregator side status update
	lockPaymentOrderUpdate := tx.LockPaymentOrder.
		Update().
		Where(
			lockpaymentorder.GatewayIDEQ(gatewayId),
			lockpaymentorder.HasTokenWith(
				tokenEnt.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		SetBlockNumber(int64(log.BlockNumber)).
		SetTxHash(log.TxHash).
		SetStatus(lockpaymentorder.StatusRefunded)

	if transactionLog != nil {
		lockPaymentOrderUpdate = lockPaymentOrderUpdate.AddTransactions(transactionLog)
	}

	_, err = lockPaymentOrderUpdate.Save(ctx)
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusRefunded.aggregator: %v", err)
	}

	// Sender side status update
	if paymentOrderExists && paymentOrder.Status != paymentorder.StatusRefunded {
		paymentOrderUpdate := tx.PaymentOrder.
			Update().
			Where(
				paymentorder.GatewayIDEQ(gatewayId),
				paymentorder.HasTokenWith(
					tokenEnt.HasNetworkWith(
						networkent.IdentifierEQ(network.Identifier),
					),
				),
			).
			SetTxHash(log.TxHash).
			SetStatus(paymentorder.StatusRefunded)

		if paymentOrder.Edges.LinkedAddress != nil {
			paymentOrderUpdate = paymentOrderUpdate.SetGatewayID("")
		}

		if transactionLog != nil {
			paymentOrderUpdate = paymentOrderUpdate.AddTransactions(transactionLog)
		}

		_, err = paymentOrderUpdate.Save(ctx)
		if err != nil {
			return fmt.Errorf("UpdateOrderStatusRefunded.sender: %v", err)
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("UpdateOrderStatusRefunded.commit %v", err)
	}

	if paymentOrderExists && paymentOrder.Status != paymentorder.StatusRefunded {
		paymentOrder.Status = paymentorder.StatusRefunded
		paymentOrder.TxHash = log.TxHash

		// Send webhook notification to sender
		err = utils.SendPaymentOrderWebhook(ctx, paymentOrder)
		if err != nil {
			return fmt.Errorf("UpdateOrderStatusRefunded.webhook: %v", err)
		}
	}

	return nil
}

// UpdateOrderStatusSettled updates the status of a payment order to settled
func (s *IndexerService) UpdateOrderStatusSettled(ctx context.Context, network *ent.Network, event *types.OrderSettledEvent) error {
	gatewayId := fmt.Sprintf("0x%v", hex.EncodeToString(event.OrderId[:]))

	// Fetch payment order
	paymentOrderExists := true
	paymentOrder, err := db.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.GatewayIDEQ(gatewayId),
			paymentorder.HasTokenWith(
				tokenEnt.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		WithSenderProfile().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			// Payment order does not exist, no need to update
			paymentOrderExists = false
		} else {
			return fmt.Errorf("UpdateOrderStatusSettled.fetchOrder: %v", err)
		}
	}

	tx, err := db.Client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusSettled.db: %v", err)
	}

	// Attempt to update an existing log
	var transactionLog *ent.TransactionLog
	updatedLogRows, err := tx.TransactionLog.
		Update().
		Where(
			transactionlog.StatusEQ(transactionlog.StatusOrderSettled),
			transactionlog.GatewayIDEQ(gatewayId),
			transactionlog.NetworkEQ(network.Identifier),
		).
		SetTxHash(event.TxHash).
		SetMetadata(map[string]interface{}{
			"GatewayID":       gatewayId,
			"TransactionData": event,
		}).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusSettled.update: %v", err)
	}

	// If no rows were updated, create a new log
	if updatedLogRows == 0 {
		transactionLog, err = tx.TransactionLog.
			Create().
			SetStatus(transactionlog.StatusOrderSettled).
			SetTxHash(event.TxHash).
			SetGatewayID(gatewayId).
			SetNetwork(network.Identifier).
			SetMetadata(map[string]interface{}{
				"GatewayID":       gatewayId,
				"TransactionData": event,
			}).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("UpdateOrderStatusSettled.create: %v", err)
		}
	}

	// Aggregator side status update
	splitOrderId, _ := uuid.Parse(utils.Byte32ToString(event.SplitOrderId))
	lockPaymentOrderUpdate := tx.LockPaymentOrder.
		Update().
		Where(
			lockpaymentorder.IDEQ(splitOrderId),
			lockpaymentorder.HasTokenWith(
				tokenEnt.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		SetBlockNumber(int64(event.BlockNumber)).
		SetTxHash(event.TxHash).
		SetStatus(lockpaymentorder.StatusSettled)

	if transactionLog != nil {
		lockPaymentOrderUpdate = lockPaymentOrderUpdate.AddTransactions(transactionLog)
	}

	_, err = lockPaymentOrderUpdate.Save(ctx)
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusSettled.aggregator: %v", err)
	}

	settledPercent := decimal.NewFromInt(0)
	// Sender side status update
	if paymentOrderExists && paymentOrder.Status != paymentorder.StatusSettled {
		paymentOrderUpdate := tx.PaymentOrder.
			Update().
			Where(
				paymentorder.GatewayIDEQ(gatewayId),
			).
			SetBlockNumber(int64(event.BlockNumber)).
			SetTxHash(event.TxHash)

		// Convert settled percent to BPS and update
		settledPercent = paymentOrder.PercentSettled.Add(decimal.NewFromBigInt(event.SettlePercent, 0).Div(decimal.NewFromInt(1000)))

		// If settled percent is 100%, mark order as settled
		if settledPercent.GreaterThanOrEqual(decimal.NewFromInt(100)) {
			settledPercent = decimal.NewFromInt(100)
			paymentOrderUpdate = paymentOrderUpdate.SetStatus(paymentorder.StatusSettled)
		}

		if transactionLog != nil {
			paymentOrderUpdate = paymentOrderUpdate.AddTransactions(transactionLog)
		}

		_, err = paymentOrderUpdate.
			SetPercentSettled(settledPercent).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("UpdateOrderStatusSettled.sender: %v", err)
		}

		paymentOrder.BlockNumber = int64(event.BlockNumber)
		paymentOrder.TxHash = event.TxHash
		paymentOrder.PercentSettled = settledPercent
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("UpdateOrderStatusSettled.sender %v", err)
	}

	if paymentOrderExists && paymentOrder.Status != paymentorder.StatusSettled {
		if settledPercent.GreaterThanOrEqual(decimal.NewFromInt(100)) {
			paymentOrder.Status = paymentorder.StatusSettled
		}
		paymentOrder.TxHash = event.TxHash

		// Send webhook notification to sender
		err = utils.SendPaymentOrderWebhook(ctx, paymentOrder)
		if err != nil {
			return fmt.Errorf("UpdateOrderStatusSettled.webhook: %v", err)
		}
	}

	return nil
}

// getOrderRecipientFromMessageHash decrypts the message hash and returns the order recipient
func (s *IndexerService) getOrderRecipientFromMessageHash(messageHash string) (*types.PaymentOrderRecipient, error) {
	messageCipher, err := base64.StdEncoding.DecodeString(messageHash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode message hash: %w", err)
	}

	// Decrypt with the private key of the aggregator
	message, err := cryptoUtils.PublicKeyDecryptJSON(messageCipher, config.CryptoConfig().AggregatorPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message hash: %w", err)
	}

	messageBytes, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}

	var recipient *types.PaymentOrderRecipient
	err = json.Unmarshal(messageBytes, &recipient)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return recipient, nil
}

// UpdateReceiveAddressStatus updates the status of a receive address. if `done` is true, the indexing process is complete for the given receive address
func (s *IndexerService) UpdateReceiveAddressStatus(
	ctx context.Context, client types.RPCClient, receiveAddress *ent.ReceiveAddress, paymentOrder *ent.PaymentOrder, event *types.TokenTransferEvent,
) (done bool, err error) {
	if event.To == receiveAddress.Address {
		// Check for existing address with txHash
		count, err := db.Client.ReceiveAddress.
			Query().
			Where(receiveaddress.TxHashEQ(event.TxHash)).
			Count(ctx)
		if err != nil {
			return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
		}

		if count > 0 && receiveAddress.Status != receiveaddress.StatusUnused {
			// This transfer has already been indexed
			return false, nil
		}

		// Check for existing payment order with txHash
		if paymentOrder.TxHash == event.TxHash {
			// This transfer has already been indexed
			return false, nil
		}

		// This is a transfer to the receive address to create an order on-chain
		// Compare the transferred value with the expected order amount + fees
		fees := paymentOrder.NetworkFee.Add(paymentOrder.SenderFee).Add(paymentOrder.ProtocolFee)
		orderAmountWithFees := paymentOrder.Amount.Add(fees).Round(int32(paymentOrder.Edges.Token.Decimals))
		orderAmountWithFeesInSubunit := utils.ToSubunit(orderAmountWithFees, paymentOrder.Edges.Token.Decimals)
		comparisonResult := event.Value.Cmp(orderAmountWithFeesInSubunit)

		tx, err := db.Client.Tx(ctx)
		if err != nil {
			return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
		}

		paymentOrderUpdate := tx.PaymentOrder.Update().Where(paymentorder.IDEQ(paymentOrder.ID))
		if paymentOrder.ReturnAddress == "" {
			paymentOrderUpdate = paymentOrderUpdate.SetReturnAddress(event.From)
		}

		orderRecipient := paymentOrder.Edges.Recipient
		if comparisonResult != 0 {
			// Update the order amount will be updated to whatever amount was sent to the receive address
			newOrderAmount := utils.FromSubunit(event.Value, paymentOrder.Edges.Token.Decimals).Sub(fees.Round(int32(paymentOrder.Edges.Token.Decimals)))
			paymentOrderUpdate = paymentOrderUpdate.SetAmount(newOrderAmount.Round(int32(paymentOrder.Edges.Token.Decimals)))
			// Update the rate with the current rate if order is older than 30 mins for a P2P order from the sender dashboard
			if strings.HasPrefix(orderRecipient.Memo, "P#P") && orderRecipient.ProviderID != "" && paymentOrder.CreatedAt.Before(time.Now().Add(-30*time.Minute)) {
				providerProfile, err := db.Client.ProviderProfile.
					Query().
					Where(
						providerprofile.HasUserWith(
							user.HasSenderProfileWith(
								senderprofile.HasPaymentOrdersWith(
									paymentorder.IDEQ(paymentOrder.ID),
								),
							),
						),
					).
					Only(ctx)
				if err != nil {
					return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
				}

				institution, err := utils.GetInstitutionByCode(ctx, orderRecipient.Institution)
				if err != nil {
					return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
				}

				rate, err := s.priorityQueue.GetProviderRate(ctx, providerProfile, paymentOrder.Edges.Token.Symbol, institution.Edges.FiatCurrency.Code)
				if err != nil {
					return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
				}
				paymentOrderUpdate = paymentOrderUpdate.SetRate(rate)
			}
			comparisonResult = 0
		}

		if paymentOrder.AmountPaid.GreaterThanOrEqual(decimal.Zero) && paymentOrder.AmountPaid.LessThan(orderAmountWithFees) {
			transactionLog, err := tx.TransactionLog.
				Create().
				SetStatus(transactionlog.StatusCryptoDeposited).
				SetGatewayID(paymentOrder.GatewayID).
				SetTxHash(event.TxHash).
				SetNetwork(paymentOrder.Edges.Token.Edges.Network.Identifier).
				SetMetadata(map[string]interface{}{
					"GatewayID":       paymentOrder.GatewayID,
					"transactionData": event,
				}).
				Save(ctx)
			if err != nil {
				return true, fmt.Errorf("UpdateReceiveAddressStatus.transactionlog: %v", err)
			}

			_, err = paymentOrderUpdate.
				SetFromAddress(event.From).
				SetTxHash(event.TxHash).
				SetBlockNumber(int64(event.BlockNumber)).
				AddAmountPaid(utils.FromSubunit(event.Value, paymentOrder.Edges.Token.Decimals)).
				AddTransactions(transactionLog).
				Save(ctx)
			if err != nil {
				return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
			}

			// Commit the transaction
			if err := tx.Commit(); err != nil {
				return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
			}
		}

		if comparisonResult == 0 {
			// Transfer value equals order amount with fees
			_, err = receiveAddress.
				Update().
				SetStatus(receiveaddress.StatusUsed).
				SetLastUsed(time.Now()).
				SetTxHash(event.TxHash).
				SetLastIndexedBlock(int64(event.BlockNumber)).
				Save(ctx)
			if err != nil {
				return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
			}

			err = s.order.CreateOrder(ctx, client, paymentOrder.ID)
			if err != nil {
				return true, fmt.Errorf("UpdateReceiveAddressStatus.CreateOrder: %v", err)
			}

			return true, nil
		}

		err = s.HandleReceiveAddressValidity(ctx, client, receiveAddress, paymentOrder)
		if err != nil {
			return true, fmt.Errorf("UpdateReceiveAddressStatus.HandleReceiveAddressValidity: %v", err)
		}
	}

	return false, nil
}

// fetchLatestOrderEvents fetches the latest events of the given order from the Tron network.
func (s *IndexerService) fetchLatestOrderEvents(rpcEndpoint, network, txHash string) ([]interface{}, error) {
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
			"Error": fmt.Sprintf("%v", err),
			"TxHash": txHash,
		}).Errorf("Failed to fetch txn event logs for %s", network)
		return nil, err
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Response": data,
		}).Errorf("Failed to parse JSON response for %s after fetching event logs", network)
		return nil, err
	}

	if data["success"].(bool) {
		return data["data"].([]interface{}), nil
	}

	return nil, fmt.Errorf("failed to fetch txn event logs: %v", data["error"])
}

// getProvisionBucket returns the provision bucket for a lock payment order
func (s *IndexerService) getProvisionBucket(ctx context.Context, amount decimal.Decimal, currency *ent.FiatCurrency) (*ent.ProvisionBucket, bool, error) {
	provisionBucket, err := db.Client.ProvisionBucket.
		Query().
		Where(
			provisionbucket.MaxAmountGTE(amount),
			provisionbucket.MinAmountLTE(amount),
			provisionbucket.HasCurrencyWith(
				fiatcurrency.IDEQ(currency.ID),
			),
		).
		WithCurrency().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			// Check if the amount is less than the minimum bucket
			minBucket, err := db.Client.ProvisionBucket.
				Query().
				Where(
					provisionbucket.HasCurrencyWith(
						fiatcurrency.IDEQ(currency.ID),
					),
				).
				Order(ent.Asc(provisionbucket.FieldMinAmount)).
				First(ctx)
			if err != nil {
				return nil, false, fmt.Errorf("failed to fetch minimum bucket: %w", err)
			}
			if amount.LessThan(minBucket.MinAmount) {
				return nil, true, nil
			}
		}
		return nil, false, fmt.Errorf("failed to fetch provision bucket: %w", err)
	}

	return provisionBucket, false, nil
}

// splitLockPaymentOrder splits a lock payment order into multiple orders
func (s *IndexerService) splitLockPaymentOrder(ctx context.Context, client types.RPCClient, lockPaymentOrder types.LockPaymentOrderFields, currency *ent.FiatCurrency) error {
	buckets, err := db.Client.ProvisionBucket.
		Query().
		Where(provisionbucket.HasCurrencyWith(
			fiatcurrency.IDEQ(currency.ID),
		)).
		WithProviderProfiles().
		Order(ent.Desc(provisionbucket.FieldMaxAmount)).
		All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Currency": currency.ID,
			"CurrencyCode": currency.Code,
			"CurrencEnabled": currency.IsEnabled,
		}).Errorf("failed to fetch provision buckets when splitting lock payment order")
		return err
	}

	amountToSplit := lockPaymentOrder.Amount.Mul(lockPaymentOrder.Rate) // e.g 100,000

	var isRefunded bool

	for _, bucket := range buckets {
		// Get the number of providers in the bucket
		bucketSize := int64(len(bucket.Edges.ProviderProfiles))

		// Get the number of allocations to make in the bucket
		numberOfAllocations := amountToSplit.Div(bucket.MaxAmount).IntPart() // e.g 100000 / 10000 = 10

		var trips int64

		if bucketSize >= numberOfAllocations {
			trips = numberOfAllocations // e.g 10
		} else {
			trips = bucketSize // e.g 2
		}

		// Create a slice to hold the LockPaymentOrder entities for this bucket
		lockOrders := make([]*ent.LockPaymentOrderCreate, 0, trips)

		tx, err := db.Client.Tx(ctx)
		if err != nil {
			return err
		}

		for i := int64(0); i < trips; i++ {
			ratio := bucket.MaxAmount.Div(amountToSplit)
			orderPercent := ratio.Mul(decimal.NewFromInt(100))
			lockOrder := tx.LockPaymentOrder.
				Create().
				SetToken(lockPaymentOrder.Token).
				SetGatewayID(lockPaymentOrder.GatewayID).
				SetAmount(bucket.MaxAmount.Div(lockPaymentOrder.Rate)).
				SetRate(lockPaymentOrder.Rate).
				SetOrderPercent(orderPercent).
				SetBlockNumber(lockPaymentOrder.BlockNumber).
				SetTxHash(lockPaymentOrder.TxHash).
				SetInstitution(lockPaymentOrder.Institution).
				SetAccountIdentifier(lockPaymentOrder.AccountIdentifier).
				SetAccountName(lockPaymentOrder.AccountName).
				SetProviderID(lockPaymentOrder.ProviderID).
				SetProvisionBucket(bucket)
			lockOrders = append(lockOrders, lockOrder)
		}

		// Batch insert all LockPaymentOrder entities for this bucket in a single transaction
		ordersCreated, err := tx.LockPaymentOrder.
			CreateBulk(lockOrders...).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
				"OrderID": lockPaymentOrder.GatewayID,
			}).Errorf("Failed to create lock payment order in Bulk when splitting lock payment order")
			_ = tx.Rollback()
			return err
		}

		// Commit the transaction if everything succeeded
		if err := tx.Commit(); err != nil {
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
				"OrderID": lockPaymentOrder.GatewayID,
			}).Errorf("Failed to commit transaction when splitting lock payment order")
			return err
		}

		// Check AML compliance
		if serverConf.Environment == "production" && !strings.HasPrefix(lockPaymentOrder.Network.Identifier, "tron") {
			ok, err := s.checkAMLCompliance(lockPaymentOrder.Network.RPCEndpoint, lockPaymentOrder.TxHash)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"endpoint": lockPaymentOrder.Network.RPCEndpoint,
					"TxHash": lockPaymentOrder.TxHash,
				}).Errorf("Failed to check AML Compliance")
			}

			if !ok && err == nil && len(ordersCreated) > 0 {
				isRefunded = true
				err := s.handleCancellation(ctx, client, ordersCreated[0], nil, "AML compliance check failed")
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error": fmt.Sprintf("%v", err),
						"OrderID": ordersCreated[0].ID,
						"OrderGatewayID": ordersCreated[0].GatewayID,
						"Reason": "AML compliance check failed",
					}).Errorf("Failed to handle cancellation when splitting lock payment order")
				}
				break
			}
		}

		// Assign the lock payment orders to providers
		for _, order := range ordersCreated {
			lockPaymentOrder.ID = order.ID
			_ = s.priorityQueue.AssignLockPaymentOrder(ctx, lockPaymentOrder)
		}

		amountToSplit = amountToSplit.Sub(bucket.MaxAmount)
	}

	largestBucket := buckets[0]

	if amountToSplit.LessThan(largestBucket.MaxAmount) {
		bucket, _, err := s.getProvisionBucket(ctx, amountToSplit, currency)
		if err != nil {
			return err
		}

		orderCreatedUpdate := db.Client.LockPaymentOrder.
			Create().
			SetToken(lockPaymentOrder.Token).
			SetGatewayID(lockPaymentOrder.GatewayID).
			SetAmount(amountToSplit.Div(lockPaymentOrder.Rate)).
			SetRate(lockPaymentOrder.Rate).
			SetBlockNumber(lockPaymentOrder.BlockNumber).
			SetTxHash(lockPaymentOrder.TxHash).
			SetInstitution(lockPaymentOrder.Institution).
			SetAccountIdentifier(lockPaymentOrder.AccountIdentifier).
			SetAccountName(lockPaymentOrder.AccountName).
			SetProviderID(lockPaymentOrder.ProviderID).
			SetProvisionBucket(bucket)

		if isRefunded {
			orderCreatedUpdate = orderCreatedUpdate.SetStatus(lockpaymentorder.StatusRefunded)
		}

		orderCreated, err := orderCreatedUpdate.Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
				"OrderID": lockPaymentOrder.GatewayID,
			}).Errorf("Failed to create lock payment order when splitting lock payment order")
			return err
		}

		if !isRefunded {
			// Assign the lock payment order to a provider
			lockPaymentOrder.ID = orderCreated.ID
			_ = s.priorityQueue.AssignLockPaymentOrder(ctx, lockPaymentOrder)
		}
	} else {
		// TODO: figure out how to handle this case, currently it recursively splits the amount
		lockPaymentOrder.Amount = amountToSplit.Div(lockPaymentOrder.Rate)
		err := s.splitLockPaymentOrder(ctx, client, lockPaymentOrder, currency)
		if err != nil {
			return err
		}
	}

	return nil
}

// checkAMLCompliance checks if a transaction is compliant with AML rules
func (s *IndexerService) checkAMLCompliance(rpcUrl string, txHash string) (bool, error) {
	if !strings.Contains(rpcUrl, "shield3") {
		return true, nil
	}

	type Transaction struct {
		Kind int         `json:"__kind"`
		Data interface{} `json:"data"`
	}

	type Response struct {
		Transaction Transaction `json:"transaction"`
		Decision    string      `json:"decision"`
	}

	// Make RPC call to Shield3 here
	var err error
	var client *rpc.Client
	client, err = rpc.Dial(rpcUrl)
	if err != nil {
		return false, fmt.Errorf("failed to connect to RPC client: %v", err)
	}

	var result json.RawMessage
	err = client.Call(&result, "eth_backfillTransaction", txHash)
	if err != nil {
		return false, fmt.Errorf("failed to backfill transaction: %v", err)
	}

	var backfillTransaction Response
	err = json.Unmarshal(result, &backfillTransaction)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if backfillTransaction.Decision == "Allow" {
		return true, nil
	}

	return false, nil
}
