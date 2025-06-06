package indexer

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/linkedaddress"
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/receiveaddress"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/services/order"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
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
func (s *IndexerEVM) IndexTransfer(ctx context.Context, rpcClient types.RPCClient, order *ent.PaymentOrder, token *ent.Token, fromBlock int64, toBlock int64) error {
	// Get Transfer event data
	payload := map[string]interface{}{
		"eventName": "Transfer",
		"fromBlock": fromBlock,
		"toBlock":   toBlock,
		"order":     "asc",
	}

	result, err := s.engineService.GetContractEvents(ctx, token.Edges.Network.ChainID, token.ContractAddress, payload)
	if err != nil {
		return fmt.Errorf("ProcessTransfer.getTransferEventData: %w", err)
	}

	unknownAddresses := []string{}
	addressToEvent := make(map[string]*types.TokenTransferEvent)

	// Parse transfer event data
	for _, r := range result {
		transferData := r.(map[string]interface{})["data"]
		transferTransaction := r.(map[string]interface{})["transaction"]
		transferValue := utils.HexToDecimal(transferData.(map[string]interface{})["value"].(map[string]interface{})["hex"].(string))

		toAddress := transferData.(map[string]interface{})["to"].(string)
		fromAddress := transferData.(map[string]interface{})["from"].(string)

		if strings.EqualFold(fromAddress, token.Edges.Network.GatewayContractAddress) {
			continue
		}

		transferEvent := &types.TokenTransferEvent{
			BlockNumber: int64(transferTransaction.(map[string]interface{})["blockNumber"].(float64)),
			TxHash:      transferTransaction.(map[string]interface{})["transactionHash"].(string),
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

	// Process receive addresses and update their status
	if err := s.processReceiveAddresses(ctx, unknownAddresses, addressToEvent); err != nil {
		return err
	}

	// Process linked addresses and create payment orders
	if err := s.processLinkedAddresses(ctx, unknownAddresses, addressToEvent, token); err != nil {
		return err
	}

	return nil
}

// IndexOrderCreated indexes orders created in the Gateway contract for EVM networks.
func (s *IndexerEVM) IndexOrderCreated(ctx context.Context, rpcClient types.RPCClient, order *ent.PaymentOrder, network *ent.Network, fromBlock int64, toBlock int64) error {
	// Get OrderCreated event data
	eventPayload := map[string]interface{}{
		"eventName": "OrderCreated",
		"fromBlock": fromBlock,
		"toBlock":   toBlock,
		"order":     "desc",
	}

	events, err := s.engineService.GetContractEvents(ctx, network.ChainID, network.GatewayContractAddress, eventPayload)
	if err != nil {
		return fmt.Errorf("IndexOrderCreated.getEvents: %w", err)
	}

	result := map[string]interface{}{}
	txHashes := []string{}
	hashToEvent := make(map[string]*types.OrderCreatedEvent)

	for _, r := range events {
		result = r.(map[string]interface{})["data"].(map[string]interface{})

		orderAmount := utils.HexToDecimal(result["amount"].(map[string]interface{})["hex"].(string))
		protocolFee := utils.HexToDecimal(result["protocolFee"].(map[string]interface{})["hex"].(string))
		createdEvent := &types.OrderCreatedEvent{
			BlockNumber: int64(r.(map[string]interface{})["transaction"].(map[string]interface{})["blockNumber"].(float64)),
			TxHash:      r.(map[string]interface{})["transaction"].(map[string]interface{})["transactionHash"].(string),
			Token:       result["token"].(string),
			Amount:      orderAmount,
			ProtocolFee: protocolFee,
			OrderId:     result["orderId"].(string),
			Rate:        utils.HexToDecimal(result["rate"].(map[string]interface{})["hex"].(string)).Div(decimal.NewFromInt(100)),
			MessageHash: result["messageHash"].(string),
			Sender:      result["sender"].(string),
		}

		txHashes = append(txHashes, createdEvent.TxHash)
		hashToEvent[createdEvent.TxHash] = createdEvent
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

		// logger.Infof("IndexOrderCreated.order 2: %v", order)
		// encryptedOrderRecipient, err := cryptoUtils.EncryptOrderRecipient(order.Edges.Recipient)
		// if err != nil {
		// 	continue
		// }

		// if createdEvent.MessageHash != encryptedOrderRecipient {
		// 	logger.Infof("IndexOrderCreated.order 2.1: %v", order)
		// 	continue
		// }

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
				SetGatewayID(result["orderId"].(string)).
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

// IndexOrderSettled indexes orders settled in the Gateway contract for EVM networks.
func (s *IndexerEVM) IndexOrderSettled(ctx context.Context, rpcClient types.RPCClient, order *ent.LockPaymentOrder, network *ent.Network, fromBlock int64, toBlock int64) error {
	// Get OrderSettled event data
	eventPayload := map[string]interface{}{
		"eventName": "OrderSettled",
		"fromBlock": fromBlock,
		"toBlock":   toBlock,
		"order":     "desc",
	}

	events, err := s.engineService.GetContractEvents(ctx, network.ChainID, network.GatewayContractAddress, eventPayload)
	if err != nil {
		return fmt.Errorf("IndexOrderSettled.getEvents: %w", err)
	}

	result := map[string]interface{}{}
	txHashes := []string{}
	hashToEvent := make(map[string]*types.OrderSettledEvent)

	for _, r := range events {
		result = r.(map[string]interface{})["data"].(map[string]interface{})
		settledEvent := &types.OrderSettledEvent{
			BlockNumber:       int64(r.(map[string]interface{})["transaction"].(map[string]interface{})["blockNumber"].(float64)),
			TxHash:            r.(map[string]interface{})["transaction"].(map[string]interface{})["transactionHash"].(string),
			SplitOrderId:      result["splitOrderId"].(string),
			OrderId:           result["orderId"].(string),
			LiquidityProvider: result["liquidityProvider"].(string),
			SettlePercent:     utils.HexToDecimal(result["settlePercent"].(map[string]interface{})["hex"].(string)),
		}

		txHashes = append(txHashes, settledEvent.TxHash)
		hashToEvent[settledEvent.TxHash] = settledEvent
	}

	if len(txHashes) == 0 {
		return nil
	}

	lockOrders, err := storage.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.TxHashIn(txHashes...),
			lockpaymentorder.StatusEQ(lockpaymentorder.StatusValidated),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		All(ctx)
	if err != nil {
		return fmt.Errorf("IndexOrderSettled.fetchLockOrders: %w", err)
	}

	var wg sync.WaitGroup
	for _, lockOrder := range lockOrders {
		settledEvent, ok := hashToEvent[lockOrder.TxHash]
		if !ok {
			continue
		}

		wg.Add(1)
		go func(lo *ent.LockPaymentOrder, se *types.OrderSettledEvent) {
			defer wg.Done()

			// Update order status
			err := common.UpdateOrderStatusSettled(ctx, lo.Edges.Token.Edges.Network, se)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   fmt.Sprintf("%v", err),
					"OrderID": se.OrderId,
				}).Errorf("Failed to update order status settlement when indexing order settled events for %s", order.Edges.Token.Edges.Network.Identifier)
			}
		}(lockOrder, settledEvent)
	}
	wg.Wait()

	return nil
}

// IndexOrderRefunded indexes orders settled in the Gateway contract for EVM networks.
func (s *IndexerEVM) IndexOrderRefunded(ctx context.Context, rpcClient types.RPCClient, order *ent.LockPaymentOrder, network *ent.Network, fromBlock int64, toBlock int64) error {
	// Get OrderRefunded event data
	eventPayload := map[string]interface{}{
		"eventName": "OrderRefunded",
		"fromBlock": fromBlock,
		"toBlock":   toBlock,
		"order":     "desc",
	}

	events, err := s.engineService.GetContractEvents(ctx, network.ChainID, network.GatewayContractAddress, eventPayload)
	if err != nil {
		return fmt.Errorf("IndexOrderRefunded.getEvents: %w", err)
	}

	result := map[string]interface{}{}
	txHashes := []string{}
	hashToEvent := make(map[string]*types.OrderRefundedEvent)

	for _, r := range events {
		result = r.(map[string]interface{})["data"].(map[string]interface{})
		refundFee := utils.HexToDecimal(result["fee"].(map[string]interface{})["hex"].(string))

		refundedEvent := &types.OrderRefundedEvent{
			BlockNumber: int64(r.(map[string]interface{})["transaction"].(map[string]interface{})["blockNumber"].(float64)),
			TxHash:      r.(map[string]interface{})["transaction"].(map[string]interface{})["transactionHash"].(string),
			Fee:         refundFee,
			OrderId:     result["orderId"].(string),
		}

		txHashes = append(txHashes, refundedEvent.TxHash)
		hashToEvent[refundedEvent.TxHash] = refundedEvent
	}

	if len(txHashes) == 0 {
		return nil
	}

	lockOrders, err := storage.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.TxHashIn(txHashes...),
			lockpaymentorder.Or(
				lockpaymentorder.StatusEQ(lockpaymentorder.StatusPending),
				lockpaymentorder.StatusEQ(lockpaymentorder.StatusCancelled),
			),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		All(ctx)
	if err != nil {
		return fmt.Errorf("IndexOrderRefunded.fetchLockOrders: %w", err)
	}

	var wg sync.WaitGroup
	for _, lockOrder := range lockOrders {
		wg.Add(1)
		go func(lockOrder *ent.LockPaymentOrder) {
			defer wg.Done()
			refundedEvent, ok := hashToEvent[lockOrder.TxHash]
			if !ok {
				return
			}

			refundedEvent.Fee = refundedEvent.Fee.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(lockOrder.Edges.Token.Decimals))))

			err := common.UpdateOrderStatusRefunded(ctx, lockOrder.Edges.Token.Edges.Network, refundedEvent)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   fmt.Sprintf("%v", err),
					"OrderID": refundedEvent.OrderId,
					"TxHash":  refundedEvent.TxHash,
				}).Errorf("Failed to update order status refund when indexing order refunded events for %s", lockOrder.Edges.Token.Edges.Network.Identifier)
			}
		}(lockOrder)
	}
	wg.Wait()

	return nil
}

// processReceiveAddresses processes transfers to receive addresses and updates their status
func (s *IndexerEVM) processReceiveAddresses(ctx context.Context, unknownAddresses []string, addressToEvent map[string]*types.TokenTransferEvent) error {
	orders, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.HasReceiveAddressWith(
				receiveaddress.StatusEQ(receiveaddress.StatusUnused),
				receiveaddress.ValidUntilGT(time.Now()),
				receiveaddress.AddressIn(unknownAddresses...),
			),
			paymentorder.StatusEQ(paymentorder.StatusInitiated),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithReceiveAddress().
		WithRecipient().
		All(ctx)
	if err != nil {
		return fmt.Errorf("processReceiveAddresses.fetchOrders: %w", err)
	}

	var wg sync.WaitGroup
	for _, order := range orders {
		receiveAddress := order.Edges.ReceiveAddress
		wg.Add(1)
		go func(receiveAddress *ent.ReceiveAddress) {
			defer wg.Done()
			transferEvent, ok := addressToEvent[receiveAddress.Address]
			if !ok {
				return
			}

			_, err := common.UpdateReceiveAddressStatus(ctx, order.Edges.ReceiveAddress, order, transferEvent, s.order.CreateOrder, s.priorityQueue.GetProviderRate)
			if err != nil {
				if !strings.Contains(fmt.Sprintf("%v", err), "Duplicate payment order") && !strings.Contains(fmt.Sprintf("%v", err), "Receive address not found") {
					logger.WithFields(logger.Fields{
						"Error":   fmt.Sprintf("%v", err),
						"OrderID": order.ID.String(),
					}).Errorf("Failed to update receive address status when indexing ERC20 transfers for %s", order.Edges.Token.Edges.Network.Identifier)
				}
				return
			}
		}(receiveAddress)
	}
	wg.Wait()
	return nil
}

// processLinkedAddresses processes transfers to linked addresses and creates payment orders
func (s *IndexerEVM) processLinkedAddresses(ctx context.Context, unknownAddresses []string, addressToEvent map[string]*types.TokenTransferEvent, token *ent.Token) error {
	linkedAddresses, err := storage.Client.LinkedAddress.
		Query().
		Where(
			linkedaddress.AddressIn(unknownAddresses...),
		).
		All(ctx)
	if err != nil {
		if !ent.IsNotFound(err) {
			logger.WithFields(logger.Fields{
				"Error":     fmt.Sprintf("%v", err),
				"Addresses": unknownAddresses,
			}).Errorf("Failed to query linked addresses when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
		}
		return nil
	}

	var wg sync.WaitGroup
	for _, linkedAddress := range linkedAddresses {
		wg.Add(1)
		go func(linkedAddress *ent.LinkedAddress) {
			defer wg.Done()
			ctx := context.Background()
			transferEvent, ok := addressToEvent[linkedAddress.Address]
			if !ok {
				return
			}

			orderAmount := transferEvent.Value

			// Check if the payment order already exists
			paymentOrderExists := true
			_, err := storage.Client.PaymentOrder.
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
					logger.WithFields(logger.Fields{
						"Error":         fmt.Sprintf("%v", err),
						"LinkedAddress": linkedAddress.Address,
					}).Errorf("Failed to fetch payment order when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
					return
				}
			}

			if paymentOrderExists {
				return
			}

			// Create payment order
			institution, err := utils.GetInstitutionByCode(ctx, linkedAddress.Institution, true)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":                    fmt.Sprintf("%v", err),
					"LinkedAddress":            linkedAddress.Address,
					"LinkedAddressInstitution": linkedAddress.Institution,
				}).Errorf("Failed to get institution when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
				return
			}

			// Get rate from priority queue
			if !strings.EqualFold(token.BaseCurrency, institution.Edges.FiatCurrency.Code) && !strings.EqualFold(token.BaseCurrency, "USD") {
				return
			}
			var rateResponse decimal.Decimal
			if !strings.EqualFold(token.BaseCurrency, institution.Edges.FiatCurrency.Code) {
				rateResponse, err = utils.GetTokenRateFromQueue(token.Symbol, orderAmount, institution.Edges.FiatCurrency.Code, institution.Edges.FiatCurrency.MarketRate)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":                    fmt.Sprintf("%v", err),
						"Token":                    token.Symbol,
						"LinkedAddressInstitution": linkedAddress.Institution,
						"Code":                     institution.Edges.FiatCurrency.Code,
					}).Errorf("Failed to get token rate when indexing ERC20 transfers for %s from queue", token.Edges.Network.Identifier)
					return
				}
			} else {
				rateResponse = decimal.NewFromInt(1)
			}

			tx, err := storage.Client.Tx(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":         fmt.Sprintf("%v", err),
					"LinkedAddress": linkedAddress.Address,
				}).Errorf("Failed to create transaction when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
				return
			}

			order, err := storage.Client.PaymentOrder.
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
				Save(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":         fmt.Sprintf("%v", err),
					"LinkedAddress": linkedAddress.Address,
				}).Errorf("Failed to create payment order when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
				_ = tx.Rollback()
				return
			}

			_, err = tx.PaymentOrderRecipient.
				Create().
				SetInstitution(linkedAddress.Institution).
				SetAccountIdentifier(linkedAddress.AccountIdentifier).
				SetAccountName(linkedAddress.AccountName).
				SetMetadata(linkedAddress.Metadata).
				SetPaymentOrder(order).
				Save(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":         fmt.Sprintf("%v", err),
					"LinkedAddress": linkedAddress.Address,
				}).Errorf("Failed to create payment order recipient when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
				_ = tx.Rollback()
				return
			}

			_, err = tx.LinkedAddress.
				UpdateOneID(linkedAddress.ID).
				SetTxHash(transferEvent.TxHash).
				SetLastIndexedBlock(int64(transferEvent.BlockNumber)).
				Save(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":         fmt.Sprintf("%v", err),
					"LinkedAddress": linkedAddress.Address,
				}).Errorf("Failed to update linked address when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
				_ = tx.Rollback()
				return
			}

			if err := tx.Commit(); err != nil {
				logger.WithFields(logger.Fields{
					"Error":         fmt.Sprintf("%v", err),
					"LinkedAddress": linkedAddress.Address,
				}).Errorf("Failed to commit transaction when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
				return
			}

			err = s.order.CreateOrder(ctx, order.ID)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   fmt.Sprintf("%v", err),
					"OrderID": order.ID.String(),
				}).Errorf("Failed to create order when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
				return
			}
		}(linkedAddress)
	}
	wg.Wait()

	return nil
}
