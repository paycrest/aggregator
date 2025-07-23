package common

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/linkedaddress"
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/receiveaddress"
	"github.com/paycrest/aggregator/ent/senderprofile"
	"github.com/paycrest/aggregator/ent/transactionlog"
	"github.com/paycrest/aggregator/ent/user"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/storage"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

// ProcessReceiveAddresses processes transfers to receive addresses and updates their status
func ProcessReceiveAddresses(
	ctx context.Context,
	orderService types.OrderService,
	priorityQueueService *services.PriorityQueueService,
	unknownAddresses []string,
	addressToEvent map[string]*types.TokenTransferEvent,
) error {
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

			_, err := UpdateReceiveAddressStatus(ctx, order.Edges.ReceiveAddress, order, transferEvent, orderService.CreateOrder, priorityQueueService.GetProviderRate)
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

// ProcessLinkedAddresses processes transfers to linked addresses and creates payment orders
func ProcessLinkedAddresses(ctx context.Context, orderService types.OrderService, unknownAddresses []string, addressToEvent map[string]*types.TokenTransferEvent, token *ent.Token) error {
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

			err = orderService.CreateOrder(ctx, order.ID)
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

// ProcessTransfers processes transfers for a network
func ProcessTransfers(
	ctx context.Context,
	orderService types.OrderService,
	priorityQueueService *services.PriorityQueueService,
	unknownAddresses []string,
	addressToEvent map[string]*types.TokenTransferEvent,
	token *ent.Token,
) error {
	// Process receive addresses and update their status
	if err := ProcessReceiveAddresses(ctx, orderService, priorityQueueService, unknownAddresses, addressToEvent); err != nil {
		return err
	}

	// Process linked addresses and create payment orders
	if err := ProcessLinkedAddresses(ctx, orderService, unknownAddresses, addressToEvent, token); err != nil {
		return err
	}

	return nil
}

// ProcessCreatedOrders processes created orders for a network
func ProcessCreatedOrders(
	ctx context.Context,
	network *ent.Network,
	orderIds []string,
	orderIdToEvent map[string]*types.OrderCreatedEvent,
	orderService types.OrderService,
	priorityQueueService *services.PriorityQueueService,
) error {
	var wg sync.WaitGroup

	for _, orderId := range orderIds {
		createdEvent, ok := orderIdToEvent[orderId]
		if !ok {
			continue
		}

		wg.Add(1)
		go func(createdEvent *types.OrderCreatedEvent) {
			defer wg.Done()

			err := CreateLockPaymentOrder(ctx, network, createdEvent, orderService.RefundOrder, priorityQueueService.AssignLockPaymentOrder)
			if err != nil {
				if !strings.Contains(fmt.Sprintf("%v", err), "duplicate key value violates unique constraint") {
					logger.WithFields(logger.Fields{
						"Error":   fmt.Sprintf("%v", err),
						"OrderID": createdEvent.OrderId,
						"TxHash":  createdEvent.TxHash,
						"Network": network.Identifier,
					}).Errorf("Failed to create lock payment order when indexing order created events for %s", network.Identifier)
				}
				return
			}
		}(createdEvent)
	}
	wg.Wait()

	return nil
}

// ProcessSettledOrders processes settled orders for a network
func ProcessSettledOrders(ctx context.Context, network *ent.Network, orderIds []string, orderIdToEvent map[string]*types.OrderSettledEvent) error {
	lockOrders, err := storage.Client.LockPaymentOrder.
		Query().
		Where(func(s *sql.Selector) {
			po := sql.Table(paymentorder.Table)
			s.LeftJoin(po).On(s.C(lockpaymentorder.FieldMessageHash), po.C(paymentorder.FieldMessageHash)).
				Where(sql.Or(
					sql.EQ(s.C(lockpaymentorder.FieldStatus), lockpaymentorder.StatusValidated),
					sql.NEQ(po.C(paymentorder.FieldStatus), paymentorder.StatusSettled),
				))
		}).
		Where(lockpaymentorder.GatewayIDIn(orderIds...)).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		All(ctx)
	if err != nil {
		return fmt.Errorf("IndexOrderSettled.fetchLockOrders: %w", err)
	}

	lockOrderDetails := make([]map[string]interface{}, len(lockOrders))
	for i, lo := range lockOrders {
		lockOrderDetails[i] = map[string]interface{}{
			"status":      lo.Status,
			"amount":      lo.Amount,
			"messageHash": lo.MessageHash,
			"gatewayID":   lo.GatewayID,
		}
	}
	logger.WithFields(logger.Fields{
		"OrderIDs":   orderIds,
		"LockOrders": lockOrderDetails,
	}).Info("Processing settled orders")

	var wg sync.WaitGroup
	for _, lockOrder := range lockOrders {
		settledEvent, ok := orderIdToEvent[lockOrder.GatewayID]
		if !ok {
			continue
		}

		wg.Add(1)
		go func(lo *ent.LockPaymentOrder, se *types.OrderSettledEvent) {
			defer wg.Done()

			// Update order status
			err := UpdateOrderStatusSettled(ctx, network, se, lockOrder.MessageHash)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   fmt.Sprintf("%v", err),
					"OrderID": se.OrderId,
					"TxHash":  se.TxHash,
					"Network": network.Identifier,
				}).Errorf("Failed to update order status settlement when indexing order settled events for %s", network.Identifier)
			}
		}(lockOrder, settledEvent)
	}
	wg.Wait()

	return nil
}

// ProcessRefundedOrders processes refunded orders for a network
func ProcessRefundedOrders(ctx context.Context, network *ent.Network, orderIds []string, orderIdToEvent map[string]*types.OrderRefundedEvent) error {
	lockOrders, err := storage.Client.LockPaymentOrder.
		Query().
		Where(func(s *sql.Selector) {
			po := sql.Table(paymentorder.Table)
			s.LeftJoin(po).On(s.C(lockpaymentorder.FieldMessageHash), po.C(paymentorder.FieldMessageHash)).
				Where(sql.Or(
					sql.EQ(s.C(lockpaymentorder.FieldStatus), lockpaymentorder.StatusPending),
					sql.EQ(s.C(lockpaymentorder.FieldStatus), lockpaymentorder.StatusCancelled),
					sql.NEQ(po.C(paymentorder.FieldStatus), paymentorder.StatusRefunded),
				))
		}).
		Where(lockpaymentorder.GatewayIDIn(orderIds...)).
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
			refundedEvent, ok := orderIdToEvent[lockOrder.GatewayID]
			if !ok {
				return
			}

			refundedEvent.Fee = refundedEvent.Fee.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(lockOrder.Edges.Token.Decimals))))

			err := UpdateOrderStatusRefunded(ctx, lockOrder.Edges.Token.Edges.Network, refundedEvent, lockOrder.MessageHash)
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

// UpdateReceiveAddressStatus updates the status of a receive address based on a transfer event.
func UpdateReceiveAddressStatus(
	ctx context.Context,
	receiveAddress *ent.ReceiveAddress,
	paymentOrder *ent.PaymentOrder,
	event *types.TokenTransferEvent,
	createOrder func(ctx context.Context, orderID uuid.UUID) error,
	getProviderRate func(ctx context.Context, providerProfile *ent.ProviderProfile, tokenSymbol string, currency string) (decimal.Decimal, error),
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
		fees := paymentOrder.NetworkFee.Add(paymentOrder.SenderFee)
		orderAmountWithFees := paymentOrder.Amount.Add(fees).Round(int32(paymentOrder.Edges.Token.Decimals))
		transferMatchesOrderAmount := event.Value.Equal(orderAmountWithFees)

		logger.WithFields(logger.Fields{
			"paymentOrderID":             paymentOrder.ID,
			"event":                      event,
			"fees":                       fees,
			"amount":                     paymentOrder.Amount,
			"orderAmountWithFees":        orderAmountWithFees,
			"transferMatchesOrderAmount": transferMatchesOrderAmount,
			"receiveAddress":             receiveAddress.Address,
		}).Info("Processing receive address status")

		tx, err := db.Client.Tx(ctx)
		if err != nil {
			return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
		}

		paymentOrderUpdate := tx.PaymentOrder.Update().Where(paymentorder.IDEQ(paymentOrder.ID))
		if paymentOrder.ReturnAddress == "" {
			paymentOrderUpdate = paymentOrderUpdate.SetReturnAddress(event.From)
		}

		orderRecipient := paymentOrder.Edges.Recipient
		if !transferMatchesOrderAmount {
			// Update the order amount will be updated to whatever amount was sent to the receive address
			newOrderAmount := event.Value.Sub(fees.Round(int32(paymentOrder.Edges.Token.Decimals)))                           // 1.99
			paymentOrderUpdate = paymentOrderUpdate.SetAmount(newOrderAmount.Round(int32(paymentOrder.Edges.Token.Decimals))) // 1.99
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

				institution, err := utils.GetInstitutionByCode(ctx, orderRecipient.Institution, true)
				if err != nil {
					return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
				}

				rate, err := getProviderRate(ctx, providerProfile, paymentOrder.Edges.Token.Symbol, institution.Edges.FiatCurrency.Code)
				if err != nil {
					return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
				}
				paymentOrderUpdate = paymentOrderUpdate.SetRate(rate)
			}
			transferMatchesOrderAmount = true
		}
		logger.WithFields(logger.Fields{
			"paymentOrderID":             paymentOrder.ID,
			"event":                      event,
			"fees":                       fees,
			"amount":                     paymentOrder.Amount,
			"orderAmountWithFees":        orderAmountWithFees,
			"transferMatchesOrderAmount": transferMatchesOrderAmount,
			"receiveAddress":             receiveAddress.Address,
		}).Info("Processing receive address status after update")

		if paymentOrder.AmountPaid.GreaterThanOrEqual(decimal.Zero) && paymentOrder.AmountPaid.LessThan(orderAmountWithFees) {
			transactionLog, err := tx.TransactionLog.
				Create().
				SetStatus(transactionlog.StatusCryptoDeposited).
				SetGatewayID(paymentOrder.GatewayID).
				SetTxHash(event.TxHash).
				SetNetwork(paymentOrder.Edges.Token.Edges.Network.Identifier).
				SetMetadata(map[string]interface{}{
					"GatewayID":       paymentOrder.GatewayID,
					"transactionData": map[string]interface{}{
						"from":         event.From,
						"to":           receiveAddress.Address,
						"value":        event.Value.String(),
						"blockNumber":  event.BlockNumber,
					},
				}).
				Save(ctx)
			if err != nil {
				return true, fmt.Errorf("UpdateReceiveAddressStatus.transactionlog: %v", err)
			}

			_, err = paymentOrderUpdate.
				SetFromAddress(event.From).
				SetTxHash(event.TxHash).
				SetBlockNumber(int64(event.BlockNumber)).
				AddAmountPaid(event.Value).
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

		logger.WithFields(logger.Fields{
			"paymentOrderID":             paymentOrder.ID,
			"event":                      event,
			"fees":                       fees,
			"amount":                     paymentOrder.Amount,
			"orderAmountWithFees":        orderAmountWithFees,
			"transferMatchesOrderAmount": transferMatchesOrderAmount,
			"receiveAddress":             receiveAddress.Address,
		}).Info("Processing receive address status after payment order update")

		if transferMatchesOrderAmount {
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

			err = createOrder(ctx, paymentOrder.ID)
			if err != nil {
				return true, fmt.Errorf("UpdateReceiveAddressStatus.CreateOrder: %v", err)
			}

			return true, nil
		}

		err = HandleReceiveAddressValidity(ctx, receiveAddress, paymentOrder)
		if err != nil {
			return true, fmt.Errorf("UpdateReceiveAddressStatus.HandleReceiveAddressValidity: %v", err)
		}
	}

	return false, nil
}
