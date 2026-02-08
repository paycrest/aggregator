package common

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerbalances"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	tokenent "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/transactionlog"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/storage"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

// ProcessTransfers processes transfers to receive addresses and updates their status
func ProcessTransfers(
	ctx context.Context,
	orderService types.OrderService,
	priorityQueueService *services.PriorityQueueService,
	unknownAddresses []string,
	addressToEvent map[string]*types.TokenTransferEvent,
) error {
	orders, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.ReceiveAddressIn(unknownAddresses...),
			paymentorder.StatusEQ(paymentorder.StatusInitiated),
			paymentorder.ReceiveAddressExpiryGT(time.Now()),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		All(ctx)
	if err != nil {
		return fmt.Errorf("ProcessTransfers.fetchOrders: %w", err)
	}

	var wg sync.WaitGroup
	for _, order := range orders {
		receiveAddress := order.ReceiveAddress
		wg.Add(1)
		go func(order *ent.PaymentOrder, receiveAddress string) {
			defer wg.Done()
			transferEvent, ok := addressToEvent[receiveAddress]
			if !ok {
				return
			}

			_, err := UpdateReceiveAddressStatus(ctx, order, transferEvent, orderService.CreateOrder, func(ctx context.Context, providerProfile *ent.ProviderProfile, tokenSymbol string, currency string) (decimal.Decimal, error) {
				// Offramp context: use sell side rates
				return priorityQueueService.GetProviderRate(ctx, providerProfile, tokenSymbol, currency, services.RateSideSell)
			})
			if err != nil {
				if !strings.Contains(fmt.Sprintf("%v", err), "Duplicate payment order") && !strings.Contains(fmt.Sprintf("%v", err), "Receive address not found") {
					logger.WithFields(logger.Fields{
						"Error":   fmt.Sprintf("%v", err),
						"OrderID": order.ID.String(),
					}).Errorf("Failed to update receive address status when indexing ERC20 transfers for %s", order.Edges.Token.Edges.Network.Identifier)
				}
				return
			}
		}(order, receiveAddress)
	}
	wg.Wait()
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

			err := ProcessPaymentOrderFromBlockchain(ctx, network, createdEvent, orderService.RefundOrder, priorityQueueService.AssignPaymentOrder)
			if err != nil {
				if !strings.Contains(fmt.Sprintf("%v", err), "duplicate key value violates unique constraint") {
					logger.WithFields(logger.Fields{
						"Error":   fmt.Sprintf("%v", err),
						"OrderID": createdEvent.OrderId,
						"TxHash":  createdEvent.TxHash,
						"Network": network.Identifier,
					}).Errorf("Failed to create payment order when indexing order created events for %s", network.Identifier)
				}
				return
			}
		}(createdEvent)
	}
	wg.Wait()

	return nil
}

// ProcessSettleOutOrders processes offramp (SettleOut) events and updates orders to settled.
func ProcessSettleOutOrders(ctx context.Context, network *ent.Network, orderIds []string, orderIdToEvent map[string]*types.SettleOutEvent) error {
	lockOrders, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.GatewayIDIn(orderIds...),
			paymentorder.StatusEQ(paymentorder.StatusSettling),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		All(ctx)
	if err != nil {
		return fmt.Errorf("ProcessSettleOutOrders.fetchLockOrders: %w", err)
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
		go func(lo *ent.PaymentOrder, se *types.SettleOutEvent) {
			defer wg.Done()

			// Update order status
			err := UpdateOrderStatusSettleOut(ctx, network, se, lockOrder.MessageHash)
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

// ProcessOrderSettledOrders processes OrderSettled events (Starknet) and updates orders to settled.
// Starknet contract still uses OrderSettled; events are converted to SettleOutEvent shape and use UpdateOrderStatusSettleOut.
func ProcessOrderSettledOrders(ctx context.Context, network *ent.Network, orderIds []string, orderIdToEvent map[string]*types.OrderSettledEvent) error {
	lockOrders, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.GatewayIDIn(orderIds...),
			paymentorder.StatusEQ(paymentorder.StatusSettling),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		All(ctx)
	if err != nil {
		return fmt.Errorf("ProcessOrderSettledOrders.fetchLockOrders: %w", err)
	}

	var wg sync.WaitGroup
	for _, lockOrder := range lockOrders {
		ev, ok := orderIdToEvent[lockOrder.GatewayID]
		if !ok {
			continue
		}
		settledEvent := &types.SettleOutEvent{
			BlockNumber:       ev.BlockNumber,
			TxHash:            ev.TxHash,
			SplitOrderId:      ev.SplitOrderId,
			OrderId:           ev.OrderId,
			LiquidityProvider: ev.LiquidityProvider,
			SettlePercent:     ev.SettlePercent,
			RebatePercent:     ev.RebatePercent,
		}
		wg.Add(1)
		go func(lo *ent.PaymentOrder, se *types.SettleOutEvent) {
			defer wg.Done()
			err := UpdateOrderStatusSettleOut(ctx, network, se, lo.MessageHash)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   fmt.Sprintf("%v", err),
					"OrderID": se.OrderId,
					"TxHash":  se.TxHash,
					"Network": network.Identifier,
				}).Errorf("Failed to update order status when indexing OrderSettled events for %s", network.Identifier)
			}
		}(lockOrder, settledEvent)
	}
	wg.Wait()
	return nil
}

// ProcessSettleInOrders processes SettleIn (onramp) events and updates payin orders to settled.
func ProcessSettleInOrders(ctx context.Context, network *ent.Network, orderIds []string, orderIdToEvent map[string]*types.SettleInEvent) error {
	if len(orderIds) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	for _, orderId := range orderIds {
		event, ok := orderIdToEvent[orderId]
		if !ok {
			continue
		}
		wg.Add(1)
		go func(ev *types.SettleInEvent) {
			defer wg.Done()
			err := UpdateOrderStatusSettleIn(ctx, network, ev)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   fmt.Sprintf("%v", err),
					"OrderID": ev.OrderId,
					"TxHash":  ev.TxHash,
					"Network": network.Identifier,
				}).Errorf("Failed to update payin order when indexing SettleIn events for %s", network.Identifier)
			}
		}(event)
	}
	wg.Wait()
	return nil
}

// ProcessRefundedOrders processes refunded orders for a network
func ProcessRefundedOrders(ctx context.Context, network *ent.Network, orderIds []string, orderIdToEvent map[string]*types.OrderRefundedEvent) error {
	lockOrders, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.GatewayIDIn(orderIds...),
			paymentorder.Or(
				paymentorder.StatusEQ(paymentorder.StatusRefunding),
				paymentorder.StatusEQ(paymentorder.StatusPending),
				paymentorder.StatusEQ(paymentorder.StatusCancelled),
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
		go func(lockOrder *ent.PaymentOrder) {
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
	paymentOrder *ent.PaymentOrder,
	event *types.TokenTransferEvent,
	createOrder func(ctx context.Context, orderID uuid.UUID) error,
	getProviderRate func(ctx context.Context, providerProfile *ent.ProviderProfile, tokenSymbol string, currency string) (decimal.Decimal, error),
) (done bool, err error) {
	if event.To == paymentOrder.ReceiveAddress {
		// Check for existing payment order with txHash
		count, err := db.Client.PaymentOrder.
			Query().
			Where(paymentorder.TxHashEQ(event.TxHash)).
			Count(ctx)
		if err != nil {
			return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
		}

		if count > 0 {
			// This transfer has already been indexed
			return false, nil
		}

		// This is a transfer to the receive address to create an order on-chain
		// Compare the transferred value with the expected order amount + fees
		fees := paymentOrder.NetworkFee.Add(paymentOrder.SenderFee)
		orderAmountWithFees := paymentOrder.Amount.Add(fees).Round(int32(paymentOrder.Edges.Token.Decimals))
		transferMatchesOrderAmount := event.Value.Equal(orderAmountWithFees)

		tx, err := db.Client.Tx(ctx)
		if err != nil {
			return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
		}

		paymentOrderUpdate := tx.PaymentOrder.Update().Where(paymentorder.IDEQ(paymentOrder.ID))
		if paymentOrder.RefundOrRecipientAddress == "" {
			paymentOrderUpdate = paymentOrderUpdate.SetRefundOrRecipientAddress(event.From)
		}

		if !transferMatchesOrderAmount {
			// Update the order amount will be updated to whatever amount was sent to the receive address
			newOrderAmount := event.Value.Sub(fees.Round(int32(paymentOrder.Edges.Token.Decimals)))
			paymentOrderUpdate = paymentOrderUpdate.SetAmount(newOrderAmount.Round(int32(paymentOrder.Edges.Token.Decimals)))
			// Update the rate with the current rate if order is older than 30 mins for a P2P order from the sender dashboard
			if paymentOrder.Memo != "" && strings.HasPrefix(paymentOrder.Memo, "P#P") && paymentOrder.Edges.Provider != nil && paymentOrder.CreatedAt.Before(time.Now().Add(-30*time.Minute)) {
				providerProfile := paymentOrder.Edges.Provider
				if providerProfile == nil {
					return true, fmt.Errorf("UpdateReceiveAddressStatus.db: provider not found")
				}

				institution, err := utils.GetInstitutionByCode(ctx, paymentOrder.Institution, true)
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

		if paymentOrder.AmountPaid.GreaterThanOrEqual(decimal.Zero) && paymentOrder.AmountPaid.LessThan(orderAmountWithFees) {
			transactionLog, err := tx.TransactionLog.
				Create().
				SetStatus(transactionlog.StatusCryptoDeposited).
				SetGatewayID(paymentOrder.GatewayID).
				SetTxHash(event.TxHash).
				SetNetwork(paymentOrder.Edges.Token.Edges.Network.Identifier).
				Save(ctx)
			if err != nil {
				return true, fmt.Errorf("UpdateReceiveAddressStatus.transactionlog: %v", err)
			}

			_, err = paymentOrderUpdate.
				SetFromAddress(event.From).
				SetTxHash(event.TxHash).
				SetBlockNumber(int64(event.BlockNumber)).
				SetStatus(paymentorder.StatusDeposited).
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

		if transferMatchesOrderAmount {
			// Transfer value equals order amount with fees - update payment order status to pending
			_, err = tx.PaymentOrder.
				Update().
				Where(paymentorder.IDEQ(paymentOrder.ID)).
				SetStatus(paymentorder.StatusPending).
				Save(ctx)
			if err != nil {
				_ = tx.Rollback()
				return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
			}

			if err := tx.Commit(); err != nil {
				return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
			}

			// Webhook for pending status is sent from ProcessPaymentOrderFromBlockchain
			// when the OrderCreatedEvent is indexed from blockchain (authoritative source)

			err = deleteTransferWebhook(ctx, event.TxHash)
			if err != nil {
				logger.Errorf("Failed to delete transfer webhook for transaction %s: %v", event.TxHash, err)
			}

			err = createOrder(ctx, paymentOrder.ID)
			if err != nil {
				return true, fmt.Errorf("UpdateReceiveAddressStatus.CreateOrder: %v", err)
			}

			return true, nil
		}

		err = HandleReceiveAddressValidity(ctx, paymentOrder)
		if err != nil {
			return true, fmt.Errorf("UpdateReceiveAddressStatus.HandleReceiveAddressValidity: %v", err)
		}
	}

	return false, nil
}

// GetProviderSettlementAddresses returns provider settlement addresses for a given token and currency.
func GetProviderSettlementAddresses(ctx context.Context, token *ent.Token, currencyCode string) ([]string, error) {
	providerOrderTokens, err := storage.Client.ProviderOrderToken.
		Query().
		Where(
			providerordertoken.HasTokenWith(tokenent.IDEQ(token.ID)),
			providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
			providerordertoken.SettlementAddressNEQ(""),
			providerordertoken.HasProviderWith(
				providerprofile.HasProviderBalancesWith(
					providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
					providerbalances.IsAvailableEQ(true),
				),
				providerprofile.IsActiveEQ(true),
			),
		).
		WithProvider().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider order tokens: %w", err)
	}

	var addresses []string
	for _, pot := range providerOrderTokens {
		if pot.SettlementAddress != "" {
			addresses = append(addresses, pot.SettlementAddress)
		}
	}

	return addresses, nil
}

// GetProviderAddressFromOrder gets the provider address for a payment order
func GetProviderAddressFromOrder(ctx context.Context, order *ent.PaymentOrder) (string, error) {
	if order.Edges.Provider == nil {
		return "", fmt.Errorf("payment order has no provider")
	}

	// Get the currency from the provision bucket
	if order.Edges.ProvisionBucket == nil {
		return "", fmt.Errorf("payment order has no provision bucket")
	}

	currencyCode := order.Edges.ProvisionBucket.Edges.Currency.Code

	// Get provider order token for this provider, token, and currency
	providerOrderToken, err := storage.Client.ProviderOrderToken.
		Query().
		Where(
			providerordertoken.HasProviderWith(providerprofile.IDEQ(order.Edges.Provider.ID)),
			providerordertoken.HasTokenWith(tokenent.IDEQ(order.Edges.Token.ID)),
			providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
			providerordertoken.SettlementAddressNEQ(""),
		).
		Only(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get provider order token: %w", err)
	}

	return providerOrderToken.SettlementAddress, nil
}
