package tasks

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/balance"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils"
	blockchainUtils "github.com/paycrest/aggregator/utils/blockchain"
	"github.com/paycrest/aggregator/utils/logger"
)

// func FixDatabaseMishap() error {
// 	ctx := context.Background()
// 	network, err := storage.Client.Network.
// 		Query().
// 		Where(networkent.ChainIDEQ(1135)).
// 		Only(ctx)
// 	if err != nil {
// 		return fmt.Errorf("FixDatabaseMishap.fetchNetworks: %w", err)
// 	}
//
// 	indexerInstance := indexer.NewIndexerEVM()
//
// 	_ = indexerInstance.IndexOrderCreated(ctx, network, 18052684, 18052684, "")
// 	_ = indexerInstance.IndexOrderCreated(ctx, network, 18056857, 18056857, "")
//
// 	return nil
// }

// ExpireStaleOrders expires orders past their validity: offramp Initiated with expired receive address, and onramp Pending past VA validity (metadata.providerAccount.validUntil). For onramp, releases reserved token balance.
func ExpireStaleOrders() error {
	ctx := context.Background()

	// Offramp: receive address validity — Initiated orders with expired receive address
	orders, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.ReceiveAddressExpiryLTE(time.Now()),
			paymentorder.StatusEQ(paymentorder.StatusInitiated),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithSenderProfile().
		All(ctx)
	if err != nil {
		return fmt.Errorf("ExpireStaleOrders.receiveAddress: %w", err)
	}
	for _, order := range orders {
		err := common.HandleReceiveAddressValidity(ctx, order)
		if err != nil {
			continue
		}
	}

	// Onramp: Pending orders past VA validity (no deposit, provider never called AcceptOrder) — use validUntil from metadata, fallback to CreatedAt + OrderFulfillmentValidity
	pendingOnramp, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.DirectionEQ(paymentorder.DirectionOnramp),
			paymentorder.StatusEQ(paymentorder.StatusPending),
		).
		WithProvider().
		WithToken().
		All(ctx)
	if err != nil {
		return fmt.Errorf("ExpireStaleOrders.pendingOnramp: %w", err)
	}
	balanceService := balance.New()
	now := time.Now()
	for _, order := range pendingOnramp {
		var validUntil time.Time
		if order.Metadata != nil {
			if pa, ok := order.Metadata["providerAccount"].(map[string]interface{}); ok {
				if t, ok := utils.ParseValidUntilFromMetadata(pa["validUntil"]); ok {
					validUntil = t
				}
			}
		}
		if validUntil.IsZero() {
			validUntil = order.CreatedAt.Add(orderConf.OrderFulfillmentValidity)
		}
		if !now.After(validUntil) {
			continue
		}
		_, err := storage.Client.PaymentOrder.UpdateOneID(order.ID).SetStatus(paymentorder.StatusExpired).Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"OrderID": order.ID.String(),
				"Error":   err,
			}).Errorf("ExpireStaleOrders: failed to set Expired for onramp Pending")
			continue
		}
		if order.Edges.Provider != nil && order.Edges.Token != nil {
			totalCryptoReserved := order.Amount.Add(order.SenderFee)
			if relErr := balanceService.ReleaseTokenBalance(ctx, order.Edges.Provider.ID, order.Edges.Token.ID, totalCryptoReserved, nil); relErr != nil {
				logger.WithFields(logger.Fields{
					"OrderID": order.ID.String(),
					"Error":   relErr,
				}).Errorf("ExpireStaleOrders: failed to release token balance for onramp Pending")
			}
		}
	}
	return nil
}

// RefundsInterval defines the interval for processing expired orders refunds
const RefundsInterval = 30

// ProcessExpiredOrdersRefunds processes expired orders and transfers any remaining funds to refund addresses
func ProcessExpiredOrdersRefunds() error {
	ctx := context.Background()

	// Get all payment orders that are expired and initiated in the last RefundsInterval
	expiredOrders, err := storage.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.StatusEQ(paymentorder.StatusExpired),
			paymentorder.CreatedAtGTE(time.Now().Add(-(RefundsInterval * time.Minute))), // Should match jobs retrying expired orders refunds
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		All(ctx)
	if err != nil {
		return fmt.Errorf("ProcessExpiredOrdersRefunds.fetchExpiredOrders: %w", err)
	}

	if len(expiredOrders) == 0 {
		return nil
	}

	engineService := services.NewEngineService()

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5)

	for _, order := range expiredOrders {
		wg.Add(1)
		go func(order *ent.PaymentOrder) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if order.ReceiveAddress == "" {
				return
			}

			receiveAddress := order.ReceiveAddress
			tokenContract := order.Edges.Token.ContractAddress
			network := order.Edges.Token.Edges.Network
			rpcEndpoint := network.RPCEndpoint
			chainID := network.ChainID

			// Skip if no return address (nowhere to refund to)
			if order.RefundOrRecipientAddress == "" {
				return
			}

			// Check balance of token at receive address
			balance, err := blockchainUtils.GetTokenBalance(rpcEndpoint, tokenContract, receiveAddress)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":             err.Error(),
					"OrderID":           order.ID.String(),
					"ReceiveAddress":    receiveAddress,
					"TokenContract":     tokenContract,
					"NetworkIdentifier": network.Identifier,
				}).Errorf("Failed to check token balance for receive address %s", receiveAddress)
				return
			}

			if balance.Cmp(big.NewInt(0)) == 0 {
				return
			}

			// Prepare transfer method call
			method := "function transfer(address recipient, uint256 amount) public returns (bool)"
			params := []interface{}{
				order.RefundOrRecipientAddress, // recipient address
				balance.String(),               // amount to transfer
			}

			// Send the transfer transaction
			_, err = engineService.SendContractCall(
				ctx,
				chainID,
				receiveAddress,
				tokenContract,
				method,
				params,
			)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":                    err.Error(),
					"OrderID":                  order.ID.String(),
					"ReceiveAddress":           receiveAddress,
					"RefundOrRecipientAddress": order.RefundOrRecipientAddress,
					"Balance":                  balance.String(),
					"TokenContract":            tokenContract,
					"NetworkIdentifier":        network.Identifier,
				}).Errorf("Failed to send refund transfer transaction")
				return
			}

		}(order)
	}

	wg.Wait()
	return nil
}
