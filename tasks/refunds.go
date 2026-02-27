package tasks

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/paycrest/aggregator/ent"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/storage"
	blockchainUtils "github.com/paycrest/aggregator/utils/blockchain"
	"github.com/paycrest/aggregator/utils/logger"
)

// HandleReceiveAddressValidity handles receive address validity
func HandleReceiveAddressValidity() error {
	ctx := context.Background()

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
		return fmt.Errorf("HandleReceiveAddressValidity: %w", err)
	}

	for _, order := range orders {
		err := common.HandleReceiveAddressValidity(ctx, order)
		if err != nil {
			continue
		}
	}

	return nil
}

// RefundsInterval defines the interval for processing expired orders refunds
const RefundsInterval = 30

// ProcessExpiredOrdersRefunds processes expired orders and transfers any remaining funds to refund addresses
func ProcessExpiredOrdersRefunds() error {
	ctx := context.Background()

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
	nativeService := services.NewNativeService()

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5)

	for _, order := range expiredOrders {
		wg.Add(1)
		go func(order *ent.PaymentOrder) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if order.ReceiveAddress == "" || order.ReturnAddress == "" {
				return
			}
			network := order.Edges.Token.Edges.Network
			if strings.HasPrefix(network.Identifier, "tron") || strings.HasPrefix(network.Identifier, "starknet") {
				return
			}

			tokenContract := order.Edges.Token.ContractAddress
			if !ethcommon.IsHexAddress(order.ReceiveAddress) || !ethcommon.IsHexAddress(order.ReturnAddress) || !ethcommon.IsHexAddress(tokenContract) {
				logger.WithFields(logger.Fields{
					"OrderID":        order.ID.String(),
					"ReceiveAddress": order.ReceiveAddress,
					"ReturnAddress":  order.ReturnAddress,
					"TokenContract":  tokenContract,
				}).Errorf("Invalid hex address format for refund, skipping")
				return
			}
			balance, err := blockchainUtils.GetTokenBalance(network.RPCEndpoint, tokenContract, order.ReceiveAddress)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   err.Error(),
					"OrderID": order.ID.String(),
				}).Errorf("Failed to check token balance")
				return
			}
			if balance.Cmp(big.NewInt(0)) == 0 {
				return
			}

			orderIDPrefix := strings.Split(order.ID.String(), "-")[0]
			var refundErr error
			switch network.WalletService {
			case networkent.WalletServiceEngine:
				refundErr = refundExpiredOrderForSmartWallet(ctx, order, network.ChainID, balance, tokenContract, engineService)
			case networkent.WalletServiceNative:
				_, refundErr = nativeService.RefundExpiredOrder(ctx, map[string]interface{}{
					"orderIDPrefix":   orderIDPrefix,
					"order":           order,
					"network":         network,
					"tokenContract":   tokenContract,
					"returnAddress":  order.ReturnAddress,
					"balance":        balance,
				})
			default:
				logger.WithFields(logger.Fields{
					"OrderID":        order.ID.String(),
					"WalletService": network.WalletService,
				}).Errorf("Unsupported wallet_service for refund, skipping")
				return
			}
			if refundErr != nil {
				logger.WithFields(logger.Fields{
					"Error":             refundErr.Error(),
					"OrderID":           order.ID.String(),
					"ReceiveAddress":    order.ReceiveAddress,
					"ReturnAddress":     order.ReturnAddress,
					"Balance":           balance.String(),
					"TokenContract":     tokenContract,
					"NetworkIdentifier": network.Identifier,
				}).Errorf("Failed to send refund transfer transaction")
				return
			}

		}(order)
	}

	wg.Wait()
	return nil
}

// refundExpiredOrderForSmartWallet sends ERC-20 transfer from smart wallet to return address via Thirdweb Engine (fire-and-forget).
func refundExpiredOrderForSmartWallet(ctx context.Context, order *ent.PaymentOrder, chainId int64, balance *big.Int, tokenContract string, engineService *services.EngineService) error {
	method := "function transfer(address recipient, uint256 amount) public returns (bool)"
	params := []interface{}{
		order.ReturnAddress,
		balance.String(),
	}
	_, err := engineService.SendContractCall(ctx, chainId, order.ReceiveAddress, tokenContract, method, params)
	if err != nil {
		return fmt.Errorf("Failed to send refund transfer via Engine: %w", err)
	}
	return nil
}
