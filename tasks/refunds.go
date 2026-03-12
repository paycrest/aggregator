package tasks

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/paycrest/aggregator/ent"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/balance"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/services/contracts"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils"
	blockchainUtils "github.com/paycrest/aggregator/utils/blockchain"
	"github.com/paycrest/aggregator/utils/logger"
)

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

			if order.ReceiveAddress == "" || order.RefundOrRecipientAddress == "" {
				return
			}
			network := order.Edges.Token.Edges.Network
			if strings.HasPrefix(network.Identifier, "tron") || strings.HasPrefix(network.Identifier, "starknet") {
				return
			}

			tokenContract := order.Edges.Token.ContractAddress
			if !ethcommon.IsHexAddress(order.ReceiveAddress) || !ethcommon.IsHexAddress(order.RefundOrRecipientAddress) || !ethcommon.IsHexAddress(tokenContract) {
				logger.WithFields(logger.Fields{
					"OrderID":                  order.ID.String(),
					"ReceiveAddress":           order.ReceiveAddress,
					"RefundOrRecipientAddress": order.RefundOrRecipientAddress,
					"TokenContract":            tokenContract,
				}).Errorf("Invalid hex address format for refund, skipping")
				return
			}
			balance, err := blockchainUtils.GetTokenBalance(network.RPCEndpoint, tokenContract, order.ReceiveAddress)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":                    err.Error(),
					"TokenSymbol":              order.Edges.Token.Symbol,
					"ReceiveAddress":           order.ReceiveAddress,
					"RefundOrRecipientAddress": order.RefundOrRecipientAddress,
				}).Errorf("Failed to check token balance: %s", order.ID.String())
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
				calls, err := buildRefundExpiredCalls(orderIDPrefix, tokenContract, order.RefundOrRecipientAddress, balance)
				if err != nil {
					refundErr = err
				} else {
					_, refundErr = nativeService.SendEIP7702Batch(ctx, orderIDPrefix, "RefundExpired", order, network, calls)
				}
			default:
				logger.WithFields(logger.Fields{
					"OrderID":       order.ID.String(),
					"WalletService": network.WalletService,
				}).Errorf("Unsupported wallet_service for refund, skipping")
				return
			}
			if refundErr != nil {
				logger.WithFields(logger.Fields{
					"Error":                    refundErr.Error(),
					"OrderID":                  order.ID.String(),
					"ReceiveAddress":           order.ReceiveAddress,
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

// buildRefundExpiredCalls returns the EIP-7702 calls slice (single transfer) for native refund-expired.
func buildRefundExpiredCalls(orderIDPrefix, tokenContract, returnAddress string, balance *big.Int) ([]services.Call7702, error) {
	erc20ABI, err := abi.JSON(strings.NewReader(contracts.ERC20TokenMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("%s - RefundExpired.parseABI: %w", orderIDPrefix, err)
	}
	transferData, err := erc20ABI.Pack("transfer", ethcommon.HexToAddress(returnAddress), balance)
	if err != nil {
		return nil, fmt.Errorf("%s - RefundExpired.packTransfer: %w", orderIDPrefix, err)
	}
	tokenAddr := ethcommon.HexToAddress(tokenContract)
	return []services.Call7702{
		{To: tokenAddr, Value: big.NewInt(0), Data: transferData},
	}, nil
}

// refundExpiredOrderForSmartWallet sends ERC-20 transfer from smart wallet to return address via Thirdweb Engine (fire-and-forget).
func refundExpiredOrderForSmartWallet(ctx context.Context, order *ent.PaymentOrder, chainId int64, balance *big.Int, tokenContract string, engineService *services.EngineService) error {
	method := "function transfer(address recipient, uint256 amount) public returns (bool)"
	params := []interface{}{
		order.RefundOrRecipientAddress,
		balance.String(),
	}
	_, err := engineService.SendContractCall(ctx, chainId, order.ReceiveAddress, tokenContract, method, params)
	if err != nil {
		return fmt.Errorf("Failed to send refund transfer via Engine: %w", err)
	}
	return nil
}
