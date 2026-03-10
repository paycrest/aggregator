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
	coretypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/paycrest/aggregator/ent"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/services/contracts"
	"github.com/paycrest/aggregator/storage"
	blockchainUtils "github.com/paycrest/aggregator/utils/blockchain"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
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
					"TokenSymbol": order.Edges.Token.Symbol,
					"ReceiveAddress": order.ReceiveAddress,
					"ReturnAddress": order.ReturnAddress,
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
				userAddr, batchData, authList, err := buildRefundExpiredBatch7702(ctx, orderIDPrefix, order, network, tokenContract, order.ReturnAddress, balance)
				if err != nil {
					refundErr = err
				} else {
					_, refundErr = nativeService.SendTransaction(ctx, orderIDPrefix, network, userAddr, batchData, authList)
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

// buildRefundExpiredBatch7702 builds the EIP-7702 batch (single transfer call) for native refund-expired. Returns (userAddr, batchData, authList).
func buildRefundExpiredBatch7702(ctx context.Context, orderIDPrefix string, order *ent.PaymentOrder, network *ent.Network, tokenContract, returnAddress string, balance *big.Int) (ethcommon.Address, []byte, []coretypes.SetCodeAuthorization, error) {
	if len(order.ReceiveAddressSalt) == 0 {
		return ethcommon.Address{}, nil, nil, fmt.Errorf("%s - RefundExpired: receive address salt is empty", orderIDPrefix)
	}
	saltDecrypted, err := cryptoUtils.DecryptPlain(order.ReceiveAddressSalt)
	if err != nil {
		return ethcommon.Address{}, nil, nil, fmt.Errorf("%s - RefundExpired.decryptSalt: %w", orderIDPrefix, err)
	}
	userKey, err := crypto.HexToECDSA(string(saltDecrypted))
	if err != nil {
		return ethcommon.Address{}, nil, nil, fmt.Errorf("%s - RefundExpired.parseKey: %w", orderIDPrefix, err)
	}
	userAddr := crypto.PubkeyToAddress(userKey.PublicKey)

	client, err := ethclient.Dial(network.RPCEndpoint)
	if err != nil {
		return ethcommon.Address{}, nil, nil, fmt.Errorf("%s - RefundExpired.dialRPC: %w", orderIDPrefix, err)
	}
	defer client.Close()

	chainID := big.NewInt(network.ChainID)
	delegationContract := ethcommon.HexToAddress(network.DelegationContractAddress)
	alreadyDelegated, err := services.CheckDelegation(ctx, client, userAddr, delegationContract)
	if err != nil {
		return ethcommon.Address{}, nil, nil, fmt.Errorf("%s - RefundExpired.checkDelegation: %w", orderIDPrefix, err)
	}

	var authList []coretypes.SetCodeAuthorization
	if !alreadyDelegated {
		authNonce, err := client.PendingNonceAt(ctx, userAddr)
		if err != nil {
			return ethcommon.Address{}, nil, nil, fmt.Errorf("%s - RefundExpired.pendingNonce: %w", orderIDPrefix, err)
		}
		auth, err := services.SignAuthorization7702(userKey, chainID, delegationContract, authNonce)
		if err != nil {
			return ethcommon.Address{}, nil, nil, fmt.Errorf("%s - RefundExpired.signAuth: %w", orderIDPrefix, err)
		}
		authList = []coretypes.SetCodeAuthorization{auth}
	}

	erc20ABI, err := abi.JSON(strings.NewReader(contracts.ERC20TokenMetaData.ABI))
	if err != nil {
		return ethcommon.Address{}, nil, nil, fmt.Errorf("%s - RefundExpired.parseABI: %w", orderIDPrefix, err)
	}
	transferData, err := erc20ABI.Pack("transfer", ethcommon.HexToAddress(returnAddress), balance)
	if err != nil {
		return ethcommon.Address{}, nil, nil, fmt.Errorf("%s - RefundExpired.packTransfer: %w", orderIDPrefix, err)
	}

	tokenAddr := ethcommon.HexToAddress(tokenContract)
	calls := []services.Call7702{
		{To: tokenAddr, Value: big.NewInt(0), Data: transferData},
	}

	var batchNonce uint64
	if alreadyDelegated {
		batchNonce, err = services.ReadBatchNonce(ctx, client, userAddr)
		if err != nil {
			return ethcommon.Address{}, nil, nil, fmt.Errorf("%s - RefundExpired.readBatchNonce: %w", orderIDPrefix, err)
		}
	}
	batchSig, err := services.SignBatch7702(userKey, batchNonce, calls)
	if err != nil {
		return ethcommon.Address{}, nil, nil, fmt.Errorf("%s - RefundExpired.signBatch: %w", orderIDPrefix, err)
	}
	batchData, err := services.PackExecute(calls, batchSig)
	if err != nil {
		return ethcommon.Address{}, nil, nil, fmt.Errorf("%s - RefundExpired.packExecute: %w", orderIDPrefix, err)
	}
	return userAddr, batchData, authList, nil
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
