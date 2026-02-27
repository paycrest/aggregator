package tasks

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/services/contracts"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils"
	blockchainUtils "github.com/paycrest/aggregator/utils/blockchain"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
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

	// Aggregator key is only required for eoa_7702 refunds; smart_wallet uses EngineService.
	// Parse only when at least one expired order needs it, so Thirdweb-only envs can still run smart_wallet refunds.
	var aggregatorKeyECDSA *ecdsa.PrivateKey
	var aggregatorAddr ethcommon.Address
	hasEoa7702 := false
	for _, o := range expiredOrders {
		if o.WalletType == paymentorder.WalletTypeEoa7702 {
			hasEoa7702 = true
			break
		}
	}
	if hasEoa7702 {
		cryptoConf := config.CryptoConfig()
		key, err := crypto.HexToECDSA(cryptoConf.AggregatorEVMPrivateKey)
		if err != nil {
			return fmt.Errorf("ProcessExpiredOrdersRefunds.parseAggregatorKey: %w", err)
		}
		aggregatorKeyECDSA = key
		aggregatorAddr = crypto.PubkeyToAddress(key.PublicKey)
	}

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

			var refundErr error
			switch order.WalletType {
			case paymentorder.WalletTypeSmartWallet:
				refundErr = refundExpiredOrderForSmartWallet(ctx, order, network.ChainID, balance, tokenContract)
			case paymentorder.WalletTypeEoa7702:
				// @todo will decide how to handle the response later
				_, refundErr = refundExpiredOrderFor7702(ctx, order, network, balance, tokenContract, aggregatorKeyECDSA, aggregatorAddr)
			default:
				logger.WithFields(logger.Fields{
					"OrderID":    order.ID.String(),
					"WalletType": order.WalletType,
				}).Errorf("Unsupported wallet_type for refund, skipping")
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
func refundExpiredOrderForSmartWallet(ctx context.Context, order *ent.PaymentOrder, chainId int64, balance *big.Int, tokenContract string) error {
	// Prepare transfer method call
	method := "function transfer(address recipient, uint256 amount) public returns (bool)"
	params := []interface{}{
		order.ReturnAddress, // recipient address
		balance.String(),    // amount to transfer
	}
	engineService := services.NewEngineService()
	_, err := engineService.SendContractCall(ctx, chainId, order.ReceiveAddress, tokenContract, method, params)
	if err != nil {
		return fmt.Errorf("Failed to send refund transfer via Engine: %w", err)
	}
	return nil
}

// refundExpiredOrderFor7702 sends ERC-20 transfer from EOA (via EIP-7702 keeper) to return address. Returns result map (transactionHash, blockNumber) for future use.
func refundExpiredOrderFor7702(ctx context.Context, order *ent.PaymentOrder, network *ent.Network, balance *big.Int, tokenContract string, aggregatorKey *ecdsa.PrivateKey, aggregatorAddr ethcommon.Address) (map[string]interface{}, error) {
	if len(order.ReceiveAddressSalt) == 0 {
		logger.WithFields(logger.Fields{"OrderID": order.ID.String()}).Errorf("Refund 7702: receive address salt is empty")
		return nil, fmt.Errorf("receive address salt is empty")
	}
	if !ethcommon.IsHexAddress(order.ReturnAddress) || !ethcommon.IsHexAddress(tokenContract) || !ethcommon.IsHexAddress(network.DelegationContractAddress) {
		logger.WithFields(logger.Fields{
			"OrderID":                   order.ID.String(),
			"ReturnAddress":             order.ReturnAddress,
			"TokenContract":             tokenContract,
			"DelegationContractAddress": network.DelegationContractAddress,
		}).Errorf("Invalid hex address format for 7702 refund")
		return nil, fmt.Errorf("invalid hex address format for refund")
	}
	saltDecrypted, err := cryptoUtils.DecryptPlain(order.ReceiveAddressSalt)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": err.Error(), "OrderID": order.ID.String()}).Errorf("Failed to decrypt receive address salt")
		return nil, err
	}
	userKey, err := crypto.HexToECDSA(string(saltDecrypted))
	if err != nil {
		logger.WithFields(logger.Fields{"Error": err.Error(), "OrderID": order.ID.String()}).Errorf("Failed to parse receive address key")
		return nil, err
	}
	userAddr := crypto.PubkeyToAddress(userKey.PublicKey)
	if userAddr != ethcommon.HexToAddress(order.ReceiveAddress) {
		logger.WithFields(logger.Fields{
			"OrderID":        order.ID.String(),
			"ReceiveAddress": order.ReceiveAddress,
			"DerivedAddress": userAddr.Hex(),
		}).Errorf("Decrypted receive key does not match receive address")
		return nil, fmt.Errorf("decrypted receive key does not match receive address")
	}

	client, err := ethclient.Dial(network.RPCEndpoint)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": err.Error(), "OrderID": order.ID.String()}).Errorf("Failed to dial RPC")
		return nil, err
	}
	defer client.Close()

	chainID := big.NewInt(network.ChainID)
	delegationContract := ethcommon.HexToAddress(network.DelegationContractAddress)
	alreadyDelegated, err := utils.CheckDelegation(client, userAddr, delegationContract)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": err.Error(), "OrderID": order.ID.String()}).Errorf("Failed to check delegation")
		return nil, err
	}

	var authList []ethTypes.SetCodeAuthorization
	if !alreadyDelegated {
		userNonce, err := client.PendingNonceAt(ctx, userAddr)
		if err != nil {
			logger.WithFields(logger.Fields{"Error": err.Error(), "OrderID": order.ID.String()}).Errorf("Failed to get user nonce")
			return nil, err
		}
		auth, err := utils.SignAuthorization7702(userKey, chainID, delegationContract, userNonce)
		if err != nil {
			logger.WithFields(logger.Fields{"Error": err.Error(), "OrderID": order.ID.String()}).Errorf("Failed to sign authorization")
			return nil, err
		}
		authList = []ethTypes.SetCodeAuthorization{auth}
	}

	erc20ABI, err := abi.JSON(strings.NewReader(contracts.ERC20TokenMetaData.ABI))
	if err != nil {
		logger.WithFields(logger.Fields{"Error": err.Error(), "OrderID": order.ID.String()}).Errorf("Failed to parse ERC20 ABI")
		return nil, err
	}
	transferData, err := erc20ABI.Pack("transfer", ethcommon.HexToAddress(order.ReturnAddress), balance)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": err.Error(), "OrderID": order.ID.String()}).Errorf("Failed to pack transfer calldata")
		return nil, err
	}

	calls := []utils.Call7702{
		{To: ethcommon.HexToAddress(tokenContract), Value: big.NewInt(0), Data: transferData},
	}

	var batchNonce uint64
	if alreadyDelegated {
		batchNonce, err = utils.ReadBatchNonce(client, userAddr)
		if err != nil {
			logger.WithFields(logger.Fields{"Error": err.Error(), "OrderID": order.ID.String()}).Errorf("Failed to read batch nonce")
			return nil, err
		}
	}

	batchSig, err := utils.SignBatch7702(userKey, userAddr, batchNonce, calls)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": err.Error(), "OrderID": order.ID.String()}).Errorf("Failed to sign batch")
		return nil, err
	}

	batchData, err := utils.PackExecute(calls, batchSig)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": err.Error(), "OrderID": order.ID.String()}).Errorf("Failed to pack execute calldata")
		return nil, err
	}

	var receipt *ethTypes.Receipt
	err = utils.DefaultNonceManager.SubmitWithNonce(ctx, client, network.ChainID, aggregatorAddr, func(nonce uint64) error {
		var txErr error
		receipt, txErr = utils.SendKeeperTx(ctx, client, aggregatorKey, nonce, userAddr, batchData, authList, chainID)
		return txErr
	})
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":          err.Error(),
			"OrderID":        order.ID.String(),
			"ReceiveAddress": order.ReceiveAddress,
			"ReturnAddress":  order.ReturnAddress,
			"Balance":        balance.String(),
		}).Errorf("Failed to send refund transfer transaction")
		return nil, err
	}
	if receipt.Status == 0 {
		return nil, fmt.Errorf("Refund 7702: refund tx reverted")
	}

	return map[string]interface{}{
		"transactionHash": receipt.TxHash.Hex(),
		"blockNumber":     receipt.BlockNumber.Int64(),
	}, nil
}
