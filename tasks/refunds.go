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
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/services/common"
	"github.com/paycrest/aggregator/services/contracts"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils"
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
			paymentorder.CreatedAtGTE(time.Now().Add(-(RefundsInterval * time.Minute))),
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

	cryptoConf := config.CryptoConfig()
	aggregatorKey, err := crypto.HexToECDSA(cryptoConf.AggregatorEVMPrivateKey)
	if err != nil {
		return fmt.Errorf("ProcessExpiredOrdersRefunds.parseAggregatorKey: %w", err)
	}
	aggregatorAddr := crypto.PubkeyToAddress(aggregatorKey.PublicKey)

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
			if len(order.ReceiveAddressSalt) == 0 {
				return
			}

			network := order.Edges.Token.Edges.Network
			if strings.HasPrefix(network.Identifier, "tron") || strings.HasPrefix(network.Identifier, "starknet") {
				return
			}

			tokenContract := order.Edges.Token.ContractAddress

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

			saltDecrypted, err := cryptoUtils.DecryptPlain(order.ReceiveAddressSalt)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   err.Error(),
					"OrderID": order.ID.String(),
				}).Errorf("Failed to decrypt receive address salt")
				return
			}
			userKey, err := crypto.HexToECDSA(string(saltDecrypted))
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   err.Error(),
					"OrderID": order.ID.String(),
				}).Errorf("Failed to parse receive address key")
				return
			}
			userAddr := crypto.PubkeyToAddress(userKey.PublicKey)

			client, err := ethclient.Dial(network.RPCEndpoint)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   err.Error(),
					"OrderID": order.ID.String(),
				}).Errorf("Failed to dial RPC")
				return
			}
			defer client.Close()

			chainID := big.NewInt(network.ChainID)
			delegationContract := ethcommon.HexToAddress(network.DelegationContractAddress)

			alreadyDelegated, err := utils.CheckDelegation(client, userAddr, delegationContract)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   err.Error(),
					"OrderID": order.ID.String(),
				}).Errorf("Failed to check delegation")
				return
			}

			var authList []ethTypes.SetCodeAuthorization
			if !alreadyDelegated {
				userNonce, err := client.PendingNonceAt(ctx, userAddr)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":   err.Error(),
						"OrderID": order.ID.String(),
					}).Errorf("Failed to get user nonce")
					return
				}
				auth, err := utils.SignAuthorization7702(userKey, chainID, delegationContract, userNonce)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":   err.Error(),
						"OrderID": order.ID.String(),
					}).Errorf("Failed to sign authorization")
					return
				}
				authList = []ethTypes.SetCodeAuthorization{auth}
			}

			erc20ABI, err := abi.JSON(strings.NewReader(contracts.ERC20TokenMetaData.ABI))
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   err.Error(),
					"OrderID": order.ID.String(),
				}).Errorf("Failed to parse ERC20 ABI")
				return
			}
			transferData, err := erc20ABI.Pack("transfer", ethcommon.HexToAddress(order.ReturnAddress), balance)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   err.Error(),
					"OrderID": order.ID.String(),
				}).Errorf("Failed to pack transfer calldata")
				return
			}

			calls := []utils.Call7702{
				{To: ethcommon.HexToAddress(tokenContract), Value: big.NewInt(0), Data: transferData},
			}

			var batchNonce uint64
			if alreadyDelegated {
				batchNonce, err = utils.ReadBatchNonce(client, userAddr)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":   err.Error(),
						"OrderID": order.ID.String(),
					}).Errorf("Failed to read batch nonce")
					return
				}
			}

			batchSig, err := utils.SignBatch7702(userKey, userAddr, batchNonce, calls)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   err.Error(),
					"OrderID": order.ID.String(),
				}).Errorf("Failed to sign batch")
				return
			}

			batchData, err := utils.PackExecute(calls, batchSig)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":   err.Error(),
					"OrderID": order.ID.String(),
				}).Errorf("Failed to pack execute calldata")
				return
			}

			err = utils.DefaultNonceManager.SubmitWithNonce(ctx, client, network.ChainID, aggregatorAddr, func(nonce uint64) error {
				receipt, txErr := utils.SendKeeperTx(ctx, client, aggregatorKey, nonce, userAddr, batchData, authList, chainID)
				if txErr != nil {
					return txErr
				}
				if receipt.Status == 0 {
					return fmt.Errorf("refund tx reverted in block %s", receipt.BlockNumber.String())
				}
				return nil
			})
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":          err.Error(),
					"OrderID":        order.ID.String(),
					"ReceiveAddress": order.ReceiveAddress,
					"ReturnAddress":  order.ReturnAddress,
					"Balance":        balance.String(),
				}).Errorf("Failed to send refund transfer transaction")
				return
			}

		}(order)
	}

	wg.Wait()
	return nil
}
