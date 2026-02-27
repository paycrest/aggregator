package services

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/services/contracts"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
)

// nonceKey identifies a (chainID, address) for nonce tracking.
type nonceKey struct {
	chainID int64
	address common.Address
}

// NonceManager manages pending nonces per (chainID, address) for native keeper txs.
type NonceManager struct {
	mu     sync.Mutex
	nonces map[nonceKey]uint64
}

// NewNonceManager creates a new NonceManager (used by NativeService).
func NewNonceManager() *NonceManager {
	return &NonceManager{
		nonces: make(map[nonceKey]uint64),
	}
}

func (nm *NonceManager) acquireNonce(ctx context.Context, client *ethclient.Client, chainID int64, addr common.Address) (uint64, error) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	key := nonceKey{chainID, addr}

	if _, ok := nm.nonces[key]; !ok {
		pendingNonce, err := client.PendingNonceAt(ctx, addr)
		if err != nil {
			return 0, fmt.Errorf("failed to fetch pending nonce: %w", err)
		}
		nm.nonces[key] = pendingNonce
	}

	nonce := nm.nonces[key]
	nm.nonces[key]++
	return nonce, nil
}

func (nm *NonceManager) releaseNonce(chainID int64, addr common.Address, nonce uint64) {
	// No-op: rolling back would be unsafe under concurrency.
}

func (nm *NonceManager) resetNonce(chainID int64, addr common.Address) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	delete(nm.nonces, nonceKey{chainID, addr})
}

func (nm *NonceManager) submitWithNonce(
	ctx context.Context,
	client *ethclient.Client,
	chainID int64,
	addr common.Address,
	submitFn func(nonce uint64) error,
) error {
	const maxRetries = 3

	for attempt := 0; attempt < maxRetries; attempt++ {
		nonce, err := nm.acquireNonce(ctx, client, chainID, addr)
		if err != nil {
			return err
		}

		err = submitFn(nonce)
		if err == nil {
			return nil
		}

		if isNonceTooLow(err) {
			nm.resetNonce(chainID, addr)
			continue
		}

		if errors.Is(err, ErrTxBroadcastNoReceipt) {
			nm.resetNonce(chainID, addr)
			return err
		}

		nm.releaseNonce(chainID, addr, nonce)
		return err
	}

	return fmt.Errorf("failed after %d attempts due to nonce conflicts", maxRetries)
}

func isNonceTooLow(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "nonce too low") ||
		strings.Contains(msg, "replacement transaction underpriced") ||
		strings.Contains(msg, "already known")
}

// NativeService provides EIP-7702 (native wallet) order operations: CreateOrder, RefundOrder, SettleOrder.
// All on-chain interaction for native (7702) flows lives here; Engine uses SendTransactionBatch, Native uses
// CreateOrder (EOA batch) and SendTransaction (single aggregator→gateway tx for refund/settle).
type NativeService struct {
	nonceManager *NonceManager
}

// NewNativeService creates a new NativeService.
func NewNativeService() *NativeService {
	return &NativeService{
		nonceManager: NewNonceManager(),
	}
}

// CreateOrder runs the full EIP-7702 flow: decrypt EOA key, check delegation, sign auth if needed,
// sign batch (approve + createOrder), send keeper tx. Returns transactionHash and blockNumber on success.
// params: map with keys "orderIDPrefix" (string), "order" (*ent.PaymentOrder), "network" (*ent.Network),
// "approveData" ([]byte), "createOrderData" ([]byte), "gatewayAddr" (common.Address), "tokenAddr" (common.Address).
func (s *NativeService) CreateOrder(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	orderIDPrefix, _ := params["orderIDPrefix"].(string)
	order, _ := params["order"].(*ent.PaymentOrder)
	network, _ := params["network"].(*ent.Network)
	approveData, _ := params["approveData"].([]byte)
	createOrderData, _ := params["createOrderData"].([]byte)
	gatewayAddr, _ := params["gatewayAddr"].(common.Address)
	tokenAddr, _ := params["tokenAddr"].(common.Address)
	if order == nil || network == nil {
		return nil, fmt.Errorf("%s - CreateOrder: missing order or network in params", orderIDPrefix)
	}

	if len(order.ReceiveAddressSalt) == 0 {
		return nil, fmt.Errorf("%s - CreateOrder: receive address salt is empty", orderIDPrefix)
	}
	saltDecrypted, err := cryptoUtils.DecryptPlain(order.ReceiveAddressSalt)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.decryptSalt: %w", orderIDPrefix, err)
	}
	userKey, err := crypto.HexToECDSA(string(saltDecrypted))
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.parseKey: %w", orderIDPrefix, err)
	}
	userAddr := crypto.PubkeyToAddress(userKey.PublicKey)

	client, err := ethclient.Dial(network.RPCEndpoint)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.dialRPC: %w", orderIDPrefix, err)
	}
	defer client.Close()

	chainID := big.NewInt(network.ChainID)
	delegationContract := common.HexToAddress(network.DelegationContractAddress)
	alreadyDelegated, err := CheckDelegation(client, userAddr, delegationContract)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.checkDelegation: %w", orderIDPrefix, err)
	}

	var authList []types.SetCodeAuthorization
	if !alreadyDelegated {
		authNonce, err := client.PendingNonceAt(ctx, userAddr)
		if err != nil {
			return nil, fmt.Errorf("%s - CreateOrder.pendingNonce: %w", orderIDPrefix, err)
		}
		auth, err := SignAuthorization7702(userKey, chainID, delegationContract, authNonce)
		if err != nil {
			return nil, fmt.Errorf("%s - CreateOrder.signAuth: %w", orderIDPrefix, err)
		}
		authList = []types.SetCodeAuthorization{auth}
	}

	calls := []Call7702{
		{To: tokenAddr, Value: big.NewInt(0), Data: approveData},
		{To: gatewayAddr, Value: big.NewInt(0), Data: createOrderData},
	}

	var batchNonce uint64
	if alreadyDelegated {
		batchNonce, err = ReadBatchNonce(client, userAddr)
		if err != nil {
			return nil, fmt.Errorf("%s - CreateOrder.readBatchNonce: %w", orderIDPrefix, err)
		}
	}
	batchSig, err := SignBatch7702(userKey, userAddr, batchNonce, calls)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.signBatch: %w", orderIDPrefix, err)
	}
	batchData, err := PackExecute(calls, batchSig)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.packExecute: %w", orderIDPrefix, err)
	}

	cryptoConf := config.CryptoConfig()
	aggregatorKey, err := crypto.HexToECDSA(cryptoConf.AggregatorAccountPrivateKeyEVM)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.parseAggregatorKey: %w", orderIDPrefix, err)
	}
	aggregatorAddr := crypto.PubkeyToAddress(aggregatorKey.PublicKey)

	var receipt *types.Receipt
	err = s.nonceManager.submitWithNonce(ctx, client, network.ChainID, aggregatorAddr, func(nonce uint64) error {
		var txErr error
		receipt, txErr = SendKeeperTx(ctx, client, aggregatorKey, nonce, userAddr, batchData, authList, chainID)
		if txErr != nil {
			return fmt.Errorf("%s - CreateOrder.sendTx: %w", orderIDPrefix, txErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if receipt.Status == 0 {
		return nil, fmt.Errorf("%s - CreateOrder: tx reverted in block %s", orderIDPrefix, receipt.BlockNumber.String())
	}
	return map[string]interface{}{
		"transactionHash": receipt.TxHash.Hex(),
		"blockNumber":     receipt.BlockNumber.Int64(),
	}, nil
}

// SendTransaction sends a single transaction from the aggregator to the given address (e.g. gateway refund/settle).
// It mirrors EngineService.SendTransactionBatch for the native path: one entry point for submitting a tx.
func (s *NativeService) SendTransaction(ctx context.Context, orderIDPrefix string, network *ent.Network, to common.Address, data []byte) (map[string]interface{}, error) {
	cryptoConf := config.CryptoConfig()
	aggregatorKey, err := crypto.HexToECDSA(cryptoConf.AggregatorAccountPrivateKeyEVM)
	if err != nil {
		return nil, fmt.Errorf("%s - SendTransaction.parseAggregatorKey: %w", orderIDPrefix, err)
	}
	aggregatorAddr := crypto.PubkeyToAddress(aggregatorKey.PublicKey)
	client, err := ethclient.Dial(network.RPCEndpoint)
	if err != nil {
		return nil, fmt.Errorf("%s - SendTransaction.dialRPC: %w", orderIDPrefix, err)
	}
	defer client.Close()
	chainID := big.NewInt(network.ChainID)

	var receipt *types.Receipt
	err = s.nonceManager.submitWithNonce(ctx, client, network.ChainID, aggregatorAddr, func(nonce uint64) error {
		var txErr error
		receipt, txErr = SendKeeperTx(ctx, client, aggregatorKey, nonce, to, data, nil, chainID)
		if txErr != nil {
			return fmt.Errorf("%s - SendTransaction.sendTx: %w", orderIDPrefix, txErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if receipt.Status == 0 {
		return nil, fmt.Errorf("%s - SendTransaction: tx reverted in block %s", orderIDPrefix, receipt.BlockNumber.String())
	}
	return map[string]interface{}{
		"transactionHash": receipt.TxHash.Hex(),
		"blockNumber":     receipt.BlockNumber.Int64(),
	}, nil
}

// RefundExpiredOrder sends ERC-20 transfer from EOA (receive address) to return address via EIP-7702 keeper tx.
// params: map with keys "orderIDPrefix" (string), "order" (*ent.PaymentOrder), "network" (*ent.Network),
// "tokenContract" (string), "returnAddress" (string), "balance" (*big.Int).
func (s *NativeService) RefundExpiredOrder(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	orderIDPrefix, _ := params["orderIDPrefix"].(string)
	order, _ := params["order"].(*ent.PaymentOrder)
	network, _ := params["network"].(*ent.Network)
	tokenContract, _ := params["tokenContract"].(string)
	returnAddress, _ := params["returnAddress"].(string)
	balance, _ := params["balance"].(*big.Int)
	if order == nil || network == nil || balance == nil {
		return nil, fmt.Errorf("%s - RefundExpiredOrder: missing order, network or balance in params", orderIDPrefix)
	}
	if len(order.ReceiveAddressSalt) == 0 {
		return nil, fmt.Errorf("%s - RefundExpiredOrder: receive address salt is empty", orderIDPrefix)
	}
	saltDecrypted, err := cryptoUtils.DecryptPlain(order.ReceiveAddressSalt)
	if err != nil {
		return nil, fmt.Errorf("%s - RefundExpiredOrder.decryptSalt: %w", orderIDPrefix, err)
	}
	userKey, err := crypto.HexToECDSA(string(saltDecrypted))
	if err != nil {
		return nil, fmt.Errorf("%s - RefundExpiredOrder.parseKey: %w", orderIDPrefix, err)
	}
	userAddr := crypto.PubkeyToAddress(userKey.PublicKey)

	client, err := ethclient.Dial(network.RPCEndpoint)
	if err != nil {
		return nil, fmt.Errorf("%s - RefundExpiredOrder.dialRPC: %w", orderIDPrefix, err)
	}
	defer client.Close()

	chainID := big.NewInt(network.ChainID)
	delegationContract := common.HexToAddress(network.DelegationContractAddress)
	alreadyDelegated, err := CheckDelegation(client, userAddr, delegationContract)
	if err != nil {
		return nil, fmt.Errorf("%s - RefundExpiredOrder.checkDelegation: %w", orderIDPrefix, err)
	}

	var authList []types.SetCodeAuthorization
	if !alreadyDelegated {
		authNonce, err := client.PendingNonceAt(ctx, userAddr)
		if err != nil {
			return nil, fmt.Errorf("%s - RefundExpiredOrder.pendingNonce: %w", orderIDPrefix, err)
		}
		auth, err := SignAuthorization7702(userKey, chainID, delegationContract, authNonce)
		if err != nil {
			return nil, fmt.Errorf("%s - RefundExpiredOrder.signAuth: %w", orderIDPrefix, err)
		}
		authList = []types.SetCodeAuthorization{auth}
	}

	erc20ABI, err := abi.JSON(strings.NewReader(contracts.ERC20TokenMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("%s - RefundExpiredOrder.parseABI: %w", orderIDPrefix, err)
	}
	transferData, err := erc20ABI.Pack("transfer", common.HexToAddress(returnAddress), balance)
	if err != nil {
		return nil, fmt.Errorf("%s - RefundExpiredOrder.packTransfer: %w", orderIDPrefix, err)
	}

	tokenAddr := common.HexToAddress(tokenContract)
	calls := []Call7702{
		{To: tokenAddr, Value: big.NewInt(0), Data: transferData},
	}

	var batchNonce uint64
	if alreadyDelegated {
		batchNonce, err = ReadBatchNonce(client, userAddr)
		if err != nil {
			return nil, fmt.Errorf("%s - RefundExpiredOrder.readBatchNonce: %w", orderIDPrefix, err)
		}
	}
	batchSig, err := SignBatch7702(userKey, userAddr, batchNonce, calls)
	if err != nil {
		return nil, fmt.Errorf("%s - RefundExpiredOrder.signBatch: %w", orderIDPrefix, err)
	}
	batchData, err := PackExecute(calls, batchSig)
	if err != nil {
		return nil, fmt.Errorf("%s - RefundExpiredOrder.packExecute: %w", orderIDPrefix, err)
	}

	cryptoConf := config.CryptoConfig()
	aggregatorKey, err := crypto.HexToECDSA(cryptoConf.AggregatorAccountPrivateKeyEVM)
	if err != nil {
		return nil, fmt.Errorf("%s - RefundExpiredOrder.parseAggregatorKey: %w", orderIDPrefix, err)
	}
	aggregatorAddr := crypto.PubkeyToAddress(aggregatorKey.PublicKey)

	var receipt *types.Receipt
	err = s.nonceManager.submitWithNonce(ctx, client, network.ChainID, aggregatorAddr, func(nonce uint64) error {
		var txErr error
		receipt, txErr = SendKeeperTx(ctx, client, aggregatorKey, nonce, userAddr, batchData, authList, chainID)
		if txErr != nil {
			return fmt.Errorf("%s - RefundExpiredOrder.sendTx: %w", orderIDPrefix, txErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if receipt.Status == 0 {
		return nil, fmt.Errorf("%s - RefundExpiredOrder: tx reverted in block %s", orderIDPrefix, receipt.BlockNumber.String())
	}
	return map[string]interface{}{
		"transactionHash": receipt.TxHash.Hex(),
		"blockNumber":     receipt.BlockNumber.Int64(),
	}, nil
}
