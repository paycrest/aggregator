package services

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
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
	const maxRetries = 8

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

// --- EIP-7702 batch execute and keeper tx (used by NativeService only) ---

// ErrTxBroadcastNoReceipt is returned when SendTransaction succeeded but the receipt
// was not obtained (timeout or context cancel). The nonce was consumed on-chain;
// nonce manager must not release it (use resetNonce so next acquire refetches).
var ErrTxBroadcastNoReceipt = errors.New("transaction broadcast but receipt not available")

const (
	batchExecuteABI = `[{"inputs":[{"components":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"bytes","name":"data","type":"bytes"}],"internalType":"struct ProviderBatchCallAndSponsor.Call[]","name":"calls","type":"tuple[]"},{"internalType":"bytes","name":"signature","type":"bytes"}],"name":"execute","outputs":[],"stateMutability":"payable","type":"function"}]`
	batchNonceABI   = `[{"inputs":[],"name":"nonce","outputs":[{"type":"uint256"}],"stateMutability":"view","type":"function"}]`
)

// Call7702 is a single call in an EIP-7702 batch execute.
type Call7702 struct {
	To    common.Address `abi:"to"`
	Value *big.Int       `abi:"value"`
	Data  []byte         `abi:"data"`
}

// CheckDelegation returns true if the EOA has delegated to the given delegation contract (EIP-7702).
func CheckDelegation(client *ethclient.Client, eoa, delegationContract common.Address) (bool, error) {
	code, err := client.CodeAt(context.Background(), eoa, nil)
	if err != nil {
		return false, err
	}
	if len(code) != 23 {
		return false, nil
	}
	if code[0] != 0xef || code[1] != 0x01 || code[2] != 0x00 {
		return false, nil
	}
	target := common.BytesToAddress(code[3:23])
	return target == delegationContract, nil
}

// SignAuthorization7702 signs an EIP-7702 SetCode authorization.
func SignAuthorization7702(privateKey *ecdsa.PrivateKey, chainID *big.Int, contractAddr common.Address, nonce uint64) (types.SetCodeAuthorization, error) {
	encoded, err := rlp.EncodeToBytes([]interface{}{
		chainID, contractAddr, new(big.Int).SetUint64(nonce),
	})
	if err != nil {
		return types.SetCodeAuthorization{}, fmt.Errorf("RLP encode failed: %w", err)
	}

	hash := crypto.Keccak256Hash(append([]byte{0x05}, encoded...))
	sig, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return types.SetCodeAuthorization{}, fmt.Errorf("signing failed: %w", err)
	}

	chainID256 := new(uint256.Int)
	chainID256.SetFromBig(chainID)

	return types.SetCodeAuthorization{
		ChainID: *chainID256,
		Address: contractAddr,
		Nonce:   nonce,
		V:       sig[64],
		R:       *new(uint256.Int).SetBytes(sig[:32]),
		S:       *new(uint256.Int).SetBytes(sig[32:64]),
	}, nil
}

// SignBatch7702 signs the batch digest for EIP-7702 execute(calls, signature).
// The digest is keccak256(nonce || packed_calls) only; the delegation contract must use the same
// construction when verifying. The signer is recovered on-chain from the signature, not encoded in the digest.
func SignBatch7702(privateKey *ecdsa.PrivateKey, nonce uint64, calls []Call7702) ([]byte, error) {
	var packed []byte
	for _, c := range calls {
		packed = append(packed, c.To.Bytes()...)
		valBytes := make([]byte, 32)
		c.Value.FillBytes(valBytes)
		packed = append(packed, valBytes...)
		packed = append(packed, c.Data...)
	}

	nonceBytes := make([]byte, 32)
	new(big.Int).SetUint64(nonce).FillBytes(nonceBytes)

	digest := crypto.Keccak256Hash(append(nonceBytes, packed...))
	prefix := []byte("\x19Ethereum Signed Message:\n32")
	msgHash := crypto.Keccak256Hash(append(prefix, digest.Bytes()...))

	sig, err := crypto.Sign(msgHash.Bytes(), privateKey)
	if err != nil {
		return nil, fmt.Errorf("batch signing failed: %w", err)
	}
	sig[64] += 27 // adjust v for OZ ECDSA.recover
	return sig, nil
}

// ReadBatchNonce reads the batch nonce from the account (delegated EOA).
func ReadBatchNonce(client *ethclient.Client, userAddr common.Address) (uint64, error) {
	parsed, err := abi.JSON(strings.NewReader(batchNonceABI))
	if err != nil {
		return 0, fmt.Errorf("failed to parse batch nonce ABI: %w", err)
	}
	data, err := parsed.Pack("nonce")
	if err != nil {
		return 0, fmt.Errorf("failed to pack nonce call: %w", err)
	}
	result, err := client.CallContract(context.Background(), ethereum.CallMsg{To: &userAddr, Data: data}, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to read batch nonce: %w", err)
	}
	return new(big.Int).SetBytes(result).Uint64(), nil
}

// PackExecute packs execute(calls, signature) calldata for the batch contract.
func PackExecute(calls []Call7702, signature []byte) ([]byte, error) {
	parsed, err := abi.JSON(strings.NewReader(batchExecuteABI))
	if err != nil {
		return nil, err
	}
	return parsed.Pack("execute", calls, signature)
}

// SendKeeperTx sends a keeper transaction (with optional EIP-7702 auth list), then polls for the receipt.
func SendKeeperTx(ctx context.Context, client *ethclient.Client, keeperKey *ecdsa.PrivateKey, keeperNonce uint64, to common.Address, data []byte, authList []types.SetCodeAuthorization, chainID *big.Int) (*types.Receipt, error) {
	gasTipCap, err := client.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to suggest gas tip: %w", err)
	}
	head, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get block header: %w", err)
	}
	var gasFeeCap *big.Int
	if head.BaseFee != nil {
		gasFeeCap = new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), gasTipCap)
	} else {
		gasFeeCap = new(big.Int).Set(gasTipCap)
	}
	gasLimit := uint64(500_000)

	var tx *types.Transaction
	if len(authList) > 0 {
		chainID256 := uint256.MustFromBig(chainID)
		tip256 := uint256.MustFromBig(gasTipCap)
		fee256 := uint256.MustFromBig(gasFeeCap)
		tx = types.NewTx(&types.SetCodeTx{
			ChainID:   chainID256,
			Nonce:     keeperNonce,
			GasTipCap: tip256,
			GasFeeCap: fee256,
			Gas:       gasLimit,
			To:        to,
			Value:     uint256.NewInt(0),
			Data:      data,
			AuthList:  authList,
		})
	} else {
		tx = types.NewTx(&types.DynamicFeeTx{
			ChainID:   chainID,
			Nonce:     keeperNonce,
			GasTipCap: gasTipCap,
			GasFeeCap: gasFeeCap,
			Gas:       gasLimit,
			To:        &to,
			Value:     big.NewInt(0),
			Data:      data,
		})
	}

	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), keeperKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign tx: %w", err)
	}

	if err := client.SendTransaction(ctx, signedTx); err != nil {
		return nil, fmt.Errorf("failed to send tx: %w", err)
	}

	for i := 0; i < 30; i++ {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("tx %s: %w", signedTx.Hash().Hex(), errors.Join(ErrTxBroadcastNoReceipt, ctx.Err()))
		}
		receipt, err := client.TransactionReceipt(ctx, signedTx.Hash())
		if err == nil {
			return receipt, nil
		}
		if !errors.Is(err, ethereum.NotFound) {
			return nil, fmt.Errorf("getting receipt for %s: %w", signedTx.Hash().Hex(), err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("tx %s: %w", signedTx.Hash().Hex(), errors.Join(ErrTxBroadcastNoReceipt, ctx.Err()))
		case <-time.After(2 * time.Second):
		}
	}
	return nil, fmt.Errorf("tx %s: %w", signedTx.Hash().Hex(), ErrTxBroadcastNoReceipt)
}

// defaultNonceManager is the shared nonce manager used by all NativeService instances
// so that OrderEVM (order create/settle/refund) and ProcessExpiredOrdersRefunds (cron)
// use the same nonce state per (chainID, address) and avoid duplicate nonces under concurrency.
var (
	defaultNonceManager   *NonceManager
	defaultNonceManagerOnce sync.Once
)

func getDefaultNonceManager() *NonceManager {
	defaultNonceManagerOnce.Do(func() {
		defaultNonceManager = NewNonceManager()
	})
	return defaultNonceManager
}

// NativeService provides EIP-7702 (native wallet) order operations: CreateOrder, RefundOrder, SettleOrder.
// All on-chain interaction for native (7702) flows lives here; Engine uses SendTransactionBatch, Native uses
// CreateOrder (EOA batch) and SendTransaction (single aggregator→gateway tx for refund/settle).
type NativeService struct {
	nonceManager *NonceManager
}

// NewNativeService creates a new NativeService that shares the default NonceManager with all other
// NativeService instances so aggregator keeper nonces are coordinated across OrderEVM and cron tasks.
func NewNativeService() *NativeService {
	return &NativeService{
		nonceManager: getDefaultNonceManager(),
	}
}

// NewNativeServiceWithNonceManager creates a NativeService with the given NonceManager (for tests or custom wiring).
func NewNativeServiceWithNonceManager(nm *NonceManager) *NativeService {
	return &NativeService{nonceManager: nm}
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
	batchSig, err := SignBatch7702(userKey, batchNonce, calls)
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
	batchSig, err := SignBatch7702(userKey, batchNonce, calls)
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
