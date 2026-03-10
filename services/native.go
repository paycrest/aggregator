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
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
)

// --- Public API ---

// NativeService provides EIP-7702 (native wallet) tx submission.
// SendTransaction is the single entry point: callers build (to, data, authList) and call it for create/settle/refund/refund-expired.
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

// SendTransaction sends a single transaction from the aggregator to the given address.
// For settle/refund, to is the gateway and authList is nil. For create-order (EIP-7702 batch),
// the caller builds (userAddr, batchData, authList) and passes them here.
func (s *NativeService) SendTransaction(ctx context.Context, orderIDPrefix string, network *ent.Network, to common.Address, data []byte, authList []types.SetCodeAuthorization) (map[string]interface{}, error) {
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
		receipt, txErr = SendKeeperTx(ctx, client, aggregatorKey, nonce, to, data, authList, chainID)
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

// --- Errors and constants ---

// ErrTxBroadcastNoReceipt is returned when SendTransaction succeeded but the receipt
// was not obtained (timeout or context cancel). The nonce was consumed on-chain;
// nonce manager must not release it (use resetNonce so next acquire refetches).
var ErrTxBroadcastNoReceipt = errors.New("transaction broadcast but receipt not available")

const (
	batchExecuteABI = `[{"inputs":[{"components":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"bytes","name":"data","type":"bytes"}],"internalType":"struct ProviderBatchCallAndSponsor.Call[]","name":"calls","type":"tuple[]"},{"internalType":"bytes","name":"signature","type":"bytes"}],"name":"execute","outputs":[],"stateMutability":"payable","type":"function"}]`
	batchNonceABI   = `[{"inputs":[],"name":"nonce","outputs":[{"type":"uint256"}],"stateMutability":"view","type":"function"}]`
)

// --- EIP-7702 batch primitives ---

// Call7702 is a single call in an EIP-7702 batch execute.
type Call7702 struct {
	To    common.Address `abi:"to"`
	Value *big.Int       `abi:"value"`
	Data  []byte         `abi:"data"`
}

// CheckDelegation returns true if the EOA has delegated to the given delegation contract (EIP-7702).
func CheckDelegation(ctx context.Context, client *ethclient.Client, eoa, delegationContract common.Address) (bool, error) {
	code, err := client.CodeAt(ctx, eoa, nil)
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
func ReadBatchNonce(ctx context.Context, client *ethclient.Client, userAddr common.Address) (uint64, error) {
	parsed, err := abi.JSON(strings.NewReader(batchNonceABI))
	if err != nil {
		return 0, fmt.Errorf("failed to parse batch nonce ABI: %w", err)
	}
	data, err := parsed.Pack("nonce")
	if err != nil {
		return 0, fmt.Errorf("failed to pack nonce call: %w", err)
	}
	result, err := client.CallContract(ctx, ethereum.CallMsg{To: &userAddr, Data: data}, nil)
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

// BuildEIP7702Batch builds the EIP-7702 batch (delegation check, optional auth, sign batch, pack execute).
// Callers provide the pre-built calls slice; this function handles decrypt salt, key, dial, CheckDelegation,
// optional SignAuthorization7702, ReadBatchNonce, SignBatch7702, and PackExecute. label is used in error messages (e.g. "CreateOrder", "RefundExpired").
func BuildEIP7702Batch(ctx context.Context, orderIDPrefix, label string, order *ent.PaymentOrder, network *ent.Network, calls []Call7702) (common.Address, []byte, []types.SetCodeAuthorization, error) {
	if len(order.ReceiveAddressSalt) == 0 {
		return common.Address{}, nil, nil, fmt.Errorf("%s - %s: receive address salt is empty", orderIDPrefix, label)
	}
	saltDecrypted, err := cryptoUtils.DecryptPlain(order.ReceiveAddressSalt)
	if err != nil {
		return common.Address{}, nil, nil, fmt.Errorf("%s - %s.decryptSalt: %w", orderIDPrefix, label, err)
	}
	userKey, err := crypto.HexToECDSA(string(saltDecrypted))
	if err != nil {
		return common.Address{}, nil, nil, fmt.Errorf("%s - %s.parseKey: %w", orderIDPrefix, label, err)
	}
	userAddr := crypto.PubkeyToAddress(userKey.PublicKey)

	client, err := ethclient.Dial(network.RPCEndpoint)
	if err != nil {
		return common.Address{}, nil, nil, fmt.Errorf("%s - %s.dialRPC: %w", orderIDPrefix, label, err)
	}
	defer client.Close()

	chainID := big.NewInt(network.ChainID)
	delegationContract := common.HexToAddress(network.DelegationContractAddress)
	alreadyDelegated, err := CheckDelegation(ctx, client, userAddr, delegationContract)
	if err != nil {
		return common.Address{}, nil, nil, fmt.Errorf("%s - %s.checkDelegation: %w", orderIDPrefix, label, err)
	}

	var authList []types.SetCodeAuthorization
	if !alreadyDelegated {
		authNonce, err := client.PendingNonceAt(ctx, userAddr)
		if err != nil {
			return common.Address{}, nil, nil, fmt.Errorf("%s - %s.pendingNonce: %w", orderIDPrefix, label, err)
		}
		auth, err := SignAuthorization7702(userKey, chainID, delegationContract, authNonce)
		if err != nil {
			return common.Address{}, nil, nil, fmt.Errorf("%s - %s.signAuth: %w", orderIDPrefix, label, err)
		}
		authList = []types.SetCodeAuthorization{auth}
	}

	var batchNonce uint64
	if alreadyDelegated {
		batchNonce, err = ReadBatchNonce(ctx, client, userAddr)
		if err != nil {
			return common.Address{}, nil, nil, fmt.Errorf("%s - %s.readBatchNonce: %w", orderIDPrefix, label, err)
		}
	}
	batchSig, err := SignBatch7702(userKey, batchNonce, calls)
	if err != nil {
		return common.Address{}, nil, nil, fmt.Errorf("%s - %s.signBatch: %w", orderIDPrefix, label, err)
	}
	batchData, err := PackExecute(calls, batchSig)
	if err != nil {
		return common.Address{}, nil, nil, fmt.Errorf("%s - %s.packExecute: %w", orderIDPrefix, label, err)
	}
	return userAddr, batchData, authList, nil
}

// --- Keeper transaction ---

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

// --- Nonce management ---

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
	key := nonceKey{chainID, addr}

	nm.mu.Lock()
	if existing, ok := nm.nonces[key]; ok {
		nonce := existing
		nm.nonces[key]++
		nm.mu.Unlock()
		return nonce, nil
	}
	nm.mu.Unlock()

	pendingNonce, err := client.PendingNonceAt(ctx, addr)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch pending nonce: %w", err)
	}

	nm.mu.Lock()
	defer nm.mu.Unlock()
	if existing, ok := nm.nonces[key]; ok {
		// Another goroutine set it while we were fetching; use existing.
		nm.nonces[key] = existing + 1
		return existing, nil
	}
	nm.nonces[key] = pendingNonce + 1
	return pendingNonce, nil
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

// defaultNonceManager is the shared nonce manager used by all NativeService instances
// so that OrderEVM (order create/settle/refund) and ProcessExpiredOrdersRefunds (cron)
// use the same nonce state per (chainID, address) and avoid duplicate nonces under concurrency.
var (
	defaultNonceManager     *NonceManager
	defaultNonceManagerOnce sync.Once
)

func getDefaultNonceManager() *NonceManager {
	defaultNonceManagerOnce.Do(func() {
		defaultNonceManager = NewNonceManager()
	})
	return defaultNonceManager
}
