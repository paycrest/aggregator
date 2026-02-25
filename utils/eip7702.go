package utils

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

const (
	batchExecuteABI = `[{"inputs":[{"components":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"bytes","name":"data","type":"bytes"}],"internalType":"struct ProviderBatchCallAndSponsor.Call[]","name":"calls","type":"tuple[]"},{"internalType":"bytes","name":"signature","type":"bytes"}],"name":"execute","outputs":[],"stateMutability":"payable","type":"function"}]`
	batchNonceABI   = `[{"inputs":[],"name":"nonce","outputs":[{"type":"uint256"}],"stateMutability":"view","type":"function"}]`
)

type Call7702 struct {
	To    common.Address `abi:"to"`
	Value *big.Int       `abi:"value"`
	Data  []byte         `abi:"data"`
}

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

func SignBatch7702(privateKey *ecdsa.PrivateKey, signerAddr common.Address, nonce uint64, calls []Call7702) ([]byte, error) {
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

// Mostly used for onramp
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

func PackExecute(calls []Call7702, signature []byte) ([]byte, error) {
	parsed, err := abi.JSON(strings.NewReader(batchExecuteABI))
	if err != nil {
		return nil, err
	}
	return parsed.Pack("execute", calls, signature)
}

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
			return nil, fmt.Errorf("context cancelled waiting for tx %s: %w", signedTx.Hash().Hex(), ctx.Err())
		}
		receipt, err := client.TransactionReceipt(ctx, signedTx.Hash())
		if err == nil {
			return receipt, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled waiting for tx %s: %w", signedTx.Hash().Hex(), ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
	return nil, fmt.Errorf("timeout waiting for tx %s", signedTx.Hash().Hex())
}
