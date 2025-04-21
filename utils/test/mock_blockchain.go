package test

import (
	"context"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	rpctypes "github.com/paycrest/aggregator/types"
)

// MockRPCClient is a mock implementation of the RPCClient interface for testing
type MockRPCClient struct {
	nonceMutex sync.Mutex
	nonce      uint64
}

// NewMockRPCClient creates a new mock RPC client
func NewMockRPCClient() rpctypes.RPCClient {
	return &MockRPCClient{
		nonce: 0,
	}
}

// PendingNonceAt returns a consistent nonce for testing
func (m *MockRPCClient) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	m.nonceMutex.Lock()
	defer m.nonceMutex.Unlock()
	return m.nonce, nil
}

// SuggestGasPrice returns a fixed gas price for testing
func (m *MockRPCClient) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	return big.NewInt(1000000000), nil // 1 Gwei
}

// SuggestGasTipCap returns a fixed gas tip cap for testing
func (m *MockRPCClient) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	return big.NewInt(1000000000), nil // 1 Gwei
}

// EstimateGas returns a fixed gas limit for testing
func (m *MockRPCClient) EstimateGas(ctx context.Context, call ethereum.CallMsg) (uint64, error) {
	return 21000, nil
}

// FilterLogs returns empty logs for testing
func (m *MockRPCClient) FilterLogs(ctx context.Context, query ethereum.FilterQuery) ([]types.Log, error) {
	return []types.Log{}, nil
}

// SubscribeFilterLogs returns a dummy subscription for testing
func (m *MockRPCClient) SubscribeFilterLogs(ctx context.Context, query ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error) {
	return nil, nil
}

// CodeAt returns empty code for testing
func (m *MockRPCClient) CodeAt(ctx context.Context, contract common.Address, blockNumber *big.Int) ([]byte, error) {
	return []byte{}, nil
}

// HeaderByNumber returns a dummy header for testing
func (m *MockRPCClient) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	return &types.Header{}, nil
}

// Commit is a no-op for testing
func (m *MockRPCClient) Commit() common.Hash {
	// No-op
	return common.Hash{}
}
