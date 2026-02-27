package utils

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type nonceKey struct {
	chainID int64
	address common.Address
}

type NonceManager struct {
	mu     sync.Mutex
	nonces map[nonceKey]uint64
}

var DefaultNonceManager = NewNonceManager()

func NewNonceManager() *NonceManager {
	return &NonceManager{
		nonces: make(map[nonceKey]uint64),
	}
}

func (nm *NonceManager) AcquireNonce(ctx context.Context, client *ethclient.Client, chainID int64, addr common.Address) (uint64, error) {
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

// ReleaseNonce is called when transaction submission failed before broadcast.
// It does not roll back the counter: with concurrent acquirers, rolling back would
// allow re-issuing a nonce that is still in-flight elsewhere (e.g. A has 7, B releases 6,
// counter becomes 6, next acquire gets 7 again → two tx with nonce 7).
// So we no-op here; the released nonce becomes a gap. On next send we may get
// "nonce too low" and ResetNonce will re-sync from chain.
func (nm *NonceManager) ReleaseNonce(chainID int64, addr common.Address, nonce uint64) {
	// Do not roll back: nm.nonces[key] = nonce would be unsafe under concurrency.
}

// ResetNonce forces a re-fetch from RPC on next AcquireNonce.
// Call this on "nonce too low" errors.
func (nm *NonceManager) ResetNonce(chainID int64, addr common.Address) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	delete(nm.nonces, nonceKey{chainID, addr})
}

// SubmitWithNonce wraps transaction submission with automatic nonce error recovery.
// submitFn receives a nonce and returns an error if submission failed.
func (nm *NonceManager) SubmitWithNonce(
	ctx context.Context,
	client *ethclient.Client,
	chainID int64,
	addr common.Address,
	submitFn func(nonce uint64) error,
) error {
	const maxRetries = 3

	for attempt := 0; attempt < maxRetries; attempt++ {
		nonce, err := nm.AcquireNonce(ctx, client, chainID, addr)
		if err != nil {
			return err
		}

		err = submitFn(nonce)
		if err == nil {
			return nil
		}

		if isNonceTooLow(err) {
			nm.ResetNonce(chainID, addr)
			continue
		}

		// Tx was broadcast but receipt failed (timeout/context). Nonce consumed on-chain; do not release.
		if errors.Is(err, ErrTxBroadcastNoReceipt) {
			nm.ResetNonce(chainID, addr)
			return err
		}

		nm.ReleaseNonce(chainID, addr, nonce)
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
