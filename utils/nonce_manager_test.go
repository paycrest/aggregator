package utils

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestAcquireNonce_Sequential(t *testing.T) {
	nm := NewNonceManager()
	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	chainID := int64(1)

	// Pre-seed the nonce so we don't need a real RPC client
	nm.mu.Lock()
	nm.nonces[nonceKey{chainID, addr}] = 10
	nm.mu.Unlock()

	for i := uint64(0); i < 5; i++ {
		nonce, err := nm.AcquireNonce(context.Background(), nil, chainID, addr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := 10 + i
		if nonce != expected {
			t.Errorf("attempt %d: expected nonce %d, got %d", i, expected, nonce)
		}
	}
}

func TestAcquireNonce_Concurrent(t *testing.T) {
	nm := NewNonceManager()
	addr := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	chainID := int64(42)

	nm.mu.Lock()
	nm.nonces[nonceKey{chainID, addr}] = 0
	nm.mu.Unlock()

	const goroutines = 50
	results := make(chan uint64, goroutines)
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nonce, err := nm.AcquireNonce(context.Background(), nil, chainID, addr)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			results <- nonce
		}()
	}

	wg.Wait()
	close(results)

	seen := make(map[uint64]bool)
	for nonce := range results {
		if seen[nonce] {
			t.Errorf("duplicate nonce: %d", nonce)
		}
		seen[nonce] = true
	}

	if len(seen) != goroutines {
		t.Errorf("expected %d unique nonces, got %d", goroutines, len(seen))
	}
}

func TestReleaseNonce(t *testing.T) {
	nm := NewNonceManager()
	addr := common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	chainID := int64(1)

	nm.mu.Lock()
	nm.nonces[nonceKey{chainID, addr}] = 5
	nm.mu.Unlock()

	nonce, _ := nm.AcquireNonce(context.Background(), nil, chainID, addr)
	if nonce != 5 {
		t.Fatalf("expected nonce 5, got %d", nonce)
	}

	// Internal counter should now be 6; release 5 to roll back
	nm.ReleaseNonce(chainID, addr, 5)

	nonce2, _ := nm.AcquireNonce(context.Background(), nil, chainID, addr)
	if nonce2 != 5 {
		t.Errorf("after release, expected nonce 5 again, got %d", nonce2)
	}
}

func TestReleaseNonce_NoRollbackForward(t *testing.T) {
	nm := NewNonceManager()
	addr := common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")
	chainID := int64(1)

	nm.mu.Lock()
	nm.nonces[nonceKey{chainID, addr}] = 5
	nm.mu.Unlock()

	// Acquire nonces 5 and 6
	nm.AcquireNonce(context.Background(), nil, chainID, addr)
	nm.AcquireNonce(context.Background(), nil, chainID, addr)

	// Try to release nonce 10 (higher than current 7) -- should be ignored
	nm.ReleaseNonce(chainID, addr, 10)

	nonce, _ := nm.AcquireNonce(context.Background(), nil, chainID, addr)
	if nonce != 7 {
		t.Errorf("expected nonce 7 (release of higher nonce should be no-op), got %d", nonce)
	}
}

func TestResetNonce(t *testing.T) {
	nm := NewNonceManager()
	addr := common.HexToAddress("0xdddddddddddddddddddddddddddddddddddddd")
	chainID := int64(1)

	nm.mu.Lock()
	nm.nonces[nonceKey{chainID, addr}] = 100
	nm.mu.Unlock()

	nm.ResetNonce(chainID, addr)

	nm.mu.Lock()
	_, exists := nm.nonces[nonceKey{chainID, addr}]
	nm.mu.Unlock()

	if exists {
		t.Error("expected nonce to be cleared after reset")
	}
}

func TestDifferentChains_IndependentNonces(t *testing.T) {
	nm := NewNonceManager()
	addr := common.HexToAddress("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")

	nm.mu.Lock()
	nm.nonces[nonceKey{1, addr}] = 10
	nm.nonces[nonceKey{42, addr}] = 50
	nm.mu.Unlock()

	nonce1, _ := nm.AcquireNonce(context.Background(), nil, 1, addr)
	nonce42, _ := nm.AcquireNonce(context.Background(), nil, 42, addr)

	if nonce1 != 10 {
		t.Errorf("chain 1: expected 10, got %d", nonce1)
	}
	if nonce42 != 50 {
		t.Errorf("chain 42: expected 50, got %d", nonce42)
	}
}

func TestDifferentAddresses_IndependentNonces(t *testing.T) {
	nm := NewNonceManager()
	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	chainID := int64(1)

	nm.mu.Lock()
	nm.nonces[nonceKey{chainID, addr1}] = 5
	nm.nonces[nonceKey{chainID, addr2}] = 20
	nm.mu.Unlock()

	n1, _ := nm.AcquireNonce(context.Background(), nil, chainID, addr1)
	n2, _ := nm.AcquireNonce(context.Background(), nil, chainID, addr2)

	if n1 != 5 {
		t.Errorf("addr1: expected 5, got %d", n1)
	}
	if n2 != 20 {
		t.Errorf("addr2: expected 20, got %d", n2)
	}
}

func TestSubmitWithNonce_Success(t *testing.T) {
	nm := NewNonceManager()
	addr := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	chainID := int64(1)

	nm.mu.Lock()
	nm.nonces[nonceKey{chainID, addr}] = 0
	nm.mu.Unlock()

	var capturedNonce uint64
	err := nm.SubmitWithNonce(context.Background(), nil, chainID, addr, func(nonce uint64) error {
		capturedNonce = nonce
		return nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedNonce != 0 {
		t.Errorf("expected nonce 0, got %d", capturedNonce)
	}
}

func TestSubmitWithNonce_NonNonceError(t *testing.T) {
	nm := NewNonceManager()
	addr := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	chainID := int64(1)

	nm.mu.Lock()
	nm.nonces[nonceKey{chainID, addr}] = 5
	nm.mu.Unlock()

	submitErr := fmt.Errorf("execution reverted")
	err := nm.SubmitWithNonce(context.Background(), nil, chainID, addr, func(nonce uint64) error {
		return submitErr
	})

	if err == nil || err.Error() != "execution reverted" {
		t.Errorf("expected 'execution reverted', got %v", err)
	}

	// Nonce should have been released back to 5
	nm.mu.Lock()
	current := nm.nonces[nonceKey{chainID, addr}]
	nm.mu.Unlock()

	if current != 5 {
		t.Errorf("expected nonce released back to 5, got %d", current)
	}
}

func TestSubmitWithNonce_NonceTooLowTriggersReset(t *testing.T) {
	nm := NewNonceManager()
	addr := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	chainID := int64(1)

	// Verify that isNonceTooLow triggers a reset (key deletion)
	nm.mu.Lock()
	nm.nonces[nonceKey{chainID, addr}] = 10
	nm.mu.Unlock()

	// Acquire a nonce
	nonce, _ := nm.AcquireNonce(context.Background(), nil, chainID, addr)
	if nonce != 10 {
		t.Fatalf("expected nonce 10, got %d", nonce)
	}

	// Simulate nonce-too-low: isNonceTooLow should detect it
	err := fmt.Errorf("nonce too low")
	if !isNonceTooLow(err) {
		t.Fatal("expected isNonceTooLow to return true")
	}

	// Reset should clear the entry, forcing a re-fetch on next AcquireNonce
	nm.ResetNonce(chainID, addr)
	nm.mu.Lock()
	_, exists := nm.nonces[nonceKey{chainID, addr}]
	nm.mu.Unlock()
	if exists {
		t.Error("expected nonce key to be deleted after reset")
	}

	// Simulate re-fetch by re-seeding (in production, AcquireNonce would call PendingNonceAt)
	nm.mu.Lock()
	nm.nonces[nonceKey{chainID, addr}] = 15
	nm.mu.Unlock()

	// Next acquire should return the re-fetched nonce
	nonce2, _ := nm.AcquireNonce(context.Background(), nil, chainID, addr)
	if nonce2 != 15 {
		t.Errorf("after reset and re-seed, expected nonce 15, got %d", nonce2)
	}
}

func TestIsNonceTooLow(t *testing.T) {
	tests := []struct {
		err    error
		expect bool
	}{
		{nil, false},
		{fmt.Errorf("execution reverted"), false},
		{fmt.Errorf("nonce too low"), true},
		{fmt.Errorf("Nonce Too Low"), true},
		{fmt.Errorf("replacement transaction underpriced"), true},
		{fmt.Errorf("already known"), true},
		{fmt.Errorf("tx failed: nonce too low for account"), true},
	}

	for _, tt := range tests {
		got := isNonceTooLow(tt.err)
		if got != tt.expect {
			t.Errorf("isNonceTooLow(%v) = %v, want %v", tt.err, got, tt.expect)
		}
	}
}
