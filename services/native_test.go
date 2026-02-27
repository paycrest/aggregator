package services

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestAcquireNonce_Sequential(t *testing.T) {
	nm := NewNonceManager()
	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	chainID := int64(1)

	nm.mu.Lock()
	nm.nonces[nonceKey{chainID, addr}] = 10
	nm.mu.Unlock()

	for i := uint64(0); i < 5; i++ {
		nonce, err := nm.acquireNonce(context.Background(), nil, chainID, addr)
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
			nonce, err := nm.acquireNonce(context.Background(), nil, chainID, addr)
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

	nonce, _ := nm.acquireNonce(context.Background(), nil, chainID, addr)
	if nonce != 5 {
		t.Fatalf("expected nonce 5, got %d", nonce)
	}

	nm.releaseNonce(chainID, addr, 5)

	nonce2, _ := nm.acquireNonce(context.Background(), nil, chainID, addr)
	if nonce2 != 6 {
		t.Errorf("after release (no-op), next acquire should be 6, got %d", nonce2)
	}
}

func TestReleaseNonce_NoRollbackForward(t *testing.T) {
	nm := NewNonceManager()
	addr := common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")
	chainID := int64(1)

	nm.mu.Lock()
	nm.nonces[nonceKey{chainID, addr}] = 5
	nm.mu.Unlock()

	nm.acquireNonce(context.Background(), nil, chainID, addr)
	nm.acquireNonce(context.Background(), nil, chainID, addr)

	nm.releaseNonce(chainID, addr, 10)

	nonce, _ := nm.acquireNonce(context.Background(), nil, chainID, addr)
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

	nm.resetNonce(chainID, addr)

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

	nonce1, _ := nm.acquireNonce(context.Background(), nil, 1, addr)
	nonce42, _ := nm.acquireNonce(context.Background(), nil, 42, addr)

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

	n1, _ := nm.acquireNonce(context.Background(), nil, chainID, addr1)
	n2, _ := nm.acquireNonce(context.Background(), nil, chainID, addr2)

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
	err := nm.submitWithNonce(context.Background(), nil, chainID, addr, func(nonce uint64) error {
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
	err := nm.submitWithNonce(context.Background(), nil, chainID, addr, func(nonce uint64) error {
		return submitErr
	})

	if err == nil || err.Error() != "execution reverted" {
		t.Errorf("expected 'execution reverted', got %v", err)
	}

	nm.mu.Lock()
	current := nm.nonces[nonceKey{chainID, addr}]
	nm.mu.Unlock()

	if current != 6 {
		t.Errorf("after non-nonce error, counter should stay 6 (no rollback), got %d", current)
	}
}

func TestSubmitWithNonce_NonceTooLowTriggersReset(t *testing.T) {
	nm := NewNonceManager()
	addr := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	chainID := int64(1)

	nm.mu.Lock()
	nm.nonces[nonceKey{chainID, addr}] = 10
	nm.mu.Unlock()

	nonce, _ := nm.acquireNonce(context.Background(), nil, chainID, addr)
	if nonce != 10 {
		t.Fatalf("expected nonce 10, got %d", nonce)
	}

	err := fmt.Errorf("nonce too low")
	if !isNonceTooLow(err) {
		t.Fatal("expected isNonceTooLow to return true")
	}

	nm.resetNonce(chainID, addr)
	nm.mu.Lock()
	_, exists := nm.nonces[nonceKey{chainID, addr}]
	nm.mu.Unlock()
	if exists {
		t.Error("expected nonce key to be deleted after reset")
	}

	nm.mu.Lock()
	nm.nonces[nonceKey{chainID, addr}] = 15
	nm.mu.Unlock()

	nonce2, _ := nm.acquireNonce(context.Background(), nil, chainID, addr)
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

// --- EIP-7702 signing tests (moved from utils/eip7702_test.go) ---

func TestSignAuthorization7702_RecoversSigner(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	expectedAddr := crypto.PubkeyToAddress(key.PublicKey)

	chainID := big.NewInt(11155111) // Sepolia
	contract := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	nonce := uint64(0)

	auth, err := SignAuthorization7702(key, chainID, contract, nonce)
	if err != nil {
		t.Fatalf("SignAuthorization7702 failed: %v", err)
	}

	if auth.Address != contract {
		t.Errorf("expected contract %s, got %s", contract.Hex(), auth.Address.Hex())
	}
	if auth.Nonce != nonce {
		t.Errorf("expected nonce %d, got %d", nonce, auth.Nonce)
	}

	recovered, err := auth.Authority()
	if err != nil {
		t.Fatalf("failed to recover authority: %v", err)
	}
	if recovered != expectedAddr {
		t.Errorf("recovered %s, expected %s", recovered.Hex(), expectedAddr.Hex())
	}
}

func TestSignAuthorization7702_DifferentNonces(t *testing.T) {
	key, _ := crypto.GenerateKey()
	chainID := big.NewInt(1)
	contract := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	auth0, err := SignAuthorization7702(key, chainID, contract, 0)
	if err != nil {
		t.Fatal(err)
	}
	auth1, err := SignAuthorization7702(key, chainID, contract, 1)
	if err != nil {
		t.Fatal(err)
	}

	if auth0.R == auth1.R && auth0.S == auth1.S {
		t.Error("different nonces should produce different signatures")
	}
}

func TestSignBatch7702_RecoversSigner(t *testing.T) {
	key, _ := crypto.GenerateKey()
	signerAddr := crypto.PubkeyToAddress(key.PublicKey)

	calls := []Call7702{
		{To: common.HexToAddress("0xtoken"), Value: big.NewInt(0), Data: []byte{0x01, 0x02}},
		{To: common.HexToAddress("0xgateway"), Value: big.NewInt(0), Data: []byte{0x03, 0x04}},
	}

	sig, err := SignBatch7702(key, 0, calls)
	if err != nil {
		t.Fatalf("SignBatch7702 failed: %v", err)
	}

	if len(sig) != 65 {
		t.Fatalf("expected 65-byte signature, got %d", len(sig))
	}
	if sig[64] != 27 && sig[64] != 28 {
		t.Errorf("expected v=27 or v=28, got %d", sig[64])
	}

	var packed []byte
	for _, c := range calls {
		packed = append(packed, c.To.Bytes()...)
		valBytes := make([]byte, 32)
		c.Value.FillBytes(valBytes)
		packed = append(packed, valBytes...)
		packed = append(packed, c.Data...)
	}
	nonceBytes := make([]byte, 32)
	big.NewInt(0).FillBytes(nonceBytes)

	digest := crypto.Keccak256Hash(append(nonceBytes, packed...))
	prefix := []byte("\x19Ethereum Signed Message:\n32")
	msgHash := crypto.Keccak256Hash(append(prefix, digest.Bytes()...))

	rawSig := make([]byte, 65)
	copy(rawSig, sig)
	rawSig[64] -= 27

	pub, err := crypto.SigToPub(msgHash.Bytes(), rawSig)
	if err != nil {
		t.Fatalf("failed to recover pubkey: %v", err)
	}
	recovered := crypto.PubkeyToAddress(*pub)
	if recovered != signerAddr {
		t.Errorf("recovered %s, expected %s", recovered.Hex(), signerAddr.Hex())
	}
}

func TestSignBatch7702_DifferentNoncesProduceDifferentSigs(t *testing.T) {
	key, _ := crypto.GenerateKey()

	calls := []Call7702{
		{To: common.HexToAddress("0xtoken"), Value: big.NewInt(0), Data: []byte{0xab}},
	}

	sig0, _ := SignBatch7702(key, 0, calls)
	sig1, _ := SignBatch7702(key, 1, calls)

	if string(sig0) == string(sig1) {
		t.Error("different nonces should produce different signatures")
	}
}

func TestPackExecute_ProducesValidCalldata(t *testing.T) {
	key, _ := crypto.GenerateKey()

	calls := []Call7702{
		{To: common.HexToAddress("0xtoken"), Value: big.NewInt(0), Data: []byte{0x01}},
	}

	sig, err := SignBatch7702(key, 0, calls)
	if err != nil {
		t.Fatal(err)
	}

	data, err := PackExecute(calls, sig)
	if err != nil {
		t.Fatalf("PackExecute failed: %v", err)
	}

	if len(data) < 4 {
		t.Fatal("calldata too short, missing function selector")
	}
	if len(data) < 100 {
		t.Errorf("calldata suspiciously short: %d bytes", len(data))
	}
}

func TestPackExecute_MultipleCalls(t *testing.T) {
	key, _ := crypto.GenerateKey()

	oneCalls := []Call7702{
		{To: common.HexToAddress("0xtoken"), Value: big.NewInt(0), Data: []byte{0x01}},
	}
	twoCalls := []Call7702{
		{To: common.HexToAddress("0xtoken"), Value: big.NewInt(0), Data: []byte{0x01}},
		{To: common.HexToAddress("0xgateway"), Value: big.NewInt(0), Data: []byte{0x02, 0x03}},
	}

	sig1, _ := SignBatch7702(key, 0, oneCalls)
	sig2, _ := SignBatch7702(key, 0, twoCalls)

	data1, _ := PackExecute(oneCalls, sig1)
	data2, _ := PackExecute(twoCalls, sig2)

	if len(data2) <= len(data1) {
		t.Error("two calls should produce longer calldata than one")
	}
}
