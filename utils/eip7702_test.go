package utils

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

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

	sig, err := SignBatch7702(key, signerAddr, 0, calls)
	if err != nil {
		t.Fatalf("SignBatch7702 failed: %v", err)
	}

	if len(sig) != 65 {
		t.Fatalf("expected 65-byte signature, got %d", len(sig))
	}
	if sig[64] != 27 && sig[64] != 28 {
		t.Errorf("expected v=27 or v=28, got %d", sig[64])
	}

	// Recompute digest and verify recovery
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
	rawSig[64] -= 27 // undo v adjustment for recovery

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
	addr := crypto.PubkeyToAddress(key.PublicKey)

	calls := []Call7702{
		{To: common.HexToAddress("0xtoken"), Value: big.NewInt(0), Data: []byte{0xab}},
	}

	sig0, _ := SignBatch7702(key, addr, 0, calls)
	sig1, _ := SignBatch7702(key, addr, 1, calls)

	if string(sig0) == string(sig1) {
		t.Error("different nonces should produce different signatures")
	}
}

func TestPackExecute_ProducesValidCalldata(t *testing.T) {
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)

	calls := []Call7702{
		{To: common.HexToAddress("0xtoken"), Value: big.NewInt(0), Data: []byte{0x01}},
	}

	sig, err := SignBatch7702(key, addr, 0, calls)
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

	// execute(Call[],bytes) selector = first 4 bytes
	// Just verify we got non-trivial output
	if len(data) < 100 {
		t.Errorf("calldata suspiciously short: %d bytes", len(data))
	}
}

func TestPackExecute_MultipleCalls(t *testing.T) {
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)

	oneCalls := []Call7702{
		{To: common.HexToAddress("0xtoken"), Value: big.NewInt(0), Data: []byte{0x01}},
	}
	twoCalls := []Call7702{
		{To: common.HexToAddress("0xtoken"), Value: big.NewInt(0), Data: []byte{0x01}},
		{To: common.HexToAddress("0xgateway"), Value: big.NewInt(0), Data: []byte{0x02, 0x03}},
	}

	sig1, _ := SignBatch7702(key, addr, 0, oneCalls)
	sig2, _ := SignBatch7702(key, addr, 0, twoCalls)

	data1, _ := PackExecute(oneCalls, sig1)
	data2, _ := PackExecute(twoCalls, sig2)

	if len(data2) <= len(data1) {
		t.Error("two calls should produce longer calldata than one")
	}
}
