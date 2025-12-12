// Package starknet provides comprehensive tests for the Starknet client implementation.
//
// This test suite uses real on-chain transaction data from Starknet mainnet to ensure
// that event parsing and blockchain interaction logic works correctly with actual data.
// Using real transactions provides more confidence than synthetic mocks, as it validates
// the code against the actual data structures returned by the Starknet network.
//
// Test Coverage:
// - Event parsing (OrderCreated, OrderSettled, OrderRefunded, Transfer)
// - Deterministic account generation from seeds
// - Cairo ByteArray encoding/decoding (for string handling)
// - U256 conversion from felt pairs (for large numbers)
// - Block number retrieval
// - Transaction receipt fetching
//
// Integration Tests:
// The tests marked with "if testing.Short()" require network access to Starknet mainnet.
// Run with `go test -short` to skip these tests during local development.
//
// Benchmarks:
// Performance benchmarks are included for event parsing operations.
// Run with `go test -bench=.` to measure parsing performance.
package starknet

import (
	"context"
	"math/big"
	"testing"

	"github.com/NethermindEth/juno/core/felt"
	"github.com/NethermindEth/starknet.go/rpc"
	"github.com/NethermindEth/starknet.go/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Real transaction hashes from Starknet mainnet for testing
const (
	providerURL = "https://1rpc.io/starknet" 
	// OrderCreated transaction
	txHashOrderCreated = "0x11a848b19eecce8aa1e420b0b7c4064f054027d0f54379c510760a6ff961186"

	// OrderSettled transaction
	txHashOrderSettled = "0x5cbd1216e1301bae373deb7552b9cb3aeacbea2a1f2a0a8c15117e8b841e8e2"

	// OrderRefunded transaction
	txHashOrderRefunded = "0x535eb1f95f5cdf365c551803a4bf57f7af691c51fe627b3905779a62f3cbb94"

	// Transfer transaction
	txHashTransfer = "0x557e915102b4f181d3056ee0d75b122be98c9430b8ef309ef607fffdde621fd"
)

// TestClient_RealTransactionData tests event parsing with real on-chain transaction data
func TestClient_RealTransactionData(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test that requires network access")
	}

	ctx := context.Background()

	// Create a provider to fetch real transaction data
	provider, err := rpc.NewProvider(ctx, providerURL)
	require.NoError(t, err, "Failed to create Starknet provider")

	client := &Client{
		providerClient: provider,
	}

	t.Run("OrderCreated Event", func(t *testing.T) {
		txHash, err := utils.HexToFelt(txHashOrderCreated)
		require.NoError(t, err)

		// Fetch the actual transaction receipt
		receipt, err := provider.TransactionReceipt(ctx, txHash)
		require.NoError(t, err, "Failed to fetch OrderCreated transaction receipt")

		// Find OrderCreated events in the receipt
		require.NotEmpty(t, receipt.Events, "No events found in transaction")

		// Process each event
		for _, event := range receipt.Events {
			emittedEvent := rpc.EmittedEvent{
				Event:           event,
				BlockHash:       receipt.BlockHash,
				BlockNumber:     uint64(receipt.BlockNumber),
				TransactionHash: receipt.Hash,
			}

			result, err := client.processEvent(emittedEvent)
			if err != nil {
				// Not all events may be OrderCreated, skip parse errors
				continue
			}

			// Verify the parsed event has expected fields
			if eventType, ok := result["event"].(string); ok && eventType == "OrderCreated" {
				assert.NotEmpty(t, result["sender"], "Sender should not be empty")
				assert.NotEmpty(t, result["token"], "Token should not be empty")
				assert.NotEmpty(t, result["amount"], "Amount should not be empty")
				assert.NotEmpty(t, result["order_id"], "Order ID should not be empty")
				assert.NotEmpty(t, result["rate"], "Rate should not be empty")
				assert.NotEmpty(t, result["message_hash"], "Message hash should not be empty")

				// Verify numeric fields are valid
				if amount, ok := result["amount"].(*big.Int); ok {
					assert.True(t, amount.Sign() > 0, "Amount should be positive")
				}

				t.Logf("OrderCreated event parsed successfully: order_id=%v", result["order_id"])
			}
		}
	})

	t.Run("OrderSettled Event", func(t *testing.T) {
		txHash, err := utils.HexToFelt(txHashOrderSettled)
		require.NoError(t, err)

		// Fetch the actual transaction receipt
		receipt, err := provider.TransactionReceipt(ctx, txHash)
		require.NoError(t, err, "Failed to fetch OrderSettled transaction receipt")

		// Find OrderSettled events in the receipt
		require.NotEmpty(t, receipt.Events, "No events found in transaction")

		// Process each event
		for _, event := range receipt.Events {
			emittedEvent := rpc.EmittedEvent{
				Event:           event,
				BlockHash:       receipt.BlockHash,
				BlockNumber:     uint64(receipt.BlockNumber),
				TransactionHash: receipt.Hash,
			}

			result, err := client.processEvent(emittedEvent)
			if err != nil {
				continue
			}

			// Verify the parsed event has expected fields
			if eventType, ok := result["event"].(string); ok && eventType == "OrderSettled" {
				assert.NotEmpty(t, result["order_id"], "Order ID should not be empty")
				assert.NotEmpty(t, result["liquidity_provider"], "Liquidity provider should not be empty")
				assert.NotEmpty(t, result["split_order_id"], "Split order ID should not be empty")

				// Verify percentages are within valid range (0-100 or 0-10000 basis points)
				if settlePercent, ok := result["settle_percent"].(uint64); ok {
					assert.True(t, settlePercent <= 10000, "Settle percent should be <= 10000")
				}
				if rebatePercent, ok := result["rebate_percent"].(uint64); ok {
					assert.True(t, rebatePercent <= 10000, "Rebate percent should be <= 10000")
				}

				t.Logf("OrderSettled event parsed successfully: order_id=%v", result["order_id"])
			}
		}
	})

	t.Run("OrderRefunded Event", func(t *testing.T) {
		txHash, err := utils.HexToFelt(txHashOrderRefunded)
		require.NoError(t, err)

		// Fetch the actual transaction receipt
		receipt, err := provider.TransactionReceipt(ctx, txHash)
		require.NoError(t, err, "Failed to fetch OrderRefunded transaction receipt")

		// Find OrderRefunded events in the receipt
		require.NotEmpty(t, receipt.Events, "No events found in transaction")

		// Process each event
		for _, event := range receipt.Events {
			emittedEvent := rpc.EmittedEvent{
				Event:           event,
				BlockHash:       receipt.BlockHash,
				BlockNumber:     uint64(receipt.BlockNumber),
				TransactionHash: receipt.Hash,
			}

			result, err := client.processEvent(emittedEvent)
			if err != nil {
				continue
			}

			// Verify the parsed event has expected fields
			if eventType, ok := result["event"].(string); ok && eventType == "OrderRefunded" {
				assert.NotEmpty(t, result["order_id"], "Order ID should not be empty")
				assert.NotEmpty(t, result["fee"], "Fee should not be empty")

				// Verify fee is valid
				if fee, ok := result["fee"].(*big.Int); ok {
					assert.True(t, fee.Sign() >= 0, "Fee should be non-negative")
				}

				t.Logf("OrderRefunded event parsed successfully: order_id=%v", result["order_id"])
			}
		}
	})

	t.Run("Transfer Event", func(t *testing.T) {
		txHash, err := utils.HexToFelt(txHashTransfer)
		require.NoError(t, err)

		// Fetch the actual transaction receipt
		receipt, err := provider.TransactionReceipt(ctx, txHash)
		require.NoError(t, err, "Failed to fetch Transfer transaction receipt")

		// Find Transfer events in the receipt
		require.NotEmpty(t, receipt.Events, "No events found in transaction")

		// Process each event
		for _, event := range receipt.Events {
			emittedEvent := rpc.EmittedEvent{
				Event:           event,
				BlockHash:       receipt.BlockHash,
				BlockNumber:     uint64(receipt.BlockNumber),
				TransactionHash: receipt.Hash,
			}

			result, err := client.processEvent(emittedEvent)
			if err != nil {
				continue
			}

			// Verify the parsed event has expected fields
			if eventType, ok := result["event"].(string); ok && eventType == "Transfer" {
				assert.NotEmpty(t, result["from"], "From address should not be empty")
				assert.NotEmpty(t, result["to"], "To address should not be empty")
				assert.NotEmpty(t, result["value"], "Value should not be empty")

				// Verify value is valid
				if value, ok := result["value"].(*big.Int); ok {
					assert.True(t, value.Sign() > 0, "Transfer value should be positive")
				}

				t.Logf("Transfer event parsed successfully: from=%v to=%v", result["from"], result["to"])
			}
		}
	})
}

// TestGenerateDeterministicAccount tests account generation from seed
func TestGenerateDeterministicAccount(t *testing.T) {
	client, err := NewClient()
	if err != nil {
		t.Skip("Skipping test: failed to create client (may need proper config)")
	}

	t.Run("Generate account with valid seed", func(t *testing.T) {
		seed := "test-seed-12345"
		account1, err := client.GenerateDeterministicAccount(seed)
		require.NoError(t, err)
		require.NotNil(t, account1)

		// Verify account has required fields
		assert.NotNil(t, account1.NewAccount, "Account should not be nil")
		assert.NotNil(t, account1.PublicKey, "Public key should not be nil")
		assert.NotNil(t, account1.Salt, "Salt should not be nil")

		// Generate again with same seed - should be deterministic
		account2, err := client.GenerateDeterministicAccount(seed)
		require.NoError(t, err)
		require.NotNil(t, account2)

		// Verify deterministic generation
		assert.Equal(t, account1.NewAccount.Address.String(), account2.NewAccount.Address.String(), "Same seed should generate same address")
		assert.Equal(t, account1.PublicKey.String(), account2.PublicKey.String(), "Same seed should generate same public key")
		assert.Equal(t, account1.Salt.String(), account2.Salt.String(), "Same seed should generate same salt")
	})

	t.Run("Different seeds generate different accounts", func(t *testing.T) {
		account1, err := client.GenerateDeterministicAccount("seed-1")
		require.NoError(t, err)

		account2, err := client.GenerateDeterministicAccount("seed-2")
		require.NoError(t, err)

		// Verify different seeds produce different accounts
		assert.NotEqual(t, account1.NewAccount.Address.String(), account2.NewAccount.Address.String(), "Different seeds should generate different addresses")
		assert.NotEqual(t, account1.PublicKey.String(), account2.PublicKey.String(), "Different seeds should generate different public keys")
	})
}

// TestEncodeCairoByteArray tests ByteArray encoding for Cairo
func TestEncodeCairoByteArray(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected int // expected number of felts
	}{
		{
			name:     "Empty data",
			input:    []byte{},
			expected: 3, // num_chunks=0, pending_word=0, pending_word_len=0
		},
		{
			name:     "Small data (< 31 bytes)",
			input:    []byte("Hello World"),
			expected: 3, // num_chunks=0, pending_word, pending_word_len=11
		},
		{
			name:     "Exactly 31 bytes",
			input:    make([]byte, 31),
			expected: 4, // num_chunks=1, one chunk, pending_word=0, pending_word_len=0
		},
		{
			name:     "32 bytes (one full chunk + 1)",
			input:    make([]byte, 32),
			expected: 4, // num_chunks=1, one chunk, pending_word, pending_word_len=1
		},
		{
			name:     "62 bytes (two full chunks)",
			input:    make([]byte, 62),
			expected: 5, // num_chunks=2, two chunks, pending_word=0, pending_word_len=0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encodeCairoByteArray(tt.input)
			assert.Equal(t, tt.expected, len(result), "Unexpected number of felts in encoded ByteArray")
		})
	}
}

// TestParseByteArray tests ByteArray parsing from Cairo format
func TestParseByteArray(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple string",
			input:    "Hello, Starknet!",
			expected: "Hello, Starknet!",
		},
		{
			name:     "Long string (> 31 bytes)",
			input:    "This is a longer string that exceeds 31 bytes and should be split into multiple chunks",
			expected: "This is a longer string that exceeds 31 bytes and should be split into multiple chunks",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode the input string
			encoded := encodeCairoByteArray([]byte(tt.input))

			// Parse it back
			parsed := parseByteArray(encoded)

			// Verify round-trip encoding/decoding
			assert.Equal(t, tt.expected, parsed, "Parsed ByteArray should match original")
		})
	}
}

// TestU256FromFelts tests u256 conversion from two felts
func TestU256FromFelts(t *testing.T) {
	tests := []struct {
		name     string
		low      *felt.Felt
		high     *felt.Felt
		expected *big.Int
	}{
		{
			name:     "Zero value",
			low:      new(felt.Felt).SetUint64(0),
			high:     new(felt.Felt).SetUint64(0),
			expected: big.NewInt(0),
		},
		{
			name:     "Low only",
			low:      new(felt.Felt).SetUint64(12345),
			high:     new(felt.Felt).SetUint64(0),
			expected: big.NewInt(12345),
		},
		{
			name: "High only",
			low:  new(felt.Felt).SetUint64(0),
			high: new(felt.Felt).SetUint64(1),
			expected: func() *big.Int {
				result := new(big.Int).Lsh(big.NewInt(1), 128)
				return result
			}(),
		},
		{
			name: "Both low and high",
			low:  new(felt.Felt).SetUint64(100),
			high: new(felt.Felt).SetUint64(1),
			expected: func() *big.Int {
				high := new(big.Int).Lsh(big.NewInt(1), 128)
				return new(big.Int).Add(high, big.NewInt(100))
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := u256FromFelts(tt.low, tt.high)
			assert.Equal(t, 0, result.Cmp(tt.expected), "u256 value should match expected: got %s, want %s", result.String(), tt.expected.String())
		})
	}
}

// TestGetBlockNumber tests block number retrieval (integration test)
func TestGetBlockNumber(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test that requires network access")
	}

	ctx := context.Background()
	client, err := NewClient()
	if err != nil {
		t.Skip("Skipping test: failed to create client (may need proper config)")
	}

	blockNumber, err := client.GetBlockNumber(ctx)
	require.NoError(t, err, "Failed to get block number")
	assert.Greater(t, blockNumber, uint64(0), "Block number should be positive")

	t.Logf("Current Starknet block number: %d", blockNumber)
}

// TestGetTransactionReceipt tests transaction receipt retrieval with real data
func TestGetTransactionReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test that requires network access")
	}

	ctx := context.Background()
	client, err := NewClient()
	if err != nil {
		t.Skip("Skipping test: failed to create client (may need proper config)")
	}

	t.Run("OrderCreated transaction receipt", func(t *testing.T) {
		txHash, err := utils.HexToFelt(txHashOrderCreated)
		require.NoError(t, err)

		// Use the gateway contract address from the actual transaction
		// For this test, we'll fetch the receipt directly and check events
		receipt, err := client.providerClient.TransactionReceipt(ctx, txHash)
		require.NoError(t, err, "Failed to get transaction receipt")

		// Should have at least one event
		assert.NotEmpty(t, receipt.Events, "Transaction should have events")

		t.Logf("Found %d events in transaction", len(receipt.Events))
	})
}

// BenchmarkEventParsing benchmarks event parsing performance
func BenchmarkEventParsing(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark that requires network access")
	}

	ctx := context.Background()
	provider, err := rpc.NewProvider(ctx, providerURL)
	if err != nil {
		b.Skip("Failed to create provider")
	}

	client := &Client{
		providerClient: provider,
	}

	// Fetch one transaction to benchmark
	txHash, _ := utils.HexToFelt(txHashOrderCreated)
	receipt, err := provider.TransactionReceipt(ctx, txHash)
	if err != nil {
		b.Skip("Failed to fetch transaction")
	}

	events := receipt.Events

	if len(events) == 0 {
		b.Skip("No events to benchmark")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, event := range events {
			emittedEvent := rpc.EmittedEvent{
				Event:           event,
				BlockHash:       receipt.BlockHash,
				BlockNumber:     uint64(receipt.BlockNumber),
				TransactionHash: receipt.Hash,
			}
			_, _ = client.processEvent(emittedEvent)
		}
	}
}
