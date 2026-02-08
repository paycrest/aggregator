package indexer

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/paycrest/aggregator/ent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Real transaction hashes from Starknet mainnet for testing
const (
	// OrderCreated transaction
	txHashOrderCreated = "0x11a848b19eecce8aa1e420b0b7c4064f054027d0f54379c510760a6ff961186"

	// OrderSettled transaction
	txHashOrderSettled = "0x5cbd1216e1301bae373deb7552b9cb3aeacbea2a1f2a0a8c15117e8b841e8e2"

	// OrderRefunded transaction
	txHashOrderRefunded = "0x535eb1f95f5cdf365c551803a4bf57f7af691c51fe627b3905779a62f3cbb94"

	// Transfer transaction
	txHashTransfer = "0x557e915102b4f181d3056ee0d75b122be98c9430b8ef309ef607fffdde621fd"

	// Gateway contract address
	gatewayContract = "0x06ff3a3b1532da65594fc98f9ca7200af6c3dbaf37e7339b0ebd3b3f2390c583"

	// Token contract address (USDC)
	tokenContract = "0x068F5c6a61780768455de69077E07e89787839bf8166dEcfBf92B645209c0fB8"

	// User account address (receive address)
	userAddress = "0x046a056257607e1126a73b789bc6b56216e260261d4b54dd0809df46638bcbad"

	// Provider address (liquidity provider)
	providerAddress = "0x032d13ffa6cbd17949ef27f6387cb99ba607d3767e6b8cd455e73139417dd770"
)

// createMockToken creates a mock token entity for testing
func createMockToken() *ent.Token {
	return &ent.Token{
		ID:              1,
		Symbol:          "USDC",
		Decimals:        6,
		ContractAddress: tokenContract,
		IsEnabled:       true,
		BaseCurrency:    "USD",
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
}

// createMockNetwork creates a mock network entity for testing
func createMockNetwork() *ent.Network {
	return &ent.Network{
		ID:                     1,
		Identifier:             "starknet-mainnet",
		ChainID:                23448594291968334, // SN_MAIN
		GatewayContractAddress: gatewayContract,
		IsTestnet:              false,
		CreatedAt:              time.Now(),
		UpdatedAt:              time.Now(),
	}
}

// TestIndexerStarknet_IndexReceiveAddress tests the IndexReceiveAddress function with a real transfer transaction
func TestIndexerStarknet_IndexReceiveAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test that requires network access")
	}

	// Skip if STARKNET_RPC_URL is not set
	if os.Getenv("STARKNET_RPC_URL") == "" {
		t.Skip("STARKNET_RPC_URL not set, skipping Starknet indexer test")
	}

	ctx := context.Background()

	// Create indexer
	indexer, err := NewIndexerStarknet()
	require.NoError(t, err, "Failed to create Starknet indexer")

	// Create mock token
	token := createMockToken()

	t.Run("Index Transfer to User Address", func(t *testing.T) {
		// Index the transfer transaction by txHash
		// fromBlock and toBlock are ignored when txHash is provided
		eventCounts, err := indexer.IndexReceiveAddress(
			ctx,
			token,
			userAddress,
			4082084, // fromBlock (ignored when txHash is provided)
			4082089, // toBlock (ignored when txHash is provided)
			txHashTransfer,
		)

		require.NoError(t, err, "Failed to index receive address")
		require.NotNil(t, eventCounts, "Event counts should not be nil")

		// Verify that at least one transfer event was found
		assert.Greater(t, eventCounts.Transfer, 0, "Expected at least one transfer event")

		t.Logf("Successfully indexed transfer transaction: %s", txHashTransfer)
		t.Logf("Transfer events found: %d", eventCounts.Transfer)
	})

	t.Run("Index Non-Existent Transfer", func(t *testing.T) {
		// Try to index with a transaction that doesn't have transfers to the user address
		eventCounts, err := indexer.IndexReceiveAddress(
			ctx,
			token,
			userAddress,
			4082085,
			4082089,
			txHashOrderCreated, // OrderCreated tx, not a transfer
		)

		// Should not error, but should find no matching transfers
		require.NoError(t, err, "Should not error on non-transfer transaction")
		require.NotNil(t, eventCounts, "Event counts should not be nil")

		// No transfer events should match the user address
		assert.Equal(t, 0, eventCounts.Transfer, "Expected no transfer events for OrderCreated transaction")
	})
}

// TestIndexerStarknet_IndexGateway tests the IndexGateway function with real gateway transactions
func TestIndexerStarknet_IndexGateway(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test that requires network access")
	}

	// Skip if STARKNET_RPC_URL is not set
	if os.Getenv("STARKNET_RPC_URL") == "" {
		t.Skip("STARKNET_RPC_URL not set, skipping Starknet indexer test")
	}

	ctx := context.Background()

	// Create indexer
	indexer, err := NewIndexerStarknet()
	require.NoError(t, err, "Failed to create Starknet indexer")

	// Create mock network
	network := createMockNetwork()

	t.Run("Index OrderCreated Event", func(t *testing.T) {
		eventCounts, err := indexer.IndexGateway(
			ctx,
			network,
			gatewayContract,
			3956603, // fromBlock (ignored when txHash is provided)
			4083247, // toBlock (ignored when txHash is provided)
			txHashOrderCreated,
		)

		require.NoError(t, err, "Failed to index OrderCreated transaction")
		require.NotNil(t, eventCounts, "Event counts should not be nil")

		// Verify that at least one OrderCreated event was found
		assert.Greater(t, eventCounts.OrderCreated, 0, "Expected at least one OrderCreated event")

		t.Logf("Successfully indexed OrderCreated transaction: %s", txHashOrderCreated)
		t.Logf("OrderCreated events found: %d", eventCounts.OrderCreated)
	})

	t.Run("Index OrderSettled Event", func(t *testing.T) {
		eventCounts, err := indexer.IndexGateway(
			ctx,
			network,
			gatewayContract,
			4083126,
			4083129,
			txHashOrderSettled,
		)

		require.NoError(t, err, "Failed to index OrderSettled transaction")
		require.NotNil(t, eventCounts, "Event counts should not be nil")

		// Verify that at least one OrderSettled event was found
		assert.Greater(t, eventCounts.OrderSettled, 0, "Expected at least one OrderSettled event")

		t.Logf("Successfully indexed OrderSettled transaction: %s", txHashOrderSettled)
		t.Logf("OrderSettled events found: %d", eventCounts.OrderSettled)
	})

	t.Run("Index OrderRefunded Event", func(t *testing.T) {
		eventCounts, err := indexer.IndexGateway(
			ctx,
			network,
			gatewayContract,
			4083245,
			4083249,
			txHashOrderRefunded,
		)

		require.NoError(t, err, "Failed to index OrderRefunded transaction")
		require.NotNil(t, eventCounts, "Event counts should not be nil")

		// Verify that at least one OrderRefunded event was found
		assert.Greater(t, eventCounts.OrderRefunded, 0, "Expected at least one OrderRefunded event")

		t.Logf("Successfully indexed OrderRefunded transaction: %s", txHashOrderRefunded)
		t.Logf("OrderRefunded events found: %d", eventCounts.OrderRefunded)
	})
}

// TestIndexerStarknet_IndexProviderSettlementAddress tests the IndexProviderSettlementAddress function with a real settlement transaction
func TestIndexerStarknet_IndexProviderSettlementAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test that requires network access")
	}

	// Skip if STARKNET_RPC_URL is not set
	if os.Getenv("STARKNET_RPC_URL") == "" {
		t.Skip("STARKNET_RPC_URL not set, skipping Starknet indexer test")
	}

	ctx := context.Background()

	// Create indexer
	indexer, err := NewIndexerStarknet()
	require.NoError(t, err, "Failed to create Starknet indexer")

	// Create mock network
	network := createMockNetwork()

	t.Run("Index Provider Settlement", func(t *testing.T) {
		eventCounts, err := indexer.IndexProviderSettlementAddress(
			ctx,
			network,
			providerAddress,
			4083126, // fromBlock (ignored when txHash is provided)
			4083129, // toBlock (ignored when txHash is provided)
			txHashOrderSettled,
		)

		require.NoError(t, err, "Failed to index provider settlement")
		require.NotNil(t, eventCounts, "Event counts should not be nil")

		// Verify that at least one OrderSettled event was found for this provider
		assert.Greater(t, eventCounts.OrderSettled, 0, "Expected at least one OrderSettled event for provider")

		t.Logf("Successfully indexed provider settlement: %s", txHashOrderSettled)
		t.Logf("OrderSettled events found for provider: %d", eventCounts.OrderSettled)
	})

	t.Run("Index Non-Provider Transaction", func(t *testing.T) {
		// Try to index OrderCreated transaction for provider (should find nothing)
		eventCounts, err := indexer.IndexProviderSettlementAddress(
			ctx,
			network,
			providerAddress,
			0,
			0,
			txHashOrderCreated, // OrderCreated doesn't have provider settlements
		)

		// Should not error, but should find no provider settlements
		require.NoError(t, err, "Should not error on non-settlement transaction")
		require.NotNil(t, eventCounts, "Event counts should not be nil")

		// No OrderSettled events should match
		assert.Equal(t, 0, eventCounts.OrderSettled, "Expected no OrderSettled events in OrderCreated transaction")
	})
}

// TestIndexerStarknet_Integration tests the complete flow of indexing different event types
func TestIndexerStarknet_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test that requires network access")
	}

	// Skip if STARKNET_RPC_URL is not set
	if os.Getenv("STARKNET_RPC_URL") == "" {
		t.Skip("STARKNET_RPC_URL not set, skipping Starknet indexer test")
	}

	ctx := context.Background()

	// Create indexer
	indexer, err := NewIndexerStarknet()
	require.NoError(t, err, "Failed to create Starknet indexer")

	// Create mocks
	token := createMockToken()
	network := createMockNetwork()

	t.Run("Complete Order Flow", func(t *testing.T) {
		// Step 1: User transfers tokens to gateway (IndexReceiveAddress)
		transferCounts, err := indexer.IndexReceiveAddress(ctx, token, userAddress, 0, 0, txHashTransfer)
		require.NoError(t, err, "Failed to index transfer")
		t.Logf("✓ Step 1 - Transfer indexed: %d events", transferCounts.Transfer)

		// Step 2: Order is created (IndexGateway)
		orderCreatedCounts, err := indexer.IndexGateway(ctx, network, gatewayContract, 0, 0, txHashOrderCreated)
		require.NoError(t, err, "Failed to index order creation")
		t.Logf("✓ Step 2 - OrderCreated indexed: %d events", orderCreatedCounts.OrderCreated)

		// Step 3: Provider settles the order (IndexProviderSettlementAddress)
		settlementCounts, err := indexer.IndexProviderSettlementAddress(ctx, network, providerAddress, 0, 0, txHashOrderSettled)
		require.NoError(t, err, "Failed to index provider settlement")
		t.Logf("✓ Step 3 - OrderSettled indexed: %d events", settlementCounts.OrderSettled)

		// Step 4: Order can be refunded if needed (IndexGateway)
		refundCounts, err := indexer.IndexGateway(ctx, network, gatewayContract, 0, 0, txHashOrderRefunded)
		require.NoError(t, err, "Failed to index order refund")
		t.Logf("✓ Step 4 - OrderRefunded indexed: %d events", refundCounts.OrderRefunded)

		t.Log("\n✓ Complete order flow tested successfully")
	})
}
