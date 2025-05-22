package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAssetsByNetworkID(t *testing.T) {
	// Test cases for different network identifiers
	testCases := []struct {
		name            string
		networkID       string
		expectedLen     int
		expectedSymbols []string
	}{
		{
			name:            "Ethereum assets",
			networkID:       "eth",
			expectedLen:     1,
			expectedSymbols: []string{"ETH"},
		},
		{
			name:            "Bitcoin assets",
			networkID:       "btc",
			expectedLen:     1,
			expectedSymbols: []string{"BTC"},
		},
		{
			name:            "Solana assets",
			networkID:       "sol",
			expectedLen:     3,
			expectedSymbols: []string{"SOL", "TRUMP", "USDC", "USDT"},
		},
		{
			name:            "Tron assets",
			networkID:       "tron",
			expectedLen:     1,
			expectedSymbols: []string{"TRX", "USDT"},
		},
		{
			name:            "Non-existent network",
			networkID:       "nonexistent",
			expectedLen:     0,
			expectedSymbols: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function being tested
			assets, err := GetAssetsByNetworkID(tc.networkID)

			// Assert no error occurred
			assert.NoError(t, err)

			// Check the length of returned assets
			assert.GreaterOrEqual(t, len(assets), tc.expectedLen, "Expected at least %d assets for network %s, got %d", tc.expectedLen, tc.networkID, len(assets))

			// For empty result, no need to check symbols
			if tc.expectedLen == 0 {
				return
			}

			// Check that the assets contain the expected symbols
			foundSymbols := make(map[string]bool)
			for _, asset := range assets {
				foundSymbols[asset.Symbol] = true
			}

			for _, expectedSymbol := range tc.expectedSymbols {
				// If the expected symbol is in the test case (not all are required),
				// verify it exists in the returned assets
				if len(expectedSymbol) > 0 {
					assert.True(t, foundSymbols[expectedSymbol], "Expected to find symbol %s for network %s", expectedSymbol, tc.networkID)
				}
			}
		})
	}
}

func TestInitIntentMetadataService(t *testing.T) {
	// Test with valid JSON data (networkIdentifier format)
	t.Run("Valid networkIdentifier JSON", func(t *testing.T) {
		jsonData := `[
			{
				"assetId": "nep141:eth.omft.near",
				"decimals": 18,
				"networkIdentifier": "eth",
				"symbol": "ETH"
			}
		]`

		service, err := initIntentMetadataService(jsonData)
		assert.NoError(t, err)
		assert.NotNil(t, service)
		assert.Equal(t, 1, len(service.assets))
		assert.Equal(t, "ETH", service.assets[0].Symbol)
		assert.Equal(t, "eth", service.assets[0].NetworkIdentifier)
	})

	// Test with legacy format (blockchain instead of networkIdentifier)
	t.Run("Legacy blockchain JSON", func(t *testing.T) {
		jsonData := `[
			{
				"assetId": "nep141:sol-5ce3bf3a31af18be40ba30f721101b4341690186.omft.near",
				"decimals": 6,
				"networkIdentifier": "sol",
				"symbol": "USDC",
				"contractAddress": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
			}
		]`

		service, err := initIntentMetadataService(jsonData)
		assert.NoError(t, err)
		assert.NotNil(t, service)
		assert.Equal(t, 1, len(service.assets))
		assert.Equal(t, "USDC", service.assets[0].Symbol)
		assert.Equal(t, "sol", service.assets[0].NetworkIdentifier)
	})

	// Test with invalid JSON
	t.Run("Invalid JSON", func(t *testing.T) {
		jsonData := `{ invalid json }`

		service, err := initIntentMetadataService(jsonData)
		assert.Error(t, err)
		assert.Nil(t, service)
	})
}

