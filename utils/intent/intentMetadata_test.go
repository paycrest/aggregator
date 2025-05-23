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
		expectedSymbols string
	}{
		{
			name:            "Ethereum assets",
			networkID:       "ETH",
			expectedSymbols: "ETH",
		},
		{
			name:            "Bitcoin assets",
			networkID:       "BTC",
			expectedSymbols: "BTC",
		},
		{
			name:            "Solana assets",
			networkID:       "SOL",
			expectedSymbols: "SOL",
		},
		{
			name:            "Tron assets",
			networkID:       "TRON",
			expectedSymbols: "TRX",
		},
		{
			name:            "Tron assets",
			networkID:       "BASE.ETH",
			expectedSymbols: "ETH",
		},
		{
			name:            "SOL assets",
			networkID:       "SOL.USDC",
			expectedSymbols: "USDC",
		},
		{
			name:            "TRON assets",
			networkID:       "TRON.USDT",
			expectedSymbols: "USDT",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function being tested
			assets, err := GetAssetsByNetworkID(tc.networkID)

			assert.NoError(t, err)
			assert.Equal(t, tc.networkID, assets.NetworkIdentifier)
			assert.Equal(t, tc.expectedSymbols, assets.Symbol)
			assert.NotNil(t, assets.AssetID)
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

