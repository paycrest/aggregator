package utils

import (
	"encoding/json"
	"fmt"

	"github.com/paycrest/aggregator/types"
)

// Raw asset data as a JSON string
const assetDataJSON = `[
  {
    "assetId": "nep141:eth.omft.near",
    "decimals": 18,
    "networkIdentifier": "ETH",
    "symbol": "ETH",
	"network": "ethereum"
  },
  {
    "assetId": "nep141:btc.omft.near",
    "decimals": 8,
    "networkIdentifier": "BTC",
    "symbol": "BTC",
	"network": "bitcoin"
  },
  {
    "assetId": "nep141:sol.omft.near",
    "decimals": 9,
    "networkIdentifier": "SOL",
    "symbol": "SOL",
	"network": "solana"
  },
  {
    "assetId": "nep141:tron.omft.near",
    "decimals": 6,
    "networkIdentifier": "TRON",
    "symbol": "TRX",
	"network": "tron"
  },
  {
    "assetId": "nep141:base.omft.near",
    "decimals": 18,
    "networkIdentifier": "BASE.ETH",
    "symbol": "ETH",
	"network": "base"
  },
  {
    "assetId": "nep141:sol-c58e6539c2f2e097c251f8edf11f9c03e581f8d4.omft.near",
    "decimals": 6,
    "networkIdentifier": "SOL.TRUMP",
    "symbol": "TRUMP",
    "network": "solana"
  },
  {
    "assetId": "nep141:arb.omft.near",
    "decimals": 18,
    "networkIdentifier": "ARB.ETH",
    "symbol": "ETH",
    "network": "arbitrum"
  },
  {
    "assetId": "nep141:sol-5ce3bf3a31af18be40ba30f721101b4341690186.omft.near",
    "decimals": 6,
    "networkIdentifier": "SOL.USDC",
    "symbol": "USDC",
    "network": "solana"
  },
  {
    "assetId": "nep141:sol-c800a4bd850783ccb82c2b2c7e84175443606352.omft.near",
    "decimals": 6,
    "networkIdentifier": "SOL.USDT",
    "symbol": "USDT",
    "network": "solana"
  },
  {
    "assetId": "nep141:tron-d28a265909efecdcee7c5028585214ea0b96f015.omft.near",
    "decimals": 6,
    "networkIdentifier": "TRON.USDT",
    "symbol": "USDT",
    "network": "tron"
  },
  {
    "assetId": "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near",
    "decimals": 6,
    "networkIdentifier": "BASE.USDC",
    "symbol": "USDC",
    "network": "base"
  }
]`

type IntentMetadataService struct {
	assets []types.Asset
}

func initIntentMetadataService(jsonData string) (*IntentMetadataService, error) {
	var assets []types.Asset

	err := json.Unmarshal([]byte(jsonData), &assets)
	if err != nil {
		return nil, err
	}

	var legacyAssets []struct {
		AssetID           string `json:"assetId"`
		Decimals          int    `json:"decimals"`
		NetworkIdentifier string `json:"networkIdentifier"`
		Symbol            string `json:"symbol"`
		ContractAddress   string `json:"contractAddress,omitempty"`
	}

	if unmarshalErr := json.Unmarshal([]byte(jsonData), &legacyAssets); unmarshalErr == nil {
		// Convert from legacy format to current format
		assets = make([]types.Asset, len(legacyAssets))
		for i, legacy := range legacyAssets {
			assets[i] = types.Asset{
				AssetID:           legacy.AssetID,
				Decimals:          legacy.Decimals,
				NetworkIdentifier: legacy.NetworkIdentifier,
				Symbol:            legacy.Symbol,
				ContractAddress:   legacy.ContractAddress,
			}
		}
	} else {
		return nil, err
	}

	return &IntentMetadataService{assets: assets}, nil
}

func (s *IntentMetadataService)  GetAssetsByNetworkIdentifier(networkIdentifier string) (types.Asset, error) {
	if networkIdentifier == "" {
		return types.Asset{}, fmt.Errorf("networkIdentifier is empty")
	}
	if networkIdentifier == "BASE.USDC" {
		return types.Asset{}, fmt.Errorf("networkIdentifier cannot be destination asset")
	}
	
	for _, asset := range s.assets {
		if asset.NetworkIdentifier == networkIdentifier {
			return asset, nil
		}
	}
	return types.Asset{}, fmt.Errorf("asset not found")
}

func GetAssetsByNetworkID(networkIdentifier string) (types.Asset, error) {
	service, err := initIntentMetadataService(assetDataJSON)
	if err != nil {
		return types.Asset{}, err
	}
	return service.GetAssetsByNetworkIdentifier(networkIdentifier)
}

func GetDestinationAssetsByNetworkID() (string) {
	return "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near"
}

func IsValidNetworkIdentifier(networkIdentifier string) bool {
	_, err := GetAssetsByNetworkID(networkIdentifier)
	return err == nil
}