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
    "symbol": "ETH"
  },
  {
    "assetId": "nep141:btc.omft.near",
    "decimals": 8,
    "networkIdentifier": "BTC",
    "symbol": "BTC"
  },
  {
    "assetId": "nep141:sol.omft.near",
    "decimals": 9,
    "networkIdentifier": "SOL",
    "symbol": "SOL"
  },
  {
    "assetId": "nep141:tron.omft.near",
    "decimals": 6,
    "networkIdentifier": "TRON",
    "symbol": "TRX"
  },
  {
    "assetId": "nep141:base.omft.near",
    "decimals": 18,
    "networkIdentifier": "BASE.ETH",
    "symbol": "ETH"
  },
  {
    "assetId": "nep141:sol-c58e6539c2f2e097c251f8edf11f9c03e581f8d4.omft.near",
    "decimals": 6,
    "networkIdentifier": "SOL.TRUMP",
    "symbol": "TRUMP",
    "contractAddress": "6p6xgHyF7AeE6TZkSmFsko444wqoP15icUSqi2jfGiPN"
  },
  {
    "assetId": "nep141:arb.omft.near",
    "decimals": 18,
    "networkIdentifier": "ARB.ETH",
    "symbol": "ETH"
  },
  {
    "assetId": "nep141:sol-5ce3bf3a31af18be40ba30f721101b4341690186.omft.near",
    "decimals": 6,
    "networkIdentifier": "SOL.USDC",
    "symbol": "USDC",
    "contractAddress": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
  },
  {
    "assetId": "nep141:sol-c800a4bd850783ccb82c2b2c7e84175443606352.omft.near",
    "decimals": 6,
    "networkIdentifier": "SOL.USDT",
    "symbol": "USDT",
    "contractAddress": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
  },
  {
    "assetId": "nep141:tron-d28a265909efecdcee7c5028585214ea0b96f015.omft.near",
    "decimals": 6,
    "networkIdentifier": "TRON.USDT",
    "symbol": "USDT",
    "contractAddress": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
  },
  {
    "assetId": "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near",
    "decimals": 6,
    "networkIdentifier": "BASE.USDC",
    "symbol": "USDC",
    "contractAddress": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
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
