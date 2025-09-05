package services

import (
	"context"
	"fmt"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/utils"
)

// BlockscoutService provides functionality for interacting with Blockscout API
type BlockscoutService struct {
	baseURL string
}

// NewBlockscoutService creates a new instance of BlockscoutService
func NewBlockscoutService() *BlockscoutService {
	return &BlockscoutService{
		baseURL: "https://blockscout.lisk.com",
	}
}

// GetAddressTokenTransfers fetches token transfer history for any address from Blockscout API
func (s *BlockscoutService) GetAddressTokenTransfers(ctx context.Context, chainID int64, walletAddress string, limit int, fromBlock int64, toBlock int64) ([]map[string]interface{}, error) {
	// Build query parameters for Blockscout API
	params := map[string]string{
		"items_count": fmt.Sprintf("%d", limit),
	}

	// Note: Blockscout API doesn't support block range filtering for token transfers
	// We'll fetch more token transfers and filter client-side if needed
	if fromBlock > 0 || toBlock > 0 {
		// Increase limit to get more token transfers for client-side filtering
		if limit < 100 {
			params["items_count"] = "100"
		}
	}

	// Use Blockscout API
	res, err := fastshot.NewClient(s.baseURL).
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}).Build().GET("/api/v2/addresses/" + walletAddress + "/token-transfers").
		Query().AddParams(params).Send()
	if err != nil {
		return nil, fmt.Errorf("failed to get token transfers from Blockscout: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response from Blockscout: %w", err)
	}

	// Check if the response contains token transfers
	if data["items"] == nil {
		return []map[string]interface{}{}, nil
	}

	tokenTransfers := data["items"].([]interface{})

	// Note: Token transfers don't have block_number in the same format as transactions
	// For now, we'll return all token transfers without block filtering
	// TODO: Implement block filtering for token transfers if needed

	result := make([]map[string]interface{}, len(tokenTransfers))
	for i, transfer := range tokenTransfers {
		result[i] = transfer.(map[string]interface{})
	}

	return result, nil
}
