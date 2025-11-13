package services

import (
	"context"
	"fmt"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
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
		Header().Add("Accept", "application/json").
		Header().Add("Content-Type", "application/json").
		Build().GET("/api/v2/addresses/" + walletAddress + "/token-transfers").
		Query().AddParams(params).Send()
	if err != nil {
		return nil, fmt.Errorf("failed to get token transfers from Blockscout: %w", err)
	}

	// Check for HTTP errors
	if res.Status().IsError() {
		body, _ := res.Body().AsString()
		return nil, fmt.Errorf("HTTP error %d: %s", res.Status().Code(), body)
	}

	var data map[string]interface{}
	err = res.Body().AsJSON(&data)
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

	result := make([]map[string]interface{}, 0, len(tokenTransfers))
	seen := make(map[string]struct{})
	for _, item := range tokenTransfers {
		transferMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		txHash, _ := transferMap["transaction_hash"].(string)
		if txHash == "" {
			continue
		}
		if _, exists := seen[txHash]; exists {
			continue
		}

		// Normalize field names to match what the indexer expects
		// Indexer expects "hash" field, but token transfers have "transaction_hash"
		transferMap["hash"] = txHash
		seen[txHash] = struct{}{}

		result = append(result, transferMap)
	}

	return result, nil
}
