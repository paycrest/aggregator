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

// GetAddressTransactionHistory fetches transaction history for any address from Blockscout API
func (s *BlockscoutService) GetAddressTransactionHistory(ctx context.Context, chainID int64, walletAddress string, limit int, fromBlock int64, toBlock int64) ([]map[string]interface{}, error) {
	// Build query parameters for Blockscout API
	params := map[string]string{
		"items_count": fmt.Sprintf("%d", limit),
	}

	// Note: Blockscout API doesn't support block range filtering
	// We'll fetch more transactions and filter client-side if needed
	if fromBlock > 0 || toBlock > 0 {
		// Increase limit to get more transactions for client-side filtering
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
	}).Build().GET("/api/v2/addresses/" + walletAddress + "/transactions").
		Query().AddParams(params).Send()
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction history from Blockscout: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response from Blockscout: %w", err)
	}

	// Check if the response contains transactions
	if data["items"] == nil {
		return []map[string]interface{}{}, nil
	}

	transactions := data["items"].([]interface{})

	// Apply client-side block range filtering if specified
	if fromBlock > 0 || toBlock > 0 {
		filteredTransactions := make([]interface{}, 0)

		for _, tx := range transactions {
			txMap := tx.(map[string]interface{})
			blockNum, ok := txMap["block_number"].(float64)
			if !ok {
				continue
			}

			// Check if transaction is within the specified block range
			if fromBlock > 0 && int64(blockNum) < fromBlock {
				continue
			}
			if toBlock > 0 && int64(blockNum) > toBlock {
				continue
			}

			filteredTransactions = append(filteredTransactions, tx)
		}

		transactions = filteredTransactions
	}

	result := make([]map[string]interface{}, len(transactions))
	for i, tx := range transactions {
		result[i] = tx.(map[string]interface{})
	}

	return result, nil
}
