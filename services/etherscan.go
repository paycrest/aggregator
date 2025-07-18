package services

import (
	"context"
	"fmt"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/utils"
)

// EtherscanService provides functionality for interacting with Etherscan API
type EtherscanService struct {
	config *config.EtherscanConfiguration
}

// NewEtherscanService creates a new instance of EtherscanService
func NewEtherscanService() *EtherscanService {
	etherscanConfig := config.EtherscanConfig()
	if etherscanConfig.ApiKey == "" {
		panic("ETHERSCAN_API_KEY environment variable is required")
	}

	return &EtherscanService{
		config: etherscanConfig,
	}
}

// GetUserTransactionHistory fetches user transaction history from Etherscan API
func (s *EtherscanService) GetUserTransactionHistory(ctx context.Context, chainID int64, walletAddress string, limit int, fromBlock int64, toBlock int64) ([]map[string]interface{}, error) {
	// Check if this is BNB Smart Chain (chain ID 56) - use RPC instead of Etherscan API
	if chainID == 56 {
		return nil, fmt.Errorf("user transaction history not supported for BNB Smart Chain via Etherscan API")
	}

	// Build query parameters for Etherscan API
	params := map[string]string{
		"module":  "account",
		"action":  "tokentx",
		"address": walletAddress,
		"page":    "1",
		"offset":  fmt.Sprintf("%d", limit),
		"sort":    "desc", // Get newest transactions first
		"apikey":  s.config.ApiKey,
	}

	// Add block range filtering if specified
	if fromBlock > 0 {
		params["startblock"] = fmt.Sprintf("%d", fromBlock)
	}
	if toBlock > 0 {
		params["endblock"] = fmt.Sprintf("%d", toBlock)
	}

	// Use Etherscan API with chain ID
	baseURL := fmt.Sprintf("https://api.etherscan.io/v2/api?chainid=%d", chainID)

	res, err := fastshot.NewClient(baseURL).
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}).Build().GET("").
		Query().AddParams(params).Send()
	if err != nil {
		return nil, fmt.Errorf("failed to get user transaction history: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	// Check if the response indicates success
	if data["status"] != "1" {
		message := "unknown error"
		if data["message"] != nil {
			message = data["message"].(string)
		}
		return nil, fmt.Errorf("etherscan API error: %s", message)
	}

	if data["result"] == nil {
		return []map[string]interface{}{}, nil
	}

	transactions := data["result"].([]interface{})
	result := make([]map[string]interface{}, len(transactions))

	for i, tx := range transactions {
		result[i] = tx.(map[string]interface{})
	}

	return result, nil
}
