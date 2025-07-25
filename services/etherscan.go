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
func NewEtherscanService() (*EtherscanService, error) {
	etherscanConfig := config.EtherscanConfig()
	if etherscanConfig.ApiKey == "" {
		return nil, fmt.Errorf("ETHERSCAN_API_KEY environment variable is required")
	}

	return &EtherscanService{
		config: etherscanConfig,
	}, nil
}

// GetAddressTransactionHistory fetches transaction history for any address from Etherscan API
func (s *EtherscanService) GetAddressTransactionHistory(ctx context.Context, chainID int64, walletAddress string, limit int, fromBlock int64, toBlock int64) ([]map[string]interface{}, error) {
	// Build query parameters for Etherscan API
	params := map[string]string{
		"module":  "account",
		"action":  "tokentx",
		"address": walletAddress,
		"page":    "1",
		"offset":  fmt.Sprintf("%d", limit),
		"sort":    "desc", // Get newest transactions first
		"apikey":  s.config.ApiKey,
		"chainid": fmt.Sprintf("%d", chainID),
	}

	// Add block range filtering if specified
	if fromBlock > 0 {
		params["startblock"] = fmt.Sprintf("%d", fromBlock)
	}
	if toBlock > 0 {
		params["endblock"] = fmt.Sprintf("%d", toBlock)
	}

	// Use Etherscan API with chain ID
	res, err := fastshot.NewClient("https://api.etherscan.io").
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}).Build().GET("/v2/api").
		Query().AddParams(params).Send()
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction history: %w", err)
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
		if message == "No transactions found" {
			return []map[string]interface{}{}, nil
		}
		return nil, fmt.Errorf("etherscan API error: %s %v %v", message, data, params)
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
