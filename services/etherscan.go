package services

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
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

	// Log the request payload
	logger.WithFields(logger.Fields{
		"chainID":       chainID,
		"walletAddress": walletAddress,
		"limit":         limit,
		"fromBlock":     fromBlock,
		"toBlock":       toBlock,
		"baseURL":       baseURL,
		"params":        params,
	}).Infof("Making Etherscan API request")

	res, err := fastshot.NewClient(baseURL).
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}).Build().GET("").
		Query().AddParams(params).Send()
	if err != nil {
		logger.WithFields(logger.Fields{
			"error": err.Error(),
		}).Errorf("Failed to make HTTP request to Etherscan API")
		return nil, fmt.Errorf("failed to get transaction history: %w", err)
	}

	// Read the response body for logging
	responseBody, _ := io.ReadAll(res.RawResponse.Body)

	// Log the full response
	logger.WithFields(logger.Fields{
		"statusCode": res.StatusCode(),
		"response":   string(responseBody),
	}).Infof("Received response from Etherscan API")

	// Create a new response with the same body for parsing
	res.RawResponse.Body = io.NopCloser(bytes.NewBuffer(responseBody))

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		logger.WithFields(logger.Fields{
			"error":       err.Error(),
			"rawResponse": string(responseBody),
		}).Errorf("Failed to parse JSON response from Etherscan API")
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	// Check if the response indicates success
	if data["status"] != "1" {
		message := "unknown error"
		if data["message"] != nil {
			message = data["message"].(string)
		}
		logger.WithFields(logger.Fields{
			"status":  data["status"],
			"message": message,
		}).Errorf("Etherscan API returned error")
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
