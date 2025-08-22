package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/utils"
)

// Global rate limiter for all Etherscan API calls
var (
	globalEtherscanLimiter = &EtherscanRateLimiter{
		lastCall: time.Now(),
		mu:       &sync.Mutex{},
		// Token bucket: 4 tokens per second, max burst of 1 to prevent initial rush
		tokens:     1,
		maxTokens:  1,
		lastRefill: time.Now(),
	}
)

// EtherscanRateLimiter provides global rate limiting for Etherscan API calls
type EtherscanRateLimiter struct {
	lastCall   time.Time
	mu         *sync.Mutex
	tokens     int
	maxTokens  int
	lastRefill time.Time
}

// EtherscanService provides functionality for interacting with Etherscan API
type EtherscanService struct {
	config *config.EtherscanConfiguration
	// Remove instance-level rate limiter since we're using global one
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

// waitForGlobalRateLimit waits for the global rate limiter before making API calls
func (s *EtherscanService) waitForGlobalRateLimit(ctx context.Context) error {
	return globalEtherscanLimiter.waitForRateLimit(ctx)
}

// waitForRateLimit waits for the rate limiter before making API calls
func (limiter *EtherscanRateLimiter) waitForRateLimit(ctx context.Context) error {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	now := time.Now()
	
	// Refill tokens based on time passed since last refill (4 tokens per second)
	timePassed := now.Sub(limiter.lastRefill)
	tokensToAdd := int(timePassed.Seconds() * 4) // 4 tokens per second

	if tokensToAdd > 0 {
		limiter.tokens = min(limiter.maxTokens, limiter.tokens+tokensToAdd)
		limiter.lastRefill = limiter.lastRefill.Add(time.Duration(tokensToAdd) * 250 * time.Millisecond)
	}

	// If no tokens available, calculate exact wait time
	if limiter.tokens <= 0 {
		// Calculate time needed for next token (250ms per token at 4 tokens/second)
		timeSinceLastRefill := now.Sub(limiter.lastRefill)
		timeForNextToken := 250 * time.Millisecond
		waitTime := timeForNextToken - timeSinceLastRefill
		
		if waitTime > 0 {
			timer := time.NewTimer(waitTime)
			defer timer.Stop()

			select {
			case <-timer.C:
				// Timer completed, add one token
				limiter.tokens = 1
				limiter.lastRefill = now
			case <-ctx.Done():
				// Context was cancelled
				return ctx.Err()
			}
		} else {
			// Enough time has passed, add one token
			limiter.tokens = 1
			limiter.lastRefill = now
		}
	}

	// Consume a token
	limiter.tokens--
	limiter.lastCall = now
	return nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetAddressTransactionHistory fetches transaction history for any address from Etherscan API
func (s *EtherscanService) GetAddressTransactionHistory(ctx context.Context, chainID int64, walletAddress string, limit int, fromBlock int64, toBlock int64) ([]map[string]interface{}, error) {
	// Wait for rate limiter before making the API call
	if err := s.waitForGlobalRateLimit(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error: %w", err)
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
