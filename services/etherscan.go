package services

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

// EtherscanService provides functionality for interacting with Etherscan API
type EtherscanService struct {
	config *config.EtherscanConfiguration
}

// EtherscanRequest represents a queued Etherscan API request
type EtherscanRequest struct {
	ID            string                  `json:"id"`
	ChainID       int64                   `json:"chain_id"`
	WalletAddress string                  `json:"wallet_address"`
	Limit         int                     `json:"limit"`
	FromBlock     int64                   `json:"from_block"`
	ToBlock       int64                   `json:"to_block"`
	CreatedAt     time.Time               `json:"created_at"`
	ResponseChan  chan *EtherscanResponse `json:"-"` // Channel for response
}

// EtherscanResponse represents the response from Etherscan API
type EtherscanResponse struct {
	Data  []map[string]interface{} `json:"data"`
	Error error                    `json:"error"`
}

var (
	workerStarted sync.Once
	workerCtx     context.Context
	workerCancel  context.CancelFunc
)

// NewEtherscanService creates a new instance of EtherscanService
func NewEtherscanService() (*EtherscanService, error) {
	etherscanConfig := config.EtherscanConfig()
	if etherscanConfig.ApiKey == "" {
		return nil, fmt.Errorf("ETHERSCAN_API_KEY environment variable is required")
	}

	// Start the background worker only once
	workerStarted.Do(func() {
		workerCtx, workerCancel = context.WithCancel(context.Background())
		go startEtherscanWorker(workerCtx)
	})

	return &EtherscanService{
		config: etherscanConfig,
	}, nil
}

// startEtherscanWorker starts a background worker to process queued requests
func startEtherscanWorker(ctx context.Context) {
	// Get rate limit from config or use default (5 requests per second for free tier)
	rateLimit := 5 // requests per second
	interval := time.Duration(1000/rateLimit) * time.Millisecond

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	logger.WithFields(logger.Fields{
		"RateLimit": rateLimit,
		"Interval":  interval,
	}).Info("Etherscan worker started")

	processedCount := 0
	errorCount := 0

	for {
		select {
		case <-ctx.Done():
			logger.Infof("Etherscan worker stopped")
			return
		case <-ticker.C:
			// Process one request from the queue
			if err := processNextEtherscanRequest(ctx); err != nil {
				if err.Error() != "no requests in queue" {
					errorCount++
					logger.WithFields(logger.Fields{
						"Error": fmt.Sprintf("%v", err),
					}).Errorf("Failed to process Etherscan request")
				}
			} else {
				processedCount++

				// Log stats every 100 processed requests
				if processedCount%100 == 0 {
					logger.WithFields(logger.Fields{
						"Processed": processedCount,
						"Errors":    errorCount,
					}).Infof("Etherscan worker stats")
				}
			}
		}
	}
}

// processNextEtherscanRequest processes the next request from the queue
func processNextEtherscanRequest(ctx context.Context) error {
	// Get the next request from the queue
	requestData, err := storage.RedisClient.LPop(ctx, "etherscan_queue").Result()
	if err != nil {
		return fmt.Errorf("no requests in queue")
	}

	var request EtherscanRequest
	if err := json.Unmarshal([]byte(requestData), &request); err != nil {
		return fmt.Errorf("failed to unmarshal request: %w", err)
	}

	// Check if request is too old (older than 5 minutes)
	if time.Since(request.CreatedAt) > 5*time.Minute {
		logger.WithFields(logger.Fields{
			"RequestID": request.ID,
			"Age":       time.Since(request.CreatedAt),
		}).Warnf("Skipping old request")
		return nil
	}

	// Make the actual API call
	data, err := makeEtherscanAPICall(request)

	// Send response through the channel
	response := &EtherscanResponse{
		Data:  data,
		Error: err,
	}

	// Try to send response, but don't block if channel is closed
	select {
	case request.ResponseChan <- response:
		// Response sent successfully
	default:
		// Channel is full or closed
		logger.WithFields(logger.Fields{
			"RequestID": request.ID,
		}).Debugf("Could not send response to request (channel full or closed)")
	}

	return nil
}

// makeEtherscanAPICall makes the actual API call to Etherscan
func makeEtherscanAPICall(request EtherscanRequest) ([]map[string]interface{}, error) {
	// Build query parameters for Etherscan API
	params := map[string]string{
		"module":  "account",
		"action":  "tokentx",
		"address": request.WalletAddress,
		"page":    "1",
		"offset":  fmt.Sprintf("%d", request.Limit),
		"sort":    "desc", // Get newest transactions first
		"apikey":  config.EtherscanConfig().ApiKey,
		"chainid": fmt.Sprintf("%d", request.ChainID),
	}

	// Add block range filtering if specified
	if request.FromBlock > 0 {
		params["startblock"] = fmt.Sprintf("%d", request.FromBlock)
	}
	if request.ToBlock > 0 {
		params["endblock"] = fmt.Sprintf("%d", request.ToBlock)
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

// GetAddressTransactionHistory fetches transaction history for any address from Etherscan API
func (s *EtherscanService) GetAddressTransactionHistory(ctx context.Context, chainID int64, walletAddress string, limit int, fromBlock int64, toBlock int64) ([]map[string]interface{}, error) {
	// Create a unique request ID
	requestID := fmt.Sprintf("%d_%s_%d_%d_%d", chainID, walletAddress, limit, fromBlock, toBlock)

	// Create response channel
	responseChan := make(chan *EtherscanResponse, 1)

	// Create the request
	request := EtherscanRequest{
		ID:            requestID,
		ChainID:       chainID,
		WalletAddress: walletAddress,
		Limit:         limit,
		FromBlock:     fromBlock,
		ToBlock:       toBlock,
		CreatedAt:     time.Now(),
		ResponseChan:  responseChan,
	}

	// Serialize and queue the request
	requestData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Add to queue
	if err := storage.RedisClient.RPush(ctx, "etherscan_queue", requestData).Err(); err != nil {
		return nil, fmt.Errorf("failed to queue request: %w", err)
	}

	// Wait for response with timeout
	select {
	case response := <-responseChan:
		if response.Error != nil {
			return nil, response.Error
		}
		return response.Data, nil
	case <-ctx.Done():
		// Context was cancelled, close the channel to signal worker
		close(responseChan)
		return nil, ctx.Err()
	case <-time.After(30 * time.Second): // 30 second timeout
		// Request timed out, close the channel to signal worker
		close(responseChan)
		return nil, fmt.Errorf("request timeout after 30 seconds")
	}
}

// GetQueueStats returns statistics about the Etherscan queue
func (s *EtherscanService) GetQueueStats(ctx context.Context) (map[string]interface{}, error) {
	queueLength, err := storage.RedisClient.LLen(ctx, "etherscan_queue").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get queue length: %w", err)
	}

	return map[string]interface{}{
		"queue_length":  queueLength,
		"rate_limit":    5, // requests per second
		"worker_active": workerCancel != nil,
	}, nil
}
