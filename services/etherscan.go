package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

// ErrorType represents different types of errors for smart handling
type ErrorType int

const (
	ErrorTypeNetwork ErrorType = iota
	ErrorTypeRateLimit
	ErrorTypeDailyLimit
	ErrorTypeAPI
	ErrorTypeUnknown
)

// RequestContext tracks pending requests with proper lifecycle management
type RequestContext struct {
	ID        string
	CreatedAt time.Time
	Context   context.Context
	Cancel    context.CancelFunc
	Response  chan *EtherscanResponse
	Done      chan struct{}
}

// EtherscanRequest represents a queued Etherscan API request
type EtherscanRequest struct {
	ID            string    `json:"id"`
	ChainID       int64     `json:"chain_id"`
	WalletAddress string    `json:"wallet_address"`
	Limit         int       `json:"limit"`
	FromBlock     int64     `json:"from_block"`
	ToBlock       int64     `json:"to_block"`
	CreatedAt     time.Time `json:"created_at"`
	Timeout       int64     `json:"timeout"` // seconds
}

// EtherscanResponse represents the response from Etherscan API
type EtherscanResponse struct {
	Data  []map[string]interface{} `json:"data"`
	Error error                    `json:"error"`
}

// EtherscanWorker represents a worker with its own API key and rate limiting
type EtherscanWorker struct {
	APIKey            string
	WorkerID          int
	RateLimit         int
	Interval          time.Duration
	Processed         int64
	Errors            int64
	ConsecutiveErrors int64
	CircuitOpen       bool
	LastFailure       time.Time
	Mutex             sync.RWMutex
}

// classifyError determines the type of error for smart handling
func classifyError(message string) ErrorType {
	switch {
	case strings.Contains(strings.ToLower(message), "max daily limit reached"):
		return ErrorTypeDailyLimit
	case strings.Contains(strings.ToLower(message), "max rate limit reached"):
		return ErrorTypeDailyLimit
	case strings.Contains(strings.ToLower(message), "max calls per sec"):
		return ErrorTypeRateLimit
	case strings.Contains(strings.ToLower(message), "rate limit"):
		return ErrorTypeRateLimit
	case strings.Contains(strings.ToLower(message), "notok"):
		return ErrorTypeAPI
	case strings.Contains(strings.ToLower(message), "timeout"):
		return ErrorTypeNetwork
	case strings.Contains(strings.ToLower(message), "connection"):
		return ErrorTypeNetwork
	default:
		return ErrorTypeUnknown
	}
}

// QueueStats represents statistics about the Etherscan queue and workers
type QueueStats struct {
	QueueLength     int64 `json:"queue_length"`
	TotalProcessed  int64 `json:"total_processed"`
	TotalErrors     int64 `json:"total_errors"`
	ActiveWorkers   int   `json:"active_workers"`
	RateLimit       int   `json:"rate_limit"`
	WorkerActive    bool  `json:"worker_active"`
	PendingRequests int   `json:"pending_requests"`
}

// EtherscanService provides functionality for interacting with Etherscan API
type EtherscanService struct {
	config *config.EtherscanConfiguration
}

var (
	workerStarted sync.Once
	workerCtx     context.Context
	workerCancel  context.CancelFunc
	workers       []*EtherscanWorker
	workerMutex   sync.RWMutex

	// Request tracking using sync.Map instead of channels
	pendingRequests sync.Map

	// Circuit breaker configuration
	circuitBreakerThreshold = 5
	circuitBreakerTimeout   = 30 * time.Second

	// Request cleanup configuration
	requestCleanupInterval = 1 * time.Minute
	requestTimeout         = 2 * time.Minute
)

// NewEtherscanService creates a new instance of EtherscanService
func NewEtherscanService() (*EtherscanService, error) {
	etherscanConfig := config.EtherscanConfig()
	if etherscanConfig.ApiKey == "" {
		return nil, fmt.Errorf("ETHERSCAN_API_KEY environment variable is required")
	}

	// Start the background workers only once
	workerStarted.Do(func() {
		workerCtx, workerCancel = context.WithCancel(context.Background())
		startMultiKeyEtherscanWorkers(workerCtx, etherscanConfig.ApiKey)
		go startRequestCleanup(workerCtx)
	})

	return &EtherscanService{
		config: etherscanConfig,
	}, nil
}

// startMultiKeyEtherscanWorkers starts multiple workers, one for each API key
func startMultiKeyEtherscanWorkers(ctx context.Context, apiKeys string) {
	// Split API keys by comma
	keys := strings.Split(apiKeys, ",")

	// Clean up keys (remove whitespace)
	var cleanKeys []string
	for _, key := range keys {
		cleanKey := strings.TrimSpace(key)
		if cleanKey != "" {
			cleanKeys = append(cleanKeys, cleanKey)
		}
	}

	if len(cleanKeys) == 0 {
		logger.Errorf("No valid Etherscan API keys found")
		return
	}

	logger.WithFields(logger.Fields{
		"TotalKeys": len(cleanKeys),
		"Keys":      cleanKeys,
	}).Info("Starting multi-key Etherscan workers")

	// Create a worker for each API key
	workerMutex.Lock()
	workers = make([]*EtherscanWorker, len(cleanKeys))
	workerMutex.Unlock()

	for i, apiKey := range cleanKeys {
		worker := &EtherscanWorker{
			APIKey:    apiKey,
			WorkerID:  i,
			RateLimit: 5, // Default rate limit, will be overridden by chain config
			Interval:  time.Duration(1000/5) * time.Millisecond,
		}

		workerMutex.Lock()
		workers[i] = worker
		workerMutex.Unlock()

		// Start worker in its own goroutine
		go worker.start(ctx)
	}

	logger.WithFields(logger.Fields{
		"TotalWorkers": len(cleanKeys),
		"TotalRate":    len(cleanKeys) * 5,
	}).Info("Multi-key Etherscan workers started successfully")
}

// startRequestCleanup periodically cleans up stale requests
func startRequestCleanup(ctx context.Context) {
	ticker := time.NewTicker(requestCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanupStaleRequests()
		}
	}
}

// cleanupStaleRequests removes stale requests from tracking
func cleanupStaleRequests() {
	now := time.Now()
	var cleaned int

	pendingRequests.Range(func(key, value interface{}) bool {
		reqCtx, ok := value.(*RequestContext)
		if !ok {
			pendingRequests.Delete(key)
			return true
		}

		// Check if request is too old or context is done
		if now.Sub(reqCtx.CreatedAt) > requestTimeout || reqCtx.Context.Err() != nil {
			reqCtx.Cancel()
			close(reqCtx.Done)
			pendingRequests.Delete(key)
			cleaned++
		}
		return true
	})

	if cleaned > 0 {
		logger.WithFields(logger.Fields{
			"CleanedRequests": cleaned,
		}).Infof("Cleaned up stale requests")
	}
}

// start starts a single worker
func (w *EtherscanWorker) start(ctx context.Context) {
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()

	logger.WithFields(logger.Fields{
		"WorkerID":  w.WorkerID,
		"APIKey":    w.APIKey[:8] + "...",
		"RateLimit": w.RateLimit,
		"Interval":  w.Interval,
	}).Info("Etherscan worker started")

	for {
		select {
		case <-ctx.Done():
			logger.WithFields(logger.Fields{
				"WorkerID": w.WorkerID,
			}).Info("Etherscan worker stopped")
			return
		case <-ticker.C:
			// Check circuit breaker before processing
			if w.isCircuitOpen() {
				continue
			}

			// Process one request from the queue
			if err := w.processNextRequest(ctx); err != nil {
				if err.Error() != "no requests in queue" {
					w.recordError()
					logger.WithFields(logger.Fields{
						"WorkerID": w.WorkerID,
						"Error":    fmt.Sprintf("%v", err),
					}).Errorf("Failed to process Etherscan request")
				}
			} else {
				w.recordSuccess()

				// Log stats every 100 processed requests
				if w.Processed%100 == 0 {
					logger.WithFields(logger.Fields{
						"WorkerID":  w.WorkerID,
						"Processed": w.Processed,
						"Errors":    w.Errors,
					}).Infof("Etherscan worker stats")
				}
			}
		}
	}
}

// isCircuitOpen checks if the circuit breaker is open
func (w *EtherscanWorker) isCircuitOpen() bool {
	w.Mutex.RLock()
	defer w.Mutex.RUnlock()

	if w.CircuitOpen && time.Since(w.LastFailure) < circuitBreakerTimeout {
		return true
	}

	if w.CircuitOpen && time.Since(w.LastFailure) >= circuitBreakerTimeout {
		// Reset circuit breaker
		w.Mutex.Lock()
		w.CircuitOpen = false
		w.Mutex.Unlock()
		logger.WithFields(logger.Fields{
			"WorkerID": w.WorkerID,
		}).Infof("Circuit breaker reset")
	}

	return false
}

// recordError records an error and potentially opens circuit breaker
func (w *EtherscanWorker) recordError() {
	w.Mutex.Lock()
	defer w.Mutex.Unlock()

	w.Errors++
	w.ConsecutiveErrors++
	w.LastFailure = time.Now()

	if w.ConsecutiveErrors >= int64(circuitBreakerThreshold) {
		w.CircuitOpen = true
		logger.WithFields(logger.Fields{
			"WorkerID":          w.WorkerID,
			"TotalErrors":       w.Errors,
			"ConsecutiveErrors": w.ConsecutiveErrors,
		}).Warnf("Circuit breaker opened")
	}
}

// recordSuccess records a successful request
func (w *EtherscanWorker) recordSuccess() {
	w.Mutex.Lock()
	defer w.Mutex.Unlock()

	w.Processed++
	// Reset consecutive errors on success, but keep total error count
	w.ConsecutiveErrors = 0
}

// processNextRequest processes the next request from the queue using this worker's API key
func (w *EtherscanWorker) processNextRequest(ctx context.Context) error {
	// Get the next request from the queue
	requestData, err := storage.RedisClient.LPop(ctx, "etherscan_queue").Result()
	if err != nil {
		return fmt.Errorf("no requests in queue")
	}

	var request EtherscanRequest
	if err := json.Unmarshal([]byte(requestData), &request); err != nil {
		return fmt.Errorf("failed to unmarshal request: %w", err)
	}

	// Check if request is too old
	if time.Since(request.CreatedAt) > requestTimeout {
		logger.WithFields(logger.Fields{
			"WorkerID":  w.WorkerID,
			"RequestID": request.ID,
			"Age":       time.Since(request.CreatedAt),
		}).Warnf("Skipping old request")
		return nil
	}

	// Make the actual API call using this worker's API key
	data, err := w.makeEtherscanAPICall(request)

	// Find and notify the pending request
	if reqCtxValue, exists := pendingRequests.Load(request.ID); exists {
		reqCtx, ok := reqCtxValue.(*RequestContext)
		if ok {
			// Send response through the channel
			select {
			case reqCtx.Response <- &EtherscanResponse{Data: data, Error: err}:
				// Response sent successfully
			default:
				// Channel is full or closed
				logger.WithFields(logger.Fields{
					"WorkerID":  w.WorkerID,
					"RequestID": request.ID,
				}).Debugf("Could not send response to request (channel full or closed)")
			}

			// Clean up the request context
			reqCtx.Cancel()
			close(reqCtx.Done)
			pendingRequests.Delete(request.ID)
		}
	}

	return nil
}

// makeEtherscanAPICall makes the actual API call to Etherscan using this worker's API key
func (w *EtherscanWorker) makeEtherscanAPICall(request EtherscanRequest) ([]map[string]interface{}, error) {

	// Build query parameters for Etherscan API
	params := map[string]string{
		"module":  "account",
		"action":  "tokentx",
		"address": request.WalletAddress,
		"page":    "1",
		"offset":  fmt.Sprintf("%d", request.Limit),
		"sort":    "desc",
		"apikey":  w.APIKey,
		"chainid": fmt.Sprintf("%d", request.ChainID), // Chain ID is passed as parameter
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

	// Check HTTP status code
	if res.RawResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d for chain %d, address %s",
			res.RawResponse.StatusCode, request.ChainID, request.WalletAddress)
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

		// Classify the error for smart handling and logging
		errorType := classifyError(message)

		// Log the error type for monitoring and debugging
		logger.Debugf("Etherscan API error classified as %v for chain %d, address %s: %s",
			errorType, request.ChainID, request.WalletAddress, message)

		return nil, fmt.Errorf("etherscan API error for chain %d, address %s: %s",
			request.ChainID, request.WalletAddress, message)
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

// validateWalletAddress validates the wallet address format
func validateWalletAddress(address string) error {
	if address == "" {
		return fmt.Errorf("wallet address cannot be empty")
	}
	if !strings.HasPrefix(address, "0x") {
		return fmt.Errorf("wallet address must start with 0x")
	}
	if len(address) != 42 {
		return fmt.Errorf("wallet address must be 42 characters long")
	}
	return nil
}

// validateChainID validates the chain ID
func validateChainID(chainID int64) error {
	if chainID <= 0 {
		return fmt.Errorf("chain ID must be positive")
	}
	return nil
}

// GetAddressTransactionHistoryImmediate fetches transaction history immediately without queuing
func (s *EtherscanService) GetAddressTransactionHistoryImmediate(ctx context.Context, chainID int64, walletAddress string, limit int, fromBlock int64, toBlock int64) ([]map[string]interface{}, error) {
	// Input validation
	if err := validateWalletAddress(walletAddress); err != nil {
		return nil, fmt.Errorf("invalid wallet address: %w", err)
	}
	if err := validateChainID(chainID); err != nil {
		return nil, fmt.Errorf("invalid chain ID: %w", err)
	}
	if limit <= 0 || limit > 1000 {
		return nil, fmt.Errorf("limit must be between 1 and 1000")
	}

	// Use the first available worker for immediate processing
	workerMutex.RLock()
	var worker *EtherscanWorker
	if len(workers) > 0 {
		worker = workers[0]
	}
	workerMutex.RUnlock()

	if worker == nil {
		return nil, fmt.Errorf("no Etherscan workers available")
	}

	request := EtherscanRequest{
		ID:            fmt.Sprintf("%d_%s_%d_%d_%d", chainID, walletAddress, limit, fromBlock, toBlock),
		ChainID:       chainID,
		WalletAddress: walletAddress,
		Limit:         limit,
		FromBlock:     fromBlock,
		ToBlock:       toBlock,
	}
	return worker.makeEtherscanAPICall(request)
}

// GetAddressTransactionHistory fetches transaction history for any address from Etherscan API
func (s *EtherscanService) GetAddressTransactionHistory(ctx context.Context, chainID int64, walletAddress string, limit int, fromBlock int64, toBlock int64) ([]map[string]interface{}, error) {
	// Input validation
	if err := validateWalletAddress(walletAddress); err != nil {
		return nil, fmt.Errorf("invalid wallet address: %w", err)
	}
	if err := validateChainID(chainID); err != nil {
		return nil, fmt.Errorf("invalid chain ID: %w", err)
	}
	if limit <= 0 || limit > 1000 {
		return nil, fmt.Errorf("limit must be between 1 and 1000")
	}

	// Create a unique request ID
	requestID := fmt.Sprintf("%d_%s_%d_%d_%d", chainID, walletAddress, limit, fromBlock, toBlock)

	// Create request context with proper lifecycle management
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Create response channel
	responseChan := make(chan *EtherscanResponse, 1)
	doneChan := make(chan struct{})

	// Create the request context
	requestContext := &RequestContext{
		ID:        requestID,
		CreatedAt: time.Now(),
		Context:   reqCtx,
		Cancel:    cancel,
		Response:  responseChan,
		Done:      doneChan,
	}

	// Track the pending request
	pendingRequests.Store(requestID, requestContext)

	// Create the request
	request := EtherscanRequest{
		ID:            requestID,
		ChainID:       chainID,
		WalletAddress: walletAddress,
		Limit:         limit,
		FromBlock:     fromBlock,
		ToBlock:       toBlock,
		CreatedAt:     time.Now(),
		Timeout:       30,
	}

	// Serialize and queue the request
	requestData, err := json.Marshal(request)
	if err != nil {
		pendingRequests.Delete(requestID)
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Add to queue
	if err := storage.RedisClient.RPush(ctx, "etherscan_queue", requestData).Err(); err != nil {
		pendingRequests.Delete(requestID)
		return nil, fmt.Errorf("failed to queue request: %w", err)
	}

	// Wait for response with proper context handling
	select {
	case response := <-responseChan:
		if response.Error != nil {
			return nil, response.Error
		}
		return response.Data, nil
	case <-reqCtx.Done():
		// Context was cancelled or timed out
		pendingRequests.Delete(requestID)
		return nil, reqCtx.Err()
	case <-doneChan:
		// Request was completed and cleaned up
		return nil, fmt.Errorf("request was cleaned up")
	}
}

// GetAddressTransactionHistoryWithBypass fetches transaction history with option to bypass queue
func (s *EtherscanService) GetAddressTransactionHistoryWithBypass(ctx context.Context, chainID int64, walletAddress string, limit int, fromBlock int64, toBlock int64, bypassQueue bool) ([]map[string]interface{}, error) {
	// Input validation
	if err := validateWalletAddress(walletAddress); err != nil {
		return nil, fmt.Errorf("invalid wallet address: %w", err)
	}
	if err := validateChainID(chainID); err != nil {
		return nil, fmt.Errorf("invalid chain ID: %w", err)
	}
	if limit <= 0 || limit > 1000 {
		return nil, fmt.Errorf("limit must be between 1 and 1000")
	}

	// If bypassing queue, make the API call immediately
	if bypassQueue {
		request := EtherscanRequest{
			ID:            fmt.Sprintf("%d_%s_%d_%d_%d", chainID, walletAddress, limit, fromBlock, toBlock),
			ChainID:       chainID,
			WalletAddress: walletAddress,
			Limit:         limit,
			FromBlock:     fromBlock,
			ToBlock:       toBlock,
		}

		// Use the first available worker for immediate processing
		workerMutex.RLock()
		var worker *EtherscanWorker
		if len(workers) > 0 {
			worker = workers[0]
		}
		workerMutex.RUnlock()

		if worker == nil {
			return nil, fmt.Errorf("no Etherscan workers available")
		}

		return worker.makeEtherscanAPICall(request)
	}

	// Use the regular queued method
	return s.GetAddressTransactionHistory(ctx, chainID, walletAddress, limit, fromBlock, toBlock)
}

// GetQueueStats returns statistics about the Etherscan queue
func (s *EtherscanService) GetQueueStats(ctx context.Context) (*QueueStats, error) {
	// Get queue length
	queueLength, err := storage.RedisClient.LLen(ctx, "etherscan_queue").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get queue length: %w", err)
	}

	// Get worker stats
	workerMutex.RLock()
	defer workerMutex.RUnlock()

	var totalProcessed, totalErrors int64
	var activeWorkers int

	for _, worker := range workers {
		if worker != nil {
			worker.Mutex.RLock()
			totalProcessed += worker.Processed
			totalErrors += worker.Errors
			worker.Mutex.RUnlock()
			activeWorkers++
		}
	}

	// Count pending requests
	var pendingCount int
	pendingRequests.Range(func(key, value interface{}) bool {
		pendingCount++
		return true
	})

	// Calculate total rate limit across all workers
	totalRateLimit := activeWorkers * 5 // Default 5 req/sec per worker

	return &QueueStats{
		QueueLength:     queueLength,
		TotalProcessed:  totalProcessed,
		TotalErrors:     totalErrors,
		ActiveWorkers:   activeWorkers,
		RateLimit:       totalRateLimit,
		WorkerActive:    activeWorkers > 0,
		PendingRequests: pendingCount,
	}, nil
}

// StopEtherscanWorkers stops all background workers gracefully
func StopEtherscanWorkers() {
	if workerCancel != nil {
		// Signal all workers to stop
		workerCancel()
		logger.Infof("Etherscan workers shutdown initiated")

		// Wait a bit for workers to finish processing
		time.Sleep(2 * time.Second)

		// Clean up any remaining pending requests
		var keysToDelete []interface{}
		pendingRequests.Range(func(key, value interface{}) bool {
			keysToDelete = append(keysToDelete, key)
			return true
		})
		for _, key := range keysToDelete {
			if reqCtx, ok := pendingRequests.Load(key); ok {
				if reqCtx, ok := reqCtx.(*RequestContext); ok {
					reqCtx.Cancel()
					close(reqCtx.Done)
				}
			}
			pendingRequests.Delete(key)
		}

		logger.Infof("Etherscan workers shutdown completed")
	}
}

// GetEtherscanServiceStatus returns the current status of workers
func GetEtherscanServiceStatus() map[string]interface{} {
	workerMutex.RLock()
	defer workerMutex.RUnlock()

	var activeWorkers int
	var totalProcessed, totalErrors int64

	for _, worker := range workers {
		if worker != nil {
			worker.Mutex.RLock()
			totalProcessed += worker.Processed
			totalErrors += worker.Errors
			worker.Mutex.RUnlock()
			activeWorkers++
		}
	}

	// Count pending requests
	var pendingCount int
	pendingRequests.Range(func(key, value interface{}) bool {
		pendingCount++
		return true
	})

	return map[string]interface{}{
		"workers_active":     activeWorkers,
		"total_processed":    totalProcessed,
		"total_errors":       totalErrors,
		"shutdown_initiated": workerCancel == nil,
		"pending_requests":   pendingCount,
	}
}
