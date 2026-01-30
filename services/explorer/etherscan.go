package explorer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
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
	ExhaustedUntil    time.Time
	BackoffInterval   time.Duration
	Mutex             sync.RWMutex
}

// classifyError determines the type of error for smart handling
func classifyError(message string) ErrorType {
	switch {
	case strings.Contains(strings.ToLower(message), "max daily limit reached"):
		return ErrorTypeDailyLimit
	case strings.Contains(strings.ToLower(message), "max rate limit reached"):
		return ErrorTypeRateLimit
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
	case strings.Contains(strings.ToLower(message), "too many invalid api key attempts"):
		return ErrorTypeAPI
	case strings.Contains(strings.ToLower(message), "invalid api key"):
		return ErrorTypeAPI
	case strings.Contains(strings.ToLower(message), "missing required parameter"):
		return ErrorTypeAPI
	case strings.Contains(strings.ToLower(message), "invalid module name"):
		return ErrorTypeAPI
	default:
		return ErrorTypeUnknown
	}
}

// timeUntilMidnightUTC calculates the duration until the next midnight UTC
func timeUntilMidnightUTC() time.Duration {
	now := time.Now().UTC()
	tomorrow := now.Truncate(24 * time.Hour).Add(24 * time.Hour)
	return tomorrow.Sub(now)
}

// markExhausted marks the worker as unavailable for the specified duration
func (w *EtherscanWorker) markExhausted(duration time.Duration) {
	w.Mutex.Lock()
	defer w.Mutex.Unlock()
	w.ExhaustedUntil = time.Now().Add(duration)
	logger.Debugf("Worker %d marked as exhausted until %v", w.WorkerID, w.ExhaustedUntil)
}

// increaseBackoff temporarily increases the worker's backoff interval
func (w *EtherscanWorker) increaseBackoff() {
	w.Mutex.Lock()
	defer w.Mutex.Unlock()
	// Double the backoff interval, but cap at 5 seconds
	if w.BackoffInterval == 0 {
		w.BackoffInterval = 500 * time.Millisecond
	} else {
		w.BackoffInterval = time.Duration(float64(w.BackoffInterval) * 1.5)
		if w.BackoffInterval > 5*time.Second {
			w.BackoffInterval = 5 * time.Second
		}
	}
	logger.Debugf("Worker %d backoff increased to %v", w.WorkerID, w.BackoffInterval)
}

// isExhausted checks if the worker should be skipped
func (w *EtherscanWorker) isExhausted() bool {
	w.Mutex.RLock()
	defer w.Mutex.RUnlock()
	return time.Now().Before(w.ExhaustedUntil)
}

// QueueStats represents statistics about the Etherscan queue and workers
type QueueStats struct {
	QueueLength       int64     `json:"queue_length"`
	TotalProcessed    int64     `json:"total_processed"`
	TotalErrors       int64     `json:"total_errors"`
	ActiveWorkers     int       `json:"active_workers"`
	RateLimit         int       `json:"rate_limit"`
	WorkerActive      bool      `json:"worker_active"`
	PendingRequests   int       `json:"pending_requests"`
	RateLimitErrors   int64     `json:"rate_limit_errors"`
	DailyLimitErrors  int64     `json:"daily_limit_errors"`
	APIErrors         int64     `json:"api_errors"`
	NetworkErrors     int64     `json:"network_errors"`
	DailyCalls        int64     `json:"daily_calls"`
	DailyLimit        int64     `json:"daily_limit"`
	DailyUsagePercent float64   `json:"daily_usage_percent"`
	NextResetTime     time.Time `json:"next_reset_time"`
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

	// Request deduplication: track queued request IDs to prevent duplicates
	queuedRequestIDs sync.Map

	// Circuit breaker configuration
	circuitBreakerThreshold = 5
	circuitBreakerTimeout   = 30 * time.Second

	// Chain-specific circuit breakers to avoid wasting API calls on failing chains
	chainCircuitBreakers sync.Map // chainID -> *ChainCircuitBreaker

	// Request cleanup configuration
	// Cleanup runs every 5 minutes - workers handle most cleanup naturally, so less frequent cleanup is sufficient
	requestCleanupInterval = 5 * time.Minute
	requestTimeout         = 60 * time.Second

	// Daily limit tracking (configured via ETHERSCAN_DAILY_LIMIT env var)
	dailyLimitCalls       int64 // Set from config, defaults to 100k for Free tier
	dailyCallsCounter     int64 // Atomic counter for calls made today
	dailyLimitResetTime   time.Time
	lastDailyLimitWarning time.Time // Throttle daily limit warnings

	// Error type counters for monitoring
	rateLimitErrorsCounter  int64
	dailyLimitErrorsCounter int64
	apiErrorsCounter        int64
	networkErrorsCounter    int64
)

// ChainCircuitBreaker tracks circuit breaker state per chain
type ChainCircuitBreaker struct {
	ChainID           int64
	ConsecutiveErrors int64
	LastFailure       time.Time
	Open              bool
	Mutex             sync.RWMutex
}

// getChainCircuitBreaker gets or creates a circuit breaker for a specific chain
func getChainCircuitBreaker(chainID int64) *ChainCircuitBreaker {
	if cb, exists := chainCircuitBreakers.Load(chainID); exists {
		return cb.(*ChainCircuitBreaker)
	}

	cb := &ChainCircuitBreaker{ChainID: chainID}
	chainCircuitBreakers.Store(chainID, cb)
	return cb
}

// NewEtherscanService creates a new instance of EtherscanService
func NewEtherscanService() (*EtherscanService, error) {
	etherscanConfig := config.EtherscanConfig()
	if etherscanConfig.ApiKey == "" {
		return nil, fmt.Errorf("ETHERSCAN_API_KEY environment variable is required")
	}

	// Start the background workers only once
	workerStarted.Do(func() {
		workerCtx, workerCancel = context.WithCancel(context.Background())
		// Initialize daily limit from config
		if etherscanConfig.DailyLimit > 0 {
			atomic.StoreInt64(&dailyLimitCalls, int64(etherscanConfig.DailyLimit))
		} else {
			// Fallback to 100k if not configured
			atomic.StoreInt64(&dailyLimitCalls, 100000)
		}
		startMultiKeyEtherscanWorkers(workerCtx, etherscanConfig.ApiKey)
		go startRequestCleanup(workerCtx)
		go startDailyLimitReset(workerCtx)
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

	// Get rate limit from config (default: 3 req/sec for free tier, override in prod with a paid plan)
	etherscanConfig := config.EtherscanConfig()
	rateLimit := etherscanConfig.RateLimit
	if rateLimit <= 0 {
		rateLimit = 3 // Safety fallback to 3 req/sec if somehow 0 or negative
	}

	// Create a worker for each API key
	workerMutex.Lock()
	workers = make([]*EtherscanWorker, len(cleanKeys))
	workerMutex.Unlock()

	for i, apiKey := range cleanKeys {
		worker := &EtherscanWorker{
			APIKey:    apiKey,
			WorkerID:  i,
			RateLimit: rateLimit, // Use configured rate limit (default: 3 free tier, set to a paid plan value in prod)
			Interval:  time.Duration(1000/rateLimit) * time.Millisecond,
		}

		workerMutex.Lock()
		workers[i] = worker
		workerMutex.Unlock()

		// Start worker in its own goroutine
		go worker.start(ctx)
	}

	logger.WithFields(logger.Fields{
		"TotalWorkers":  len(cleanKeys),
		"TotalRate":     len(cleanKeys) * rateLimit,
		"RatePerWorker": rateLimit,
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
			cleanupStaleQueueEntries(ctx)
			cleanupQueuedRequestIDs()
		}
	}
}

// startDailyLimitReset resets daily call counter at midnight UTC
func startDailyLimitReset(ctx context.Context) {
	// Calculate time until next midnight UTC
	now := time.Now().UTC()
	nextMidnight := now.Truncate(24 * time.Hour).Add(24 * time.Hour)
	initialDelay := nextMidnight.Sub(now)

	// Set initial reset time
	dailyLimitResetTime = nextMidnight

	// Wait until midnight
	time.Sleep(initialDelay)

	// Reset counter and schedule next reset
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			atomic.StoreInt64(&dailyCallsCounter, 0)
			dailyLimitResetTime = time.Now().UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
			logger.Infof("Daily Etherscan API call counter reset. Limit: %d calls", atomic.LoadInt64(&dailyLimitCalls))
		}
	}
}

// cleanupQueuedRequestIDs removes old entries from queuedRequestIDs map
func cleanupQueuedRequestIDs() {
	now := time.Now()
	var cleaned int

	queuedRequestIDs.Range(func(key, value interface{}) bool {
		queuedAt, ok := value.(time.Time)
		if !ok {
			queuedRequestIDs.Delete(key)
			cleaned++
			return true
		}

		// Remove entries older than requestTimeout
		if now.Sub(queuedAt) > requestTimeout {
			queuedRequestIDs.Delete(key)
			cleaned++
		}
		return true
	})

	if cleaned > 0 {
		logger.WithFields(logger.Fields{
			"CleanedIDs": cleaned,
		}).Debugf("Cleaned up queued request IDs")
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

// cleanupStaleQueueEntries removes old requests from Redis queue
// Optimized: Only checks a limited number of items from the front of the queue
// instead of loading the entire queue into memory
func cleanupStaleQueueEntries(ctx context.Context) {
	queueKey := "etherscan_queue"

	// Only check first 100 items to avoid loading entire queue (O(n) operation)
	// Stale items will naturally be processed and removed by workers
	maxCheckItems := 100
	items, err := storage.RedisClient.LRange(ctx, queueKey, 0, int64(maxCheckItems-1)).Result()
	if err != nil {
		logger.Errorf("Failed to get queue items for cleanup: %v", err)
		return
	}

	if len(items) == 0 {
		return
	}

	var staleCount int
	now := time.Now()

	// Process items from front of queue (oldest first)
	for _, item := range items {
		var request EtherscanRequest
		if json.Unmarshal([]byte(item), &request) != nil {
			continue
		}

		// Check if request is stale
		if now.Sub(request.CreatedAt) > requestTimeout {
			// Remove this specific stale item using LRem
			// Note: LRem removes matching elements, so we need to be careful
			// Since we're checking from front, this is safe
			if err := storage.RedisClient.LRem(ctx, queueKey, 1, item).Err(); err == nil {
				staleCount++
			}
		} else {
			// Since queue is FIFO, if we hit a non-stale item, we can stop
			// (all older items would have been stale)
			break
		}
	}

	if staleCount > 0 {
		logger.WithFields(logger.Fields{
			"StaleRequests": staleCount,
			"CheckedItems":  len(items),
		}).Infof("Cleaned up stale queue entries")
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

	consecutiveEmptyPolls := 0
	maxEmptyPolls := 10 // After 10 empty polls, increase polling interval

	for {
		select {
		case <-ctx.Done():
			logger.WithFields(logger.Fields{
				"WorkerID": w.WorkerID,
			}).Info("Etherscan worker stopped")
			return
		case <-ticker.C:
			// Check if worker is exhausted
			if w.isExhausted() {
				continue
			}

			// Check circuit breaker before processing
			if w.isCircuitOpen() {
				continue
			}

			// Check daily limit before processing
			dailyLimit := atomic.LoadInt64(&dailyLimitCalls)
			if atomic.LoadInt64(&dailyCallsCounter) >= dailyLimit {
				logger.Warnf("Daily Etherscan API limit reached (%d/%d). Worker %d paused until reset.",
					atomic.LoadInt64(&dailyCallsCounter), dailyLimit, w.WorkerID)
				// Wait until next reset
				time.Sleep(time.Until(dailyLimitResetTime))
				continue
			}

			// Use dynamic interval based on backoff
			currentInterval := w.Interval
			w.Mutex.RLock()
			if w.BackoffInterval > 0 {
				currentInterval = w.BackoffInterval
			}
			w.Mutex.RUnlock()

			// Process one request from the queue
			err := w.processNextRequest(ctx)
			if err != nil {
				if err.Error() == "no requests in queue" {
					consecutiveEmptyPolls++
					// If queue is empty, increase polling interval to reduce CPU/Redis load
					if consecutiveEmptyPolls >= maxEmptyPolls {
						// Poll every 1 second when queue is consistently empty
						ticker.Reset(1 * time.Second)
					}
					continue
				}
				// Reset empty poll counter on error
				consecutiveEmptyPolls = 0
				ticker.Reset(currentInterval)
				w.recordError()
				logger.WithFields(logger.Fields{
					"WorkerID": w.WorkerID,
					"Error":    fmt.Sprintf("%v", err),
				}).Errorf("Failed to process Etherscan request")
			} else {
				// Reset empty poll counter and interval on success
				consecutiveEmptyPolls = 0
				ticker.Reset(currentInterval)
				w.recordSuccess()

				// Increment daily call counter
				atomic.AddInt64(&dailyCallsCounter, 1)

				// Log worker stats periodically to monitor health without excessive logging
				// At 10 req/sec, logs approximately every 2 minutes
				if w.Processed%1000 == 0 {
					dailyCalls := atomic.LoadInt64(&dailyCallsCounter)
					dailyLimit := atomic.LoadInt64(&dailyLimitCalls)
					logger.WithFields(logger.Fields{
						"WorkerID":   w.WorkerID,
						"Processed":  w.Processed,
						"Errors":     w.Errors,
						"DailyCalls": dailyCalls,
						"DailyLimit": dailyLimit,
					}).Infof("Etherscan worker stats")
				}

				// Warn if approaching daily limit - only at thresholds (80%, 90%, 95%) and throttled
				dailyCalls := atomic.LoadInt64(&dailyCallsCounter)
				dailyLimit := atomic.LoadInt64(&dailyLimitCalls)
				if dailyLimit > 0 {
					usagePercent := float64(dailyCalls) / float64(dailyLimit) * 100
					// Warn at specific thresholds to provide actionable alerts without log spam
					shouldWarn := (usagePercent >= 80 && usagePercent < 90) ||
						(usagePercent >= 90 && usagePercent < 95) ||
						(usagePercent >= 95)

					if shouldWarn {
						now := time.Now()
						// Throttle warnings to once per 5 minutes to keep log volume manageable
						if now.Sub(lastDailyLimitWarning) >= 5*time.Minute {
							lastDailyLimitWarning = now
							logger.Warnf("Approaching daily Etherscan API limit: %d/%d calls used (%.1f%%)",
								dailyCalls, dailyLimit, usagePercent)
						}
					}
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
	// Reset backoff interval on success
	w.BackoffInterval = 0
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

	// Check if request was cancelled before processing
	if reqCtxValue, exists := pendingRequests.Load(request.ID); exists {
		if reqCtx, ok := reqCtxValue.(*RequestContext); ok {
			if reqCtx.Context.Err() != nil {
				// Request was cancelled, clean up and skip
				pendingRequests.Delete(request.ID)
				queuedRequestIDs.Delete(request.ID)
				logger.WithFields(logger.Fields{
					"WorkerID":  w.WorkerID,
					"RequestID": request.ID,
				}).Debugf("Skipping cancelled request")
				return nil
			}
		}
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

	// Check chain-specific circuit breaker before making API call
	chainCB := getChainCircuitBreaker(request.ChainID)
	chainCB.Mutex.RLock()
	if chainCB.Open && time.Since(chainCB.LastFailure) < circuitBreakerTimeout {
		chainCB.Mutex.RUnlock()
		// Circuit breaker is open for this chain, skip to avoid wasting API call
		logger.WithFields(logger.Fields{
			"WorkerID":  w.WorkerID,
			"RequestID": request.ID,
			"ChainID":   request.ChainID,
		}).Warnf("Skipping request - circuit breaker open for chain")
		// Notify the pending request of the error
		if reqCtxValue, exists := pendingRequests.Load(request.ID); exists {
			if reqCtx, ok := reqCtxValue.(*RequestContext); ok {
				select {
				case reqCtx.Response <- &EtherscanResponse{
					Data:  nil,
					Error: fmt.Errorf("circuit breaker open for chain %d", request.ChainID),
				}:
				default:
				}
				reqCtx.Cancel()
				close(reqCtx.Done)
				pendingRequests.Delete(request.ID)
				queuedRequestIDs.Delete(request.ID)
			}
		}
		return nil
	}
	chainCB.Mutex.RUnlock()

	// Make the actual API call using this worker's API key
	data, err := w.makeEtherscanAPICall(request)

	// Update chain-specific circuit breaker based on result (chainCB already declared above)
	if err != nil {
		// Record error in chain circuit breaker
		chainCB.Mutex.Lock()
		chainCB.ConsecutiveErrors++
		chainCB.LastFailure = time.Now()
		if chainCB.ConsecutiveErrors >= int64(circuitBreakerThreshold) {
			chainCB.Open = true
			logger.WithFields(logger.Fields{
				"ChainID":           request.ChainID,
				"ConsecutiveErrors": chainCB.ConsecutiveErrors,
			}).Warnf("Circuit breaker opened for chain %d", request.ChainID)
		}
		chainCB.Mutex.Unlock()
	} else {
		// Reset chain circuit breaker on success
		chainCB.Mutex.Lock()
		chainCB.ConsecutiveErrors = 0
		chainCB.Open = false
		chainCB.Mutex.Unlock()
	}

	// Smart error handling based on error type
	if err != nil {
		errorType := classifyError(err.Error())
		switch errorType {
		case ErrorTypeDailyLimit:
			// Mark this worker as exhausted until midnight UTC
			resetDuration := timeUntilMidnightUTC()
			w.markExhausted(resetDuration)
			atomic.AddInt64(&dailyLimitErrorsCounter, 1)
			logger.WithFields(logger.Fields{
				"WorkerID":  w.WorkerID,
				"RequestID": request.ID,
				"ErrorType": errorType,
			}).Warnf("Worker marked as exhausted due to daily limit")
		case ErrorTypeRateLimit:
			// Increase backoff interval temporarily
			w.increaseBackoff()
			atomic.AddInt64(&rateLimitErrorsCounter, 1)
			logger.WithFields(logger.Fields{
				"WorkerID":  w.WorkerID,
				"RequestID": request.ID,
				"ErrorType": errorType,
			}).Warnf("Worker backoff increased due to rate limit")
		case ErrorTypeAPI:
			// Log API errors for monitoring
			atomic.AddInt64(&apiErrorsCounter, 1)
			logger.WithFields(logger.Fields{
				"WorkerID":  w.WorkerID,
				"RequestID": request.ID,
				"ErrorType": errorType,
				"ChainID":   request.ChainID,
				"Address":   request.WalletAddress,
				"Error":     err.Error(),
			}).Errorf("Etherscan API error for chain %d", request.ChainID)
		case ErrorTypeNetwork:
			// Network errors are usually temporary
			atomic.AddInt64(&networkErrorsCounter, 1)
			logger.WithFields(logger.Fields{
				"WorkerID":  w.WorkerID,
				"RequestID": request.ID,
				"ErrorType": errorType,
			}).Warnf("Network error occurred: %v", err)
		default:
			// Unknown errors
			logger.WithFields(logger.Fields{
				"WorkerID":  w.WorkerID,
				"RequestID": request.ID,
				"ErrorType": errorType,
				"ChainID":   request.ChainID,
				"Address":   request.WalletAddress,
				"Error":     err.Error(),
			}).Errorf("Etherscan unknown error for chain %d", request.ChainID)
		}
	}

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
			queuedRequestIDs.Delete(request.ID)
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

	// Use the first available non-exhausted worker for immediate processing
	workerMutex.RLock()
	var worker *EtherscanWorker
	for _, w := range workers {
		if !w.isExhausted() {
			worker = w
			break
		}
	}
	// If all workers are exhausted, use the first one anyway
	if worker == nil && len(workers) > 0 {
		worker = workers[0]
		logger.Warnf("All workers are exhausted, using worker %d anyway", workers[0].WorkerID)
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

	// Check for duplicate request - if same request ID is already queued, reuse existing pending request
	if existingCtx, exists := pendingRequests.Load(requestID); exists {
		// Request already pending, reuse the existing request context
		existingReqCtx, ok := existingCtx.(*RequestContext)
		if ok {
			logger.WithFields(logger.Fields{
				"RequestID": requestID,
			}).Debugf("Duplicate request detected, reusing existing request")
			// Wait for the existing request's response
			select {
			case response := <-existingReqCtx.Response:
				if response.Error != nil {
					return nil, response.Error
				}
				return response.Data, nil
			case <-reqCtx.Done():
				return nil, reqCtx.Err()
			case <-existingReqCtx.Context.Done():
				return nil, existingReqCtx.Context.Err()
			}
		}
	}

	// Check if request ID is already in queue (but not yet processed)
	if _, queued := queuedRequestIDs.LoadOrStore(requestID, time.Now()); queued {
		// Request is queued but not yet in pendingRequests, wait a bit and check again
		// This handles race condition where request is queued but worker hasn't picked it up yet
		logger.WithFields(logger.Fields{
			"RequestID": requestID,
		}).Debugf("Request already queued, waiting for processing")
		// Fall through to wait for response below
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
		queuedRequestIDs.Delete(requestID)
		pendingRequests.Delete(requestID)
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Add to queue
	if err := storage.RedisClient.RPush(ctx, "etherscan_queue", requestData).Err(); err != nil {
		queuedRequestIDs.Delete(requestID)
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
		queuedRequestIDs.Delete(requestID)
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
	// Get rate limit from service config (already loaded)
	var rateLimitPerWorker int
	if s.config != nil && s.config.RateLimit > 0 {
		rateLimitPerWorker = s.config.RateLimit
	} else {
		rateLimitPerWorker = 3 // Default to 3 req/sec for free tier
	}
	totalRateLimit := activeWorkers * rateLimitPerWorker

	dailyCalls := atomic.LoadInt64(&dailyCallsCounter)
	dailyLimit := atomic.LoadInt64(&dailyLimitCalls)
	var dailyUsagePercent float64
	if dailyLimit > 0 {
		dailyUsagePercent = float64(dailyCalls) / float64(dailyLimit) * 100
	}

	return &QueueStats{
		QueueLength:       queueLength,
		TotalProcessed:    totalProcessed,
		TotalErrors:       totalErrors,
		ActiveWorkers:     activeWorkers,
		RateLimit:         totalRateLimit,
		WorkerActive:      activeWorkers > 0,
		PendingRequests:   pendingCount,
		RateLimitErrors:   atomic.LoadInt64(&rateLimitErrorsCounter),
		DailyLimitErrors:  atomic.LoadInt64(&dailyLimitErrorsCounter),
		APIErrors:         atomic.LoadInt64(&apiErrorsCounter),
		NetworkErrors:     atomic.LoadInt64(&networkErrorsCounter),
		DailyCalls:        dailyCalls,
		DailyLimit:        dailyLimit,
		DailyUsagePercent: dailyUsagePercent,
		NextResetTime:     dailyLimitResetTime,
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
