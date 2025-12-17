package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NethermindEth/juno/core/felt"
	"github.com/NethermindEth/starknet.go/utils"
	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/services/starknet"
	"github.com/paycrest/aggregator/storage"
	u "github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

// VoyagerErrorType represents different types of errors for smart handling
type VoyagerErrorType int

const (
	VoyagerErrorTypeNetwork VoyagerErrorType = iota
	VoyagerErrorTypeRateLimit
	VoyagerErrorTypeMonthlyLimit
	VoyagerErrorTypeAPI
	VoyagerErrorTypeUnknown
)

// VoyagerRequestContext tracks pending requests with proper lifecycle management
type VoyagerRequestContext struct {
	ID        string
	CreatedAt time.Time
	Context   context.Context
	Cancel    context.CancelFunc
	Response  chan *VoyagerResponse
	Done      chan struct{}
}

// VoyagerRequest represents a queued Voyager API request
type VoyagerRequest struct {
	ID           string    `json:"id"`
	RequestType  string    `json:"request_type"` // "transfers", "events", "events_by_tx", "blocks"
	Address      string    `json:"address,omitempty"`
	ContractAddr string    `json:"contract_addr,omitempty"`
	TxHash       string    `json:"tx_hash,omitempty"`
	Limit        int       `json:"limit"`
	FromBlock    int64     `json:"from_block"`
	ToBlock      int64     `json:"to_block"`
	FromAddress  string    `json:"from_address,omitempty"`
	ToAddress    string    `json:"to_address,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	Timeout      int64     `json:"timeout"` // seconds
}

// VoyagerResponse represents the response from Voyager API
type VoyagerResponse struct {
	Data  interface{} `json:"data"`
	Error error       `json:"error"`
}

// VoyagerWorker represents a worker with its own API key and rate limiting
type VoyagerWorker struct {
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

// classifyVoyagerError determines the type of error for smart handling
func classifyVoyagerError(message string) VoyagerErrorType {
	switch {
	case strings.Contains(strings.ToLower(message), "monthly limit reached"):
		return VoyagerErrorTypeMonthlyLimit
	case strings.Contains(strings.ToLower(message), "rate limit"):
		return VoyagerErrorTypeRateLimit
	case strings.Contains(strings.ToLower(message), "too many requests"):
		return VoyagerErrorTypeRateLimit
	case strings.Contains(strings.ToLower(message), "timeout"):
		return VoyagerErrorTypeNetwork
	case strings.Contains(strings.ToLower(message), "connection"):
		return VoyagerErrorTypeNetwork
	case strings.Contains(strings.ToLower(message), "invalid api key"):
		return VoyagerErrorTypeAPI
	case strings.Contains(strings.ToLower(message), "unauthorized"):
		return VoyagerErrorTypeAPI
	default:
		return VoyagerErrorTypeUnknown
	}
}

// isExhausted checks if the worker should be skipped
func (w *VoyagerWorker) isExhausted() bool {
	w.Mutex.RLock()
	defer w.Mutex.RUnlock()
	return time.Now().Before(w.ExhaustedUntil)
}

// VoyagerService provides functionality for interacting with Voyager API
type VoyagerService struct {
	config *config.VoyagerConfiguration
}

var (
	voyagerWorkerStarted sync.Once
	voyagerWorkerCtx     context.Context
	voyagerWorkerCancel  context.CancelFunc
	voyagerWorkers       []*VoyagerWorker
	voyagerWorkerMutex   sync.RWMutex

	// Request tracking
	voyagerPendingRequests  sync.Map
	voyagerQueuedRequestIDs sync.Map

	// Circuit breaker configuration
	voyagerCircuitBreakerThreshold = 5
	voyagerCircuitBreakerTimeout   = 30 * time.Second

	// Request cleanup configuration
	voyagerRequestCleanupInterval = 5 * time.Minute
	voyagerRequestTimeout         = 60 * time.Second

	// Monthly limit tracking
	voyagerMonthlyLimitCalls     int64
	voyagerMonthlyCallsCounter   int64
	voyagerMonthlyLimitResetTime time.Time

	// Error type counters
	voyagerRateLimitErrorsCounter    int64
	voyagerMonthlyLimitErrorsCounter int64
	voyagerAPIErrorsCounter          int64
	voyagerNetworkErrorsCounter      int64
)

// NewVoyagerService creates a new instance of VoyagerService
func NewVoyagerService() (*VoyagerService, error) {
	voyagerConfig := config.VoyagerConfig()
	if voyagerConfig.ApiKey == "" {
		return nil, fmt.Errorf("VOYAGER_API_KEY environment variable is required")
	}

	// Start the background workers only once
	voyagerWorkerStarted.Do(func() {
		voyagerWorkerCtx, voyagerWorkerCancel = context.WithCancel(context.Background())
		// Initialize monthly limit from config
		if voyagerConfig.MonthlyLimit > 0 {
			atomic.StoreInt64(&voyagerMonthlyLimitCalls, int64(voyagerConfig.MonthlyLimit))
		} else {
			atomic.StoreInt64(&voyagerMonthlyLimitCalls, 300000) // Default: 300k
		}
		startVoyagerWorkers(voyagerWorkerCtx, voyagerConfig.ApiKey)
		go startVoyagerRequestCleanup(voyagerWorkerCtx)
		go startVoyagerMonthlyLimitReset(voyagerWorkerCtx)
	})

	return &VoyagerService{
		config: voyagerConfig,
	}, nil
}

// startVoyagerWorkers starts workers for Voyager API
func startVoyagerWorkers(ctx context.Context, apiKeys string) {
	// Split API keys by comma
	keys := strings.Split(apiKeys, ",")

	// Clean up keys
	var cleanKeys []string
	for _, key := range keys {
		cleanKey := strings.TrimSpace(key)
		if cleanKey != "" {
			cleanKeys = append(cleanKeys, cleanKey)
		}
	}

	if len(cleanKeys) == 0 {
		logger.Errorf("No valid Voyager API keys found")
		return
	}

	logger.WithFields(logger.Fields{
		"TotalKeys": len(cleanKeys),
	}).Info("Starting Voyager workers")

	// Get rate limit from config
	voyagerConfig := config.VoyagerConfig()
	rateLimit := voyagerConfig.RateLimit
	if rateLimit <= 0 {
		rateLimit = 10 // Default: 10 req/sec
	}

	// Create a worker for each API key
	voyagerWorkerMutex.Lock()
	voyagerWorkers = make([]*VoyagerWorker, len(cleanKeys))
	voyagerWorkerMutex.Unlock()

	for i, apiKey := range cleanKeys {
		worker := &VoyagerWorker{
			APIKey:    apiKey,
			WorkerID:  i,
			RateLimit: rateLimit,
			Interval:  time.Duration(1000/rateLimit) * time.Millisecond,
		}

		voyagerWorkerMutex.Lock()
		voyagerWorkers[i] = worker
		voyagerWorkerMutex.Unlock()

		// Start worker in its own goroutine
		go worker.start(ctx)
	}

	logger.WithFields(logger.Fields{
		"TotalWorkers":  len(cleanKeys),
		"TotalRate":     len(cleanKeys) * rateLimit,
		"RatePerWorker": rateLimit,
	}).Info("Voyager workers started successfully")
}

// startVoyagerRequestCleanup periodically cleans up stale requests
func startVoyagerRequestCleanup(ctx context.Context) {
	ticker := time.NewTicker(voyagerRequestCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanupVoyagerStaleRequests()
			cleanupVoyagerStaleQueueEntries(ctx)
			cleanupVoyagerQueuedRequestIDs()
		}
	}
}

// startVoyagerMonthlyLimitReset resets monthly call counter at start of each month UTC
func startVoyagerMonthlyLimitReset(ctx context.Context) {
	// Calculate time until next month start using AddDate to avoid month overflow
	now := time.Now().UTC()
	nextMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	voyagerMonthlyLimitResetTime = nextMonth

	for {
		// Calculate duration until next month
		now := time.Now().UTC()
		duration := nextMonth.Sub(now)

		// Create timer for next month reset
		timer := time.NewTimer(duration)

		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			// Reset counter at start of month
			atomic.StoreInt64(&voyagerMonthlyCallsCounter, 0)
			logger.Infof("Monthly Voyager API call counter reset. Limit: %d calls", atomic.LoadInt64(&voyagerMonthlyLimitCalls))

			// Advance to next month
			nextMonth = nextMonth.AddDate(0, 1, 0)
			voyagerMonthlyLimitResetTime = nextMonth
		}
	}
}

// cleanupVoyagerQueuedRequestIDs removes old entries from queuedRequestIDs map
func cleanupVoyagerQueuedRequestIDs() {
	now := time.Now()
	var cleaned int

	voyagerQueuedRequestIDs.Range(func(key, value interface{}) bool {
		queuedAt, ok := value.(time.Time)
		if !ok {
			voyagerQueuedRequestIDs.Delete(key)
			cleaned++
			return true
		}

		if now.Sub(queuedAt) > voyagerRequestTimeout {
			voyagerQueuedRequestIDs.Delete(key)
			cleaned++
		}
		return true
	})

	if cleaned > 0 {
		logger.WithFields(logger.Fields{
			"CleanedIDs": cleaned,
		}).Debugf("Cleaned up Voyager queued request IDs")
	}
}

// cleanupVoyagerStaleRequests removes stale requests from tracking
func cleanupVoyagerStaleRequests() {
	now := time.Now()
	var cleaned int

	voyagerPendingRequests.Range(func(key, value interface{}) bool {
		reqCtx, ok := value.(*VoyagerRequestContext)
		if !ok {
			voyagerPendingRequests.Delete(key)
			return true
		}

		if now.Sub(reqCtx.CreatedAt) > voyagerRequestTimeout || reqCtx.Context.Err() != nil {
			reqCtx.Cancel()
			close(reqCtx.Done)
			voyagerPendingRequests.Delete(key)
			cleaned++
		}
		return true
	})

	if cleaned > 0 {
		logger.WithFields(logger.Fields{
			"CleanedRequests": cleaned,
		}).Infof("Cleaned up stale Voyager requests")
	}
}

// cleanupVoyagerStaleQueueEntries removes old requests from Redis queue
func cleanupVoyagerStaleQueueEntries(ctx context.Context) {
	queueKey := "voyager_queue"
	maxCheckItems := 100
	items, err := storage.RedisClient.LRange(ctx, queueKey, 0, int64(maxCheckItems-1)).Result()
	if err != nil {
		logger.Errorf("Failed to get Voyager queue items for cleanup: %v", err)
		return
	}

	if len(items) == 0 {
		return
	}

	var staleCount int
	now := time.Now()

	for _, item := range items {
		var request VoyagerRequest
		if json.Unmarshal([]byte(item), &request) != nil {
			continue
		}

		if now.Sub(request.CreatedAt) > voyagerRequestTimeout {
			if err := storage.RedisClient.LRem(ctx, queueKey, 1, item).Err(); err == nil {
				staleCount++
			}
		} else {
			break
		}
	}

	if staleCount > 0 {
		logger.WithFields(logger.Fields{
			"StaleRequests": staleCount,
			"CheckedItems":  len(items),
		}).Infof("Cleaned up stale Voyager queue entries")
	}
}

// start starts a single Voyager worker
func (w *VoyagerWorker) start(ctx context.Context) {
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()

	logger.WithFields(logger.Fields{
		"WorkerID":  w.WorkerID,
		"APIKey":    w.APIKey[:8] + "...",
		"RateLimit": w.RateLimit,
		"Interval":  w.Interval,
	}).Info("Voyager worker started")

	consecutiveEmptyPolls := 0
	maxEmptyPolls := 10

	for {
		select {
		case <-ctx.Done():
			logger.WithFields(logger.Fields{
				"WorkerID": w.WorkerID,
			}).Info("Voyager worker stopped")
			return
		case <-ticker.C:
			if w.isExhausted() {
				continue
			}

			if w.isCircuitOpen() {
				continue
			}

			// Check monthly limit
			monthlyLimit := atomic.LoadInt64(&voyagerMonthlyLimitCalls)
			if atomic.LoadInt64(&voyagerMonthlyCallsCounter) >= monthlyLimit {
				logger.Warnf("Monthly Voyager API limit reached (%d/%d). Worker %d paused until reset.",
					atomic.LoadInt64(&voyagerMonthlyCallsCounter), monthlyLimit, w.WorkerID)
				
				// Calculate sleep duration, ensuring a minimum wait to avoid busy-looping
				sleepDuration := time.Until(voyagerMonthlyLimitResetTime)
				const minBackoff = 1 * time.Second
				if sleepDuration <= 0 {
					// Reset time is in the past or not initialized - use short backoff
					sleepDuration = minBackoff
					logger.Warnf("Worker %d: monthly limit reset time is in the past, using %v backoff", w.WorkerID, minBackoff)
				}
				
				time.Sleep(sleepDuration)
				continue
			}

			currentInterval := w.Interval
			w.Mutex.RLock()
			if w.BackoffInterval > 0 {
				currentInterval = w.BackoffInterval
			}
			w.Mutex.RUnlock()

			err := w.processNextRequest(ctx)
			if err != nil {
				if err.Error() == "no requests in queue" {
					consecutiveEmptyPolls++
					if consecutiveEmptyPolls >= maxEmptyPolls {
						ticker.Reset(1 * time.Second)
					}
					continue
				}
				consecutiveEmptyPolls = 0
				ticker.Reset(currentInterval)
				w.recordError()
				logger.WithFields(logger.Fields{
					"WorkerID": w.WorkerID,
					"Error":    fmt.Sprintf("%v", err),
				}).Errorf("Failed to process Voyager request")
			} else {
				consecutiveEmptyPolls = 0
				ticker.Reset(currentInterval)
				w.recordSuccess()
				atomic.AddInt64(&voyagerMonthlyCallsCounter, 1)
			}
		}
	}
}

// isCircuitOpen checks if the circuit breaker is open
func (w *VoyagerWorker) isCircuitOpen() bool {
	w.Mutex.RLock()
	circuitOpen := w.CircuitOpen
	lastFailure := w.LastFailure
	w.Mutex.RUnlock()

	if circuitOpen && time.Since(lastFailure) < voyagerCircuitBreakerTimeout {
		return true
	}

	// Circuit should be reset - acquire write lock after releasing read lock
	if circuitOpen && time.Since(lastFailure) >= voyagerCircuitBreakerTimeout {
		w.Mutex.Lock()
		// Re-check condition after acquiring write lock to avoid race
		if w.CircuitOpen && time.Since(w.LastFailure) >= voyagerCircuitBreakerTimeout {
			w.CircuitOpen = false
			w.Mutex.Unlock()
			logger.WithFields(logger.Fields{
				"WorkerID": w.WorkerID,
			}).Infof("Voyager circuit breaker reset")
		} else {
			w.Mutex.Unlock()
		}
	}

	return false
}

// recordError records an error and potentially opens circuit breaker
func (w *VoyagerWorker) recordError() {
	w.Mutex.Lock()
	defer w.Mutex.Unlock()

	w.Errors++
	w.ConsecutiveErrors++
	w.LastFailure = time.Now()

	if w.ConsecutiveErrors >= int64(voyagerCircuitBreakerThreshold) {
		w.CircuitOpen = true
		logger.WithFields(logger.Fields{
			"WorkerID":          w.WorkerID,
			"TotalErrors":       w.Errors,
			"ConsecutiveErrors": w.ConsecutiveErrors,
		}).Warnf("Voyager circuit breaker opened")
	}
}

// recordSuccess records a successful request
func (w *VoyagerWorker) recordSuccess() {
	w.Mutex.Lock()
	defer w.Mutex.Unlock()

	w.Processed++
	w.ConsecutiveErrors = 0
	w.BackoffInterval = 0
}

// processNextRequest processes the next request from the queue
func (w *VoyagerWorker) processNextRequest(ctx context.Context) error {
	requestData, err := storage.RedisClient.LPop(ctx, "voyager_queue").Result()
	if err != nil {
		return fmt.Errorf("no requests in queue")
	}

	var request VoyagerRequest
	if err := json.Unmarshal([]byte(requestData), &request); err != nil {
		return fmt.Errorf("failed to unmarshal request: %w", err)
	}

	// Check if request was cancelled
	if reqCtxValue, exists := voyagerPendingRequests.Load(request.ID); exists {
		if reqCtx, ok := reqCtxValue.(*VoyagerRequestContext); ok {
			if reqCtx.Context.Err() != nil {
				voyagerPendingRequests.Delete(request.ID)
				voyagerQueuedRequestIDs.Delete(request.ID)
				return nil
			}
		}
	}

	// Check if request is too old
	if time.Since(request.CreatedAt) > voyagerRequestTimeout {
		logger.WithFields(logger.Fields{
			"WorkerID":  w.WorkerID,
			"RequestID": request.ID,
			"Age":       time.Since(request.CreatedAt),
		}).Warnf("Skipping old Voyager request")
		return nil
	}

	// Make the actual API call
	var data interface{}
	var apiErr error

	switch request.RequestType {
	case "transfers":
		data, apiErr = w.makeVoyagerTransfersAPICall(request)
	case "events":
		data, apiErr = w.makeVoyagerEventsAPICall(request)
	case "events_by_tx":
		data, apiErr = w.makeVoyagerEventsByTxAPICall(request)
	case "blocks":
		data, apiErr = w.makeVoyagerBlocksAPICall()
	default:
		apiErr = fmt.Errorf("unknown request type: %s", request.RequestType)
	}

	// Update error counters
	if apiErr != nil {
		errorType := classifyVoyagerError(apiErr.Error())
		switch errorType {
		case VoyagerErrorTypeRateLimit:
			atomic.AddInt64(&voyagerRateLimitErrorsCounter, 1)
		case VoyagerErrorTypeMonthlyLimit:
			atomic.AddInt64(&voyagerMonthlyLimitErrorsCounter, 1)
		case VoyagerErrorTypeAPI:
			atomic.AddInt64(&voyagerAPIErrorsCounter, 1)
		case VoyagerErrorTypeNetwork:
			atomic.AddInt64(&voyagerNetworkErrorsCounter, 1)
		}
	}

	// Send response to pending request
	if reqCtxValue, exists := voyagerPendingRequests.Load(request.ID); exists {
		if reqCtx, ok := reqCtxValue.(*VoyagerRequestContext); ok {
			select {
			case reqCtx.Response <- &VoyagerResponse{
				Data:  data,
				Error: apiErr,
			}:
			default:
				logger.WithFields(logger.Fields{
					"WorkerID":  w.WorkerID,
					"RequestID": request.ID,
				}).Debugf("Could not send Voyager response to request")
			}

			reqCtx.Cancel()
			close(reqCtx.Done)
			voyagerPendingRequests.Delete(request.ID)
			voyagerQueuedRequestIDs.Delete(request.ID)
		}
	}

	return apiErr
}

// makeVoyagerTransfersAPICall makes the actual API call to Voyager for transfers
func (w *VoyagerWorker) makeVoyagerTransfersAPICall(request VoyagerRequest) ([]map[string]interface{}, error) {
	// Build URL: /beta/contracts/{address}/transfers
	url := fmt.Sprintf("https://api.voyager.online/beta/contracts/%s/transfers", request.Address)

	// Build query parameters
	params := map[string]string{
		"type": "erc20",
		"ps":   fmt.Sprintf("%d", request.Limit),
		"p":    "1",
	}

	// Add timestamp filters if block numbers are provided
	if request.FromBlock > 0 || request.ToBlock > 0 {
		// Convert block numbers to timestamps using Voyager blocks endpoint
		// Query blocks endpoint to get timestamps for the block range
		if request.FromBlock > 0 {
			// Get timestamp for fromBlock by querying a specific block
			fromBlockData, err := w.getBlockByNumber(request.FromBlock)
			if err == nil && fromBlockData != nil {
				if timestamp, ok := fromBlockData["timestamp"].(float64); ok {
					params["timestampFrom"] = fmt.Sprintf("%.0f", timestamp)
				}
			}
		}
		if request.ToBlock > 0 {
			toBlockData, err := w.getBlockByNumber(request.ToBlock)
			if err == nil && toBlockData != nil {
				if timestamp, ok := toBlockData["timestamp"].(float64); ok {
					params["timestampTo"] = fmt.Sprintf("%.0f", timestamp)
				}
			}
		}
	}

	// Add from/to address filters
	if request.FromAddress != "" {
		params["from"] = request.FromAddress
	}
	if request.ToAddress != "" {
		params["to"] = request.ToAddress
	}

	// Make API call
	res, err := fastshot.NewClient(url).
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"x-api-key":    w.APIKey,
	}).Build().GET("").
		Query().AddParams(params).Send()

	if err != nil {
		return nil, fmt.Errorf("failed to get transfers: %w", err)
	}

	if res.RawResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d for address %s", res.RawResponse.StatusCode, request.Address)
	}

	data, err := u.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	// Voyager returns { "items": [...], "hasMore": bool }
	itemsRaw, ok := data["items"]
	if !ok || itemsRaw == nil {
		return []map[string]interface{}{}, nil
	}

	items, ok := itemsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid items type in Voyager response")
	}

	result := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue // Skip non-map items
		}
		result = append(result, itemMap)
	}

	return result, nil
}

// makeVoyagerEventsAPICall makes the actual API call to Voyager for contract events
func (w *VoyagerWorker) makeVoyagerEventsAPICall(request VoyagerRequest) ([]map[string]interface{}, error) {
	// Build URL: /beta/events?contract={address}
	url := "https://api.voyager.online/beta/events"

	// Build query parameters
	params := map[string]string{
		"contract": request.ContractAddr,
		"ps":       fmt.Sprintf("%d", request.Limit),
		"p":        "1",
	}

	// Add timestamp filters if block numbers are provided
	if request.FromBlock > 0 || request.ToBlock > 0 {
		// Convert block numbers to timestamps using Voyager blocks endpoint
		if request.FromBlock > 0 {
			fromBlockData, err := w.getBlockByNumber(request.FromBlock)
			if err == nil && fromBlockData != nil {
				if timestamp, ok := fromBlockData["timestamp"].(float64); ok {
					params["timestampFrom"] = fmt.Sprintf("%.0f", timestamp)
				}
			}
		}
		if request.ToBlock > 0 {
			toBlockData, err := w.getBlockByNumber(request.ToBlock)
			if err == nil && toBlockData != nil {
				if timestamp, ok := toBlockData["timestamp"].(float64); ok {
					params["timestampTo"] = fmt.Sprintf("%.0f", timestamp)
				}
			}
		}
	}

	// Make API call
	res, err := fastshot.NewClient(url).
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"x-api-key":    w.APIKey,
	}).Build().GET("").
		Query().AddParams(params).Send()

	if err != nil {
		return nil, fmt.Errorf("failed to get events: %w", err)
	}

	if res.RawResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d for contract %s", res.RawResponse.StatusCode, request.ContractAddr)
	}

	data, err := u.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	itemsRaw, ok := data["items"]
	if !ok || itemsRaw == nil {
		return []map[string]interface{}{}, nil
	}

	items, ok := itemsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid items type in Voyager response")
	}

	result := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue // Skip non-map items
		}
		result = append(result, itemMap)
	}

	return result, nil
}

// makeVoyagerEventsByTxAPICall makes the actual API call to Voyager for events by transaction hash
func (w *VoyagerWorker) makeVoyagerEventsByTxAPICall(request VoyagerRequest) ([]map[string]interface{}, error) {
	// Build URL: /beta/events?txnHash={txHash}
	url := "https://api.voyager.online/beta/events"

	// Build query parameters
	params := map[string]string{
		"txnHash": request.TxHash,
		"ps":      fmt.Sprintf("%d", request.Limit),
		"p":       "1",
	}

	// Make API call
	res, err := fastshot.NewClient(url).
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"x-api-key":    w.APIKey,
	}).Build().GET("").
		Query().AddParams(params).Send()

	if err != nil {
		return nil, fmt.Errorf("failed to get events by tx: %w", err)
	}

	if res.RawResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d for tx %s", res.RawResponse.StatusCode, request.TxHash)
	}

	data, err := u.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	itemsRaw, ok := data["items"]
	if !ok || itemsRaw == nil {
		return []map[string]interface{}{}, nil
	}

	items, ok := itemsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid items type in Voyager response")
	}

	result := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue // Skip non-map items
		}
		result = append(result, itemMap)
	}

	return result, nil
}

// makeVoyagerBlocksAPICall makes the actual API call to Voyager for blocks
func (w *VoyagerWorker) makeVoyagerBlocksAPICall() (map[string]interface{}, error) {
	// Build URL: /beta/blocks?p=1&ps=1
	url := "https://api.voyager.online/beta/blocks"

	// Build query parameters
	params := map[string]string{
		"p":  "1",
		"ps": "1",
	}

	// Make API call
	res, err := fastshot.NewClient(url).
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"x-api-key":    w.APIKey,
	}).Build().GET("").
		Query().AddParams(params).Send()

	if err != nil {
		return nil, fmt.Errorf("failed to get blocks: %w", err)
	}

	if res.RawResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d for blocks", res.RawResponse.StatusCode)
	}

	data, err := u.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	if data["items"] == nil {
		return nil, fmt.Errorf("no blocks found")
	}

	itemsRaw, ok := data["items"]
	if !ok || itemsRaw == nil {
		return nil, fmt.Errorf("no blocks found")
	}

	items, ok := itemsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid items type in Voyager blocks response")
	}

	if len(items) == 0 {
		return nil, fmt.Errorf("no blocks found")
	}

	// Return the first (latest) block
	block, ok := items[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid block type in Voyager blocks response")
	}

	return block, nil
}

// getBlockByNumber queries Voyager blocks endpoint for a specific block number
func (w *VoyagerWorker) getBlockByNumber(blockNumber int64) (map[string]interface{}, error) {
	url := fmt.Sprintf("https://api.voyager.online/beta/blocks/%d", blockNumber)

	res, err := fastshot.NewClient(url).
		Config().SetTimeout(10 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"x-api-key":    w.APIKey,
	}).Build().GET("").Send()

	if err != nil {
		return nil, err
	}

	if res.RawResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d for block %d", res.RawResponse.StatusCode, blockNumber)
	}

	data, err := u.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// getStarknetRPCClient creates a Starknet RPC client on-demand for fallback
func getStarknetRPCClient() (*starknet.Client, error) {
	return starknet.NewClient()
}

// TransformVoyagerTransferToRPCFormat converts Voyager transfer format to RPC event format
func TransformVoyagerTransferToRPCFormat(transfer map[string]interface{}) map[string]interface{} {
	// Voyager format: txHash, transferFrom, transferTo, blockNumber, transferValue, etc.
	// RPC format: transaction_hash, block_number, decoded.non_indexed_params (from, to, value)

	txHash, _ := transfer["txHash"].(string)
	blockNumber, _ := transfer["blockNumber"].(float64)
	transferFrom, _ := transfer["transferFrom"].(string)
	transferTo, _ := transfer["transferTo"].(string)
	transferValue, _ := transfer["transferValue"].(string)

	// Create RPC-formatted event
	rpcEvent := map[string]interface{}{
		"transaction_hash": txHash,
		"block_number":     blockNumber,
		"decoded": map[string]interface{}{
			"non_indexed_params": map[string]interface{}{
				"from":  transferFrom,
				"to":    transferTo,
				"value": transferValue,
			},
			"indexed_params": map[string]interface{}{},
		},
	}

	return rpcEvent
}

// TransformVoyagerEventToRPCFormat converts Voyager event format to RPC event format
func TransformVoyagerEventToRPCFormat(event map[string]interface{}) map[string]interface{} {
	// Voyager format: transactionHash, blockNumber, name, dataDecoded, keyDecoded, fromAddress
	// RPC format: transaction_hash, block_number, decoded.indexed_params, decoded.non_indexed_params

	transactionHash, _ := event["transactionHash"].(string)
	blockNumber, _ := event["blockNumber"].(float64)
	name, _ := event["name"].(string)
	dataDecoded, _ := event["dataDecoded"].([]interface{})
	keyDecoded, _ := event["keyDecoded"].([]interface{})
	fromAddress, _ := event["fromAddress"].(string)

	// Convert keyDecoded to indexed_params
	indexedParams := make(map[string]interface{})
	for _, keyItem := range keyDecoded {
		if keyMap, ok := keyItem.(map[string]interface{}); ok {
			keyName, _ := keyMap["name"].(string)
			keyValue, _ := keyMap["value"]
			if keyName != "" {
				indexedParams[keyName] = keyValue
			}
		}
	}

	// Convert dataDecoded to non_indexed_params
	nonIndexedParams := make(map[string]interface{})
	for _, dataItem := range dataDecoded {
		if dataMap, ok := dataItem.(map[string]interface{}); ok {
			dataName, _ := dataMap["name"].(string)
			dataValue, _ := dataMap["value"]
			if dataName != "" {
				nonIndexedParams[dataName] = dataValue
			}
		}
	}

	// Create RPC-formatted event
	rpcEvent := map[string]interface{}{
		"transaction_hash": transactionHash,
		"block_number":     blockNumber,
		"name":             name,
		"from_address":     fromAddress,
		"decoded": map[string]interface{}{
			"indexed_params":     indexedParams,
			"non_indexed_params": nonIndexedParams,
		},
	}

	return rpcEvent
}

// GetAddressTokenTransfersImmediate fetches token transfers immediately without queuing
func (s *VoyagerService) GetAddressTokenTransfersImmediate(ctx context.Context, address string, limit int, fromBlock int64, toBlock int64, fromAddress string, toAddress string) ([]map[string]interface{}, error) {
	// Try Voyager API first
	voyagerWorkerMutex.RLock()
	var worker *VoyagerWorker
	if len(voyagerWorkers) > 0 {
		worker = voyagerWorkers[0]
	}
	voyagerWorkerMutex.RUnlock()

	if worker == nil {
		// Fallback to RPC if no workers available
		return s.getAddressTokenTransfersRPC(ctx, address, limit, fromBlock, toBlock)
	}

	request := VoyagerRequest{
		ID:          fmt.Sprintf("transfers_%s_%d", address, limit),
		RequestType: "transfers",
		Address:     address,
		Limit:       limit,
		FromBlock:   fromBlock,
		ToBlock:     toBlock,
		FromAddress: fromAddress,
		ToAddress:   toAddress,
	}

	transfers, err := worker.makeVoyagerTransfersAPICall(request)
	if err == nil {
		return transfers, nil
	}

	// Voyager failed, fallback to RPC
	logger.WithFields(logger.Fields{
		"Address":       address,
		"VoyagerError":  err.Error(),
		"FallbackToRPC": true,
	}).Warnf("Voyager failed, falling back to RPC for token transfers")

	return s.getAddressTokenTransfersRPC(ctx, address, limit, fromBlock, toBlock)
}

// getAddressTokenTransfersRPC fetches token transfers using RPC as fallback
func (s *VoyagerService) getAddressTokenTransfersRPC(ctx context.Context, address string, limit int, fromBlock int64, toBlock int64) ([]map[string]interface{}, error) {
	client, err := getStarknetRPCClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create RPC client: %w", err)
	}

	addressFelt, err := utils.HexToFelt(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	transferSelectorFelt, _ := utils.HexToFelt(u.TransferStarknetSelector)
	events, err := client.GetEvents(ctx, addressFelt, fromBlock, toBlock, []*felt.Felt{transferSelectorFelt}, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get events from RPC: %w", err)
	}

	return events, nil
}

// GetAddressTokenTransfers fetches token transfers (queued version)
func (s *VoyagerService) GetAddressTokenTransfers(ctx context.Context, address string, limit int, fromBlock int64, toBlock int64, fromAddress string, toAddress string) ([]map[string]interface{}, error) {
	// Create request ID
	requestID := fmt.Sprintf("transfers_%s_%d_%d_%d", address, limit, fromBlock, toBlock)

	// Create request context
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	responseChan := make(chan *VoyagerResponse, 1)
	doneChan := make(chan struct{})

	requestContext := &VoyagerRequestContext{
		ID:        requestID,
		CreatedAt: time.Now(),
		Context:   reqCtx,
		Cancel:    cancel,
		Response:  responseChan,
		Done:      doneChan,
	}

	// Check for duplicate request
	if existingCtx, exists := voyagerPendingRequests.Load(requestID); exists {
		if existingReqCtx, ok := existingCtx.(*VoyagerRequestContext); ok {
			// Wait for the original request to complete instead of consuming its response
			// This ensures the original requester receives the response
			select {
			case <-existingReqCtx.Context.Done():
				// Original request completed, make our own immediate request
				return s.GetAddressTokenTransfersImmediate(ctx, address, limit, fromBlock, toBlock, fromAddress, toAddress)
			case <-reqCtx.Done():
				return nil, reqCtx.Err()
			}
		}
	}

	// Track the pending request
	voyagerPendingRequests.Store(requestID, requestContext)

	// Create the request
	request := VoyagerRequest{
		ID:          requestID,
		RequestType: "transfers",
		Address:     address,
		Limit:       limit,
		FromBlock:   fromBlock,
		ToBlock:     toBlock,
		FromAddress: fromAddress,
		ToAddress:   toAddress,
		CreatedAt:   time.Now(),
		Timeout:     30,
	}

	// Serialize and queue the request
	requestData, err := json.Marshal(request)
	if err != nil {
		voyagerQueuedRequestIDs.Delete(requestID)
		voyagerPendingRequests.Delete(requestID)
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Add to queue
	if err := storage.RedisClient.RPush(ctx, "voyager_queue", requestData).Err(); err != nil {
		voyagerQueuedRequestIDs.Delete(requestID)
		voyagerPendingRequests.Delete(requestID)
		return nil, fmt.Errorf("failed to queue request: %w", err)
	}

	// Wait for response
	select {
	case response := <-responseChan:
		if response.Error != nil {
			// Voyager failed, fallback to RPC
			logger.WithFields(logger.Fields{
				"Address":       address,
				"VoyagerError":  response.Error.Error(),
				"FallbackToRPC": true,
			}).Warnf("Voyager failed, falling back to RPC for token transfers")
			return s.getAddressTokenTransfersRPC(ctx, address, limit, fromBlock, toBlock)
		}
		if transfers, ok := response.Data.([]map[string]interface{}); ok {
			return transfers, nil
		}
		return []map[string]interface{}{}, nil
	case <-reqCtx.Done():
		voyagerPendingRequests.Delete(requestID)
		voyagerQueuedRequestIDs.Delete(requestID)
		return nil, reqCtx.Err()
	case <-doneChan:
		return nil, fmt.Errorf("request was cleaned up")
	}
}

// GetContractEventsImmediate fetches contract events immediately without queuing
func (s *VoyagerService) GetContractEventsImmediate(ctx context.Context, contractAddress string, limit int, fromBlock int64, toBlock int64) ([]map[string]interface{}, error) {
	// Try Voyager API first
	voyagerWorkerMutex.RLock()
	var worker *VoyagerWorker
	if len(voyagerWorkers) > 0 {
		worker = voyagerWorkers[0]
	}
	voyagerWorkerMutex.RUnlock()

	if worker == nil {
		return s.getContractEventsRPC(ctx, contractAddress, limit, fromBlock, toBlock)
	}

	request := VoyagerRequest{
		ID:           fmt.Sprintf("events_%s_%d", contractAddress, limit),
		RequestType:  "events",
		ContractAddr: contractAddress,
		Limit:        limit,
		FromBlock:    fromBlock,
		ToBlock:      toBlock,
	}

	events, err := worker.makeVoyagerEventsAPICall(request)
	if err == nil {
		return events, nil
	}

	logger.WithFields(logger.Fields{
		"Contract":      contractAddress,
		"VoyagerError":  err.Error(),
		"FallbackToRPC": true,
	}).Warnf("Voyager failed, falling back to RPC for contract events")

	return s.getContractEventsRPC(ctx, contractAddress, limit, fromBlock, toBlock)
}

// getContractEventsRPC fetches contract events using RPC as fallback
func (s *VoyagerService) getContractEventsRPC(ctx context.Context, contractAddress string, limit int, fromBlock int64, toBlock int64) ([]map[string]interface{}, error) {
	client, err := getStarknetRPCClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create RPC client: %w", err)
	}

	contractFelt, err := utils.HexToFelt(contractAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid contract address: %w", err)
	}

	events, err := client.GetEvents(ctx, contractFelt, fromBlock, toBlock, nil, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get events from RPC: %w", err)
	}

	return events, nil
}

// GetContractEvents fetches contract events (queued version)
func (s *VoyagerService) GetContractEvents(ctx context.Context, contractAddress string, limit int, fromBlock int64, toBlock int64) ([]map[string]interface{}, error) {
	requestID := fmt.Sprintf("events_%s_%d_%d_%d", contractAddress, limit, fromBlock, toBlock)

	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	responseChan := make(chan *VoyagerResponse, 1)
	doneChan := make(chan struct{})

	requestContext := &VoyagerRequestContext{
		ID:        requestID,
		CreatedAt: time.Now(),
		Context:   reqCtx,
		Cancel:    cancel,
		Response:  responseChan,
		Done:      doneChan,
	}

	if existingCtx, exists := voyagerPendingRequests.Load(requestID); exists {
		if existingReqCtx, ok := existingCtx.(*VoyagerRequestContext); ok {
			// Wait for the original request to complete instead of consuming its response
			// This ensures the original requester receives the response
			select {
			case <-existingReqCtx.Context.Done():
				// Original request completed, make our own immediate request
				return s.GetContractEventsImmediate(ctx, contractAddress, limit, fromBlock, toBlock)
			case <-reqCtx.Done():
				return nil, reqCtx.Err()
			}
		}
	}

	voyagerPendingRequests.Store(requestID, requestContext)

	request := VoyagerRequest{
		ID:           requestID,
		RequestType:  "events",
		ContractAddr: contractAddress,
		Limit:        limit,
		FromBlock:    fromBlock,
		ToBlock:      toBlock,
		CreatedAt:    time.Now(),
		Timeout:      30,
	}

	requestData, err := json.Marshal(request)
	if err != nil {
		voyagerQueuedRequestIDs.Delete(requestID)
		voyagerPendingRequests.Delete(requestID)
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	if err := storage.RedisClient.RPush(ctx, "voyager_queue", requestData).Err(); err != nil {
		voyagerQueuedRequestIDs.Delete(requestID)
		voyagerPendingRequests.Delete(requestID)
		return nil, fmt.Errorf("failed to queue request: %w", err)
	}

	select {
	case response := <-responseChan:
		if response.Error != nil {
			logger.WithFields(logger.Fields{
				"Contract":      contractAddress,
				"VoyagerError":  response.Error.Error(),
				"FallbackToRPC": true,
			}).Warnf("Voyager failed, falling back to RPC for contract events")
			return s.getContractEventsRPC(ctx, contractAddress, limit, fromBlock, toBlock)
		}
		if events, ok := response.Data.([]map[string]interface{}); ok {
			return events, nil
		}
		return []map[string]interface{}{}, nil
	case <-reqCtx.Done():
		voyagerPendingRequests.Delete(requestID)
		voyagerQueuedRequestIDs.Delete(requestID)
		return nil, reqCtx.Err()
	case <-doneChan:
		return nil, fmt.Errorf("request was cleaned up")
	}
}

// GetEventsByTransactionHashImmediate fetches events by transaction hash immediately
func (s *VoyagerService) GetEventsByTransactionHashImmediate(ctx context.Context, txHash string, limit int) ([]map[string]interface{}, error) {
	voyagerWorkerMutex.RLock()
	var worker *VoyagerWorker
	if len(voyagerWorkers) > 0 {
		worker = voyagerWorkers[0]
	}
	voyagerWorkerMutex.RUnlock()

	if worker == nil {
		return s.getEventsByTransactionHashRPC(ctx, txHash)
	}

	request := VoyagerRequest{
		ID:          fmt.Sprintf("events_tx_%s", txHash),
		RequestType: "events_by_tx",
		TxHash:      txHash,
		Limit:       limit,
	}

	events, err := worker.makeVoyagerEventsByTxAPICall(request)
	if err == nil {
		return events, nil
	}

	logger.WithFields(logger.Fields{
		"TxHash":        txHash,
		"VoyagerError":  err.Error(),
		"FallbackToRPC": true,
	}).Warnf("Voyager failed, falling back to RPC for events by transaction hash")

	return s.getEventsByTransactionHashRPC(ctx, txHash)
}

// getEventsByTransactionHashRPC fetches events by transaction hash using RPC as fallback
func (s *VoyagerService) getEventsByTransactionHashRPC(ctx context.Context, txHash string) ([]map[string]interface{}, error) {
	client, err := getStarknetRPCClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create RPC client: %w", err)
	}

	txHashFelt, err := utils.HexToFelt(txHash)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction hash: %w", err)
	}

	// GetTransactionReceipt with nil address now works (fixed in client.go to handle nil)
	events, err := client.GetTransactionReceipt(ctx, txHashFelt, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction receipt from RPC: %w", err)
	}

	return events, nil
}

// GetEventsByTransactionHash fetches events by transaction hash (queued version)
func (s *VoyagerService) GetEventsByTransactionHash(ctx context.Context, txHash string, limit int) ([]map[string]interface{}, error) {
	requestID := fmt.Sprintf("events_tx_%s_%d", txHash, limit)

	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	responseChan := make(chan *VoyagerResponse, 1)
	doneChan := make(chan struct{})

	requestContext := &VoyagerRequestContext{
		ID:        requestID,
		CreatedAt: time.Now(),
		Context:   reqCtx,
		Cancel:    cancel,
		Response:  responseChan,
		Done:      doneChan,
	}

	if existingCtx, exists := voyagerPendingRequests.Load(requestID); exists {
		if existingReqCtx, ok := existingCtx.(*VoyagerRequestContext); ok {
			// Wait for the original request to complete instead of consuming its response
			// This ensures the original requester receives the response
			select {
			case <-existingReqCtx.Context.Done():
				// Original request completed, make our own immediate request
				return s.GetEventsByTransactionHashImmediate(ctx, txHash, limit)
			case <-reqCtx.Done():
				return nil, reqCtx.Err()
			}
		}
	}

	voyagerPendingRequests.Store(requestID, requestContext)

	request := VoyagerRequest{
		ID:          requestID,
		RequestType: "events_by_tx",
		TxHash:      txHash,
		Limit:       limit,
		CreatedAt:   time.Now(),
		Timeout:     30,
	}

	requestData, err := json.Marshal(request)
	if err != nil {
		voyagerQueuedRequestIDs.Delete(requestID)
		voyagerPendingRequests.Delete(requestID)
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	if err := storage.RedisClient.RPush(ctx, "voyager_queue", requestData).Err(); err != nil {
		voyagerQueuedRequestIDs.Delete(requestID)
		voyagerPendingRequests.Delete(requestID)
		return nil, fmt.Errorf("failed to queue request: %w", err)
	}

	select {
	case response := <-responseChan:
		if response.Error != nil {
			logger.WithFields(logger.Fields{
				"TxHash":        txHash,
				"VoyagerError":  response.Error.Error(),
				"FallbackToRPC": true,
			}).Warnf("Voyager failed, falling back to RPC for events by transaction hash")
			return s.getEventsByTransactionHashRPC(ctx, txHash)
		}
		if events, ok := response.Data.([]map[string]interface{}); ok {
			return events, nil
		}
		return []map[string]interface{}{}, nil
	case <-reqCtx.Done():
		voyagerPendingRequests.Delete(requestID)
		voyagerQueuedRequestIDs.Delete(requestID)
		return nil, reqCtx.Err()
	case <-doneChan:
		return nil, fmt.Errorf("request was cleaned up")
	}
}

// GetLatestBlockNumber fetches the latest block number from Voyager
func (s *VoyagerService) GetLatestBlockNumber(ctx context.Context) (uint64, error) {
	requestID := "blocks_latest"

	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	responseChan := make(chan *VoyagerResponse, 1)
	doneChan := make(chan struct{})

	requestContext := &VoyagerRequestContext{
		ID:        requestID,
		CreatedAt: time.Now(),
		Context:   reqCtx,
		Cancel:    cancel,
		Response:  responseChan,
		Done:      doneChan,
	}

	if existingCtx, exists := voyagerPendingRequests.Load(requestID); exists {
		if existingReqCtx, ok := existingCtx.(*VoyagerRequestContext); ok {
			// Wait for the original request to complete instead of consuming its response
			// This ensures the original requester receives the response
			select {
			case <-existingReqCtx.Context.Done():
				// Original request completed, make our own request
				// The original request will have been removed from pending, so this will be a new request
				return s.GetLatestBlockNumber(ctx)
			case <-reqCtx.Done():
				return 0, reqCtx.Err()
			}
		}
	}

	voyagerPendingRequests.Store(requestID, requestContext)

	request := VoyagerRequest{
		ID:          requestID,
		RequestType: "blocks",
		Limit:       1,
		CreatedAt:   time.Now(),
		Timeout:     30,
	}

	requestData, err := json.Marshal(request)
	if err != nil {
		voyagerQueuedRequestIDs.Delete(requestID)
		voyagerPendingRequests.Delete(requestID)
		return 0, fmt.Errorf("failed to marshal request: %w", err)
	}

	if err := storage.RedisClient.RPush(ctx, "voyager_queue", requestData).Err(); err != nil {
		voyagerQueuedRequestIDs.Delete(requestID)
		voyagerPendingRequests.Delete(requestID)
		return 0, fmt.Errorf("failed to queue request: %w", err)
	}

	select {
	case response := <-responseChan:
		if response.Error != nil {
			logger.WithFields(logger.Fields{
				"VoyagerError":  response.Error.Error(),
				"FallbackToRPC": true,
			}).Warnf("Voyager failed, falling back to RPC for latest block number")
			return s.getLatestBlockNumberRPC(ctx)
		}
		if block, ok := response.Data.(map[string]interface{}); ok {
			if blockNum, ok := block["blockNumber"].(float64); ok {
				return uint64(blockNum), nil
			}
		}
		return 0, fmt.Errorf("invalid block data")
	case <-reqCtx.Done():
		voyagerPendingRequests.Delete(requestID)
		voyagerQueuedRequestIDs.Delete(requestID)
		return 0, reqCtx.Err()
	case <-doneChan:
		return 0, fmt.Errorf("request was cleaned up")
	}
}

// getLatestBlockNumberRPC fetches latest block number using RPC as fallback
func (s *VoyagerService) getLatestBlockNumberRPC(ctx context.Context) (uint64, error) {
	client, err := getStarknetRPCClient()
	if err != nil {
		return 0, fmt.Errorf("failed to create RPC client: %w", err)
	}

	return client.GetBlockNumber(ctx)
}
