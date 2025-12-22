package services

import (
	"context"
	"encoding/json"
	"errors"
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
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
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
	ID             string
	CreatedAt      time.Time
	Context        context.Context
	Cancel         context.CancelFunc
	Response       chan *VoyagerResponse
	Done           chan struct{}
	doneOnce       sync.Once        // Ensures Done channel is closed exactly once
	StoredResponse *VoyagerResponse // Stored response for duplicate waiters
	responseMutex  sync.RWMutex
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
	RateLimitedUntil  time.Time
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

// isRateLimited checks if the worker is currently rate limited
func (w *VoyagerWorker) isRateLimited() bool {
	w.Mutex.RLock()
	defer w.Mutex.RUnlock()
	return time.Now().Before(w.RateLimitedUntil)
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

	// Sentinel errors
	ErrWorkerRateLimited = fmt.Errorf("worker is rate limited")

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
			reqCtx.doneOnce.Do(func() { close(reqCtx.Done) })
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
	}).Infof("Voyager worker started")

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

			err := w.processNextRequest(ctx)
			if err != nil {
				if err.Error() == "no requests in queue" {
					consecutiveEmptyPolls++
					if consecutiveEmptyPolls >= maxEmptyPolls {
						ticker.Reset(1 * time.Second)
					}
					continue
				}
				// Check if worker is rate limited - don't record as error
				if errors.Is(err, ErrWorkerRateLimited) {
					// Worker is rate limited, skip without recording error
					continue
				}
				consecutiveEmptyPolls = 0
				ticker.Reset(w.Interval)
				w.recordError()
				logger.WithFields(logger.Fields{
					"WorkerID": w.WorkerID,
					"Error":    fmt.Sprintf("%v", err),
				}).Errorf("Failed to process Voyager request")
			} else {
				consecutiveEmptyPolls = 0
				ticker.Reset(w.Interval)
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
		}).Infof("Voyager circuit breaker opened")
	}
}

// recordRateLimitError records a rate limit error and sets rate limit backoff
func (w *VoyagerWorker) recordRateLimitError() {
	w.Mutex.Lock()
	defer w.Mutex.Unlock()

	w.Errors++
	w.ConsecutiveErrors++
	w.LastFailure = time.Now()
	w.RateLimitedUntil = time.Now().Add(60 * time.Second)

	logger.WithFields(logger.Fields{
		"WorkerID":         w.WorkerID,
		"RateLimitedUntil": w.RateLimitedUntil,
		"TotalErrors":      w.Errors,
	}).Infof("Worker rate limited, backing off for 60 seconds")
}

// recordSuccess records a successful request
func (w *VoyagerWorker) recordSuccess() {
	w.Mutex.Lock()
	defer w.Mutex.Unlock()

	w.Processed++
	w.ConsecutiveErrors = 0
	w.RateLimitedUntil = time.Time{}
}

// processNextRequest processes the next request from the queue
func (w *VoyagerWorker) processNextRequest(ctx context.Context) error {
	// Check if worker is rate limited before consuming queue items
	if w.isRateLimited() {
		return ErrWorkerRateLimited
	}

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

	if apiErr != nil {
		logger.WithFields(logger.Fields{
			"WorkerID":    w.WorkerID,
			"RequestID":   request.ID,
			"RequestType": request.RequestType,
			"Error":       apiErr.Error(),
		}).Infof("Voyager API call failed")
	} else {
		var itemCount int
		if items, ok := data.([]map[string]interface{}); ok {
			itemCount = len(items)
		}
		logger.WithFields(logger.Fields{
			"WorkerID":    w.WorkerID,
			"RequestID":   request.ID,
			"RequestType": request.RequestType,
			"ItemCount":   itemCount,
		}).Infof("Voyager API call successful")
	}

	// Update error counters and handle rate limiting
	if apiErr != nil {
		errorType := classifyVoyagerError(apiErr.Error())
		switch errorType {
		case VoyagerErrorTypeRateLimit:
			atomic.AddInt64(&voyagerRateLimitErrorsCounter, 1)
			w.recordRateLimitError()
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
			response := &VoyagerResponse{
				Data:  data,
				Error: apiErr,
			}

			// Store response for duplicate waiters
			reqCtx.responseMutex.Lock()
			reqCtx.StoredResponse = response
			reqCtx.responseMutex.Unlock()

			// Send to response channel (non-blocking)
			select {
			case reqCtx.Response <- response:
			default:
				logger.WithFields(logger.Fields{
					"WorkerID":  w.WorkerID,
					"RequestID": request.ID,
				}).Debugf("Could not send Voyager response to request")
			}

			reqCtx.Cancel()
			reqCtx.doneOnce.Do(func() { close(reqCtx.Done) })
			voyagerPendingRequests.Delete(request.ID)
			voyagerQueuedRequestIDs.Delete(request.ID)
		}
	}

	return apiErr
}

// makeVoyagerTransfersAPICall makes the actual API call to Voyager for transfers
func (w *VoyagerWorker) makeVoyagerTransfersAPICall(request VoyagerRequest) ([]map[string]interface{}, error) {
	// Build URL: /beta/contracts/{address}/transfers
	url := fmt.Sprintf("https://api.voyager.online/beta/contracts/%s/transfers", request.ToAddress)

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
			} else {
				logger.WithFields(logger.Fields{
					"BlockNumber": request.FromBlock,
					"Error":       err.Error(),
				}).Warnf("Failed to convert block to timestamp")
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
	} else {
		// timestampFrom and timestampTo should be default to 3 days ago and now
		timestampFrom := time.Now().Add(-3 * 24 * time.Hour).Unix()
		params["timestampFrom"] = fmt.Sprintf("%d", timestampFrom)
		params["timestampTo"] = fmt.Sprintf("%d", time.Now().Unix())
	}

	// Add from/to address filters
	if request.ContractAddr != "" {
		params["tokenAddress"] = request.ContractAddr
	}
	if request.FromAddress != "" {
		params["from"] = request.FromAddress
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

	if res.RawResponse.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limit exceeded (429) for address %s", request.Address)
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
			if err != nil {
				logger.WithFields(logger.Fields{
					"BlockNumber": request.FromBlock,
					"RequestID":   request.ID,
					"Error":       err.Error(),
				}).Warnf("Failed to get timestamp for FromBlock in makeVoyagerEventsAPICall")
			} else if fromBlockData == nil {
				logger.WithFields(logger.Fields{
					"BlockNumber": request.FromBlock,
					"RequestID":   request.ID,
				}).Warnf("getBlockByNumber returned nil for FromBlock")
			} else {
				if timestamp, ok := fromBlockData["timestamp"].(float64); ok {
					params["timestampFrom"] = fmt.Sprintf("%.0f", timestamp)
				} else {
					logger.WithFields(logger.Fields{
						"BlockNumber": request.FromBlock,
						"RequestID":   request.ID,
						"DataType":    fmt.Sprintf("%T", fromBlockData["timestamp"]),
					}).Warnf("Unexpected timestamp type for FromBlock")
				}
			}
		}
		if request.ToBlock > 0 {
			toBlockData, err := w.getBlockByNumber(request.ToBlock)
			if err != nil {
				logger.WithFields(logger.Fields{
					"BlockNumber": request.ToBlock,
					"RequestID":   request.ID,
					"Error":       err.Error(),
				}).Warnf("Failed to get timestamp for ToBlock in makeVoyagerEventsAPICall")
			} else if toBlockData == nil {
				logger.WithFields(logger.Fields{
					"BlockNumber": request.ToBlock,
					"RequestID":   request.ID,
				}).Warnf("getBlockByNumber returned nil for ToBlock")
			} else {
				if timestamp, ok := toBlockData["timestamp"].(float64); ok {
					params["timestampTo"] = fmt.Sprintf("%.0f", timestamp)
				} else {
					logger.WithFields(logger.Fields{
						"BlockNumber": request.ToBlock,
						"RequestID":   request.ID,
						"DataType":    fmt.Sprintf("%T", toBlockData["timestamp"]),
					}).Warnf("Unexpected timestamp type for ToBlock")
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

	if res.RawResponse.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limit exceeded (429) for contract %s", request.ContractAddr)
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

	if res.RawResponse.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limit exceeded (429) for tx %s", request.TxHash)
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

	if res.RawResponse.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limit exceeded (429) for blocks")
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
	tokenDecimals, _ := transfer["tokenDecimals"].(float64)

	if tokenDecimals <= 0 {
		logger.WithFields(logger.Fields{
			"TxHash":        txHash,
			"TokenDecimals": tokenDecimals,
		}).Warnf("token decimals must be greater than zero to process transfer value")
		return nil
	}
	if transferValue == "" {
		logger.WithFields(logger.Fields{
			"TxHash": txHash,
		}).Warnf("transfer value is empty")
		return nil
	}
	decimalValue, err := decimal.NewFromString(transferValue)
	if err != nil {
		logger.WithFields(logger.Fields{
			"TxHash":        txHash,
			"TransferValue": transferValue,
			"Error":         err.Error(),
		}).Warnf("invalid transfer value format")
		return nil
	}
	rawValueDecimals := u.ToSubunit(decimalValue, int8(tokenDecimals))

	logger.WithFields(logger.Fields{
		"TxHash":      txHash,
		"BlockNumber": blockNumber,
		"From":        cryptoUtils.NormalizeStarknetAddress(transferFrom),
		"To":          cryptoUtils.NormalizeStarknetAddress(transferTo),
		"Value":       rawValueDecimals.String(),
	}).Infof("Transforming Voyager transfer to RPC format")

	// Create RPC-formatted event
	rpcEvent := map[string]interface{}{
		"transaction_hash": txHash,
		"block_number":     blockNumber,
		"topics":           u.TransferStarknetSelector,
		"decoded": map[string]interface{}{
			"non_indexed_params": map[string]interface{}{
				"from":  cryptoUtils.NormalizeStarknetAddress(transferFrom),
				"to":    cryptoUtils.NormalizeStarknetAddress(transferTo),
				"value": rawValueDecimals.String(),
			},
			"indexed_params": map[string]interface{}{},
		},
	}

	return rpcEvent
}

// TransformVoyagerEventToRPCFormat converts Voyager event format to RPC event format
func TransformVoyagerEventToRPCFormat(event map[string]interface{}) (map[string]interface{}, error) {
	// Voyager format: transactionHash, blockNumber, name, dataDecoded, keyDecoded, fromAddress
	// RPC format: transaction_hash, block_number, decoded.indexed_params, decoded.non_indexed_params

	transactionHash, _ := event["transactionHash"].(string)
	blockNumber, _ := event["blockNumber"].(float64)
	name, _ := event["name"].(string)
	dataDecoded, _ := event["dataDecoded"].([]interface{})
	keyDecoded, _ := event["keyDecoded"].([]interface{})
	fromAddress, _ := event["fromAddress"].(string)
	keys, _ := event["keys"].([]interface{})

	if len(keys) == 0 {
		return nil, fmt.Errorf("event has no keys")
	}

	indexedParams := make(map[string]interface{})
	nonIndexedParams := make(map[string]interface{})
	// Key is expected to be a string
	topics, ok := keys[0].(string)
	if !ok {
		return nil, fmt.Errorf("failed to assert keys[0] as string")
	}

	switch topics {
	case u.OrderCreatedStarknetSelector:
		for _, keyItem := range keyDecoded {
			if keyMap, ok := keyItem.(map[string]interface{}); ok {
				keyName, _ := keyMap["name"].(string)
				keyValue := keyMap["value"]
				switch keyName {
				case "sender", "token":
					indexedParams[keyName] = keyValue
				case "amount":
					orderAmount, err := u.ParseStringAsDecimals(keyValue.(string))
					if err != nil {
						return nil, fmt.Errorf("failed to parse order amount: %v", err)
					}
					indexedParams[keyName] = orderAmount
				default:
					indexedParams[keyName] = keyValue
				}
			}
		}

		for _, dataItem := range dataDecoded {
			if dataMap, ok := dataItem.(map[string]interface{}); ok {
				dataName, _ := dataMap["name"].(string)
				dataValue := dataMap["value"]
				dataType, _ := dataMap["type"].(string)

				switch dataName {
				case "protocol_fee", "rate":
					valueDecimals, err := u.ParseStringAsDecimals(dataValue.(string))
					if err != nil {
						return nil, fmt.Errorf("failed to parse %s: %v", dataName, err)
					}
					nonIndexedParams[dataName] = valueDecimals
				case "order_id":
					nonIndexedParams[dataName] = dataValue
				case "message_hash":
					// Handle ByteArray type specially
					if dataType == "core::byte_array::ByteArray" {
						if byteArrayMap, ok := dataValue.(map[string]interface{}); ok {
							messageHash, err := u.ParseByteArrayFromJSON(byteArrayMap)
							if err != nil {
								nonIndexedParams[dataName] = dataValue
							} else {
								nonIndexedParams[dataName] = messageHash
							}
						} else {
							nonIndexedParams[dataName] = dataValue
						}
					} else {
						nonIndexedParams[dataName] = dataValue
					}
				}
			}
		}

	case u.OrderSettledStarknetSelector:
		for _, keyItem := range keyDecoded {
			if keyMap, ok := keyItem.(map[string]interface{}); ok {
				keyName, _ := keyMap["name"].(string)
				keyValue, _ := keyMap["value"].(string)
				indexedParams[keyName] = keyValue
			}
		}

		for _, dataItem := range dataDecoded {
			if dataMap, ok := dataItem.(map[string]interface{}); ok {
				dataName, _ := dataMap["name"].(string)
				dataValue := dataMap["value"]
				switch dataName {
				case "split_order_id":
					nonIndexedParams[dataName] = dataValue
				case "settle_percent", "rebate_percent":
					percentValue, err := u.ParseStringAsDecimals(dataValue.(string))
					if err != nil {
						return nil, fmt.Errorf("failed to parse %s: %v", dataName, err)
					}
					nonIndexedParams[dataName] = percentValue
				default:
					nonIndexedParams[dataName] = dataValue
				}
			}
		}

	case u.OrderRefundedStarknetSelector:
		for _, keyItem := range keyDecoded {
			if keyMap, ok := keyItem.(map[string]interface{}); ok {
				keyName, _ := keyMap["name"].(string)
				keyValue, _ := keyMap["value"].(string)
				indexedParams[keyName] = keyValue
			}
		}

		for _, dataItem := range dataDecoded {
			if dataMap, ok := dataItem.(map[string]interface{}); ok {
				dataName, _ := dataMap["name"].(string)
				dataValue, _ := dataMap["value"].(string)
				feeValue, err := u.ParseStringAsDecimals(dataValue)
				if err != nil {
					return nil, fmt.Errorf("failed to parse %s: %v", dataName, err)
				}
				nonIndexedParams[dataName] = feeValue
			}
		}

	}

	// Create RPC-formatted event
	rpcEvent := map[string]interface{}{
		"transaction_hash": transactionHash,
		"block_number":     blockNumber,
		"name":             name,
		"topics":           topics,
		"address":          cryptoUtils.NormalizeStarknetAddress(fromAddress),
		"decoded": map[string]interface{}{
			"indexed_params":     indexedParams,
			"non_indexed_params": nonIndexedParams,
		},
	}

	return rpcEvent, nil
}

// TransformRPCEventToTransferFormat converts RPC event format (from GetEventsByTransactionHash) to RPC transfer format
// This is needed when processing transaction hash events that should be treated as transfers
func TransformRPCEventToTransferFormat(event map[string]interface{}) map[string]interface{} {
	// RPC event format: transaction_hash, block_number, decoded.indexed_params, decoded.non_indexed_params
	// RPC transfer format: transaction_hash, block_number, topics, decoded.non_indexed_params (from, to, value)
	needsTransformation, _ := event["needs_transformation"].(bool)
	if !needsTransformation {
		return event
	}

	transactionHash, _ := event["transactionHash"].(string) 
	blockNumber, _ := event["blockNumber"].(float64)
	topics, _ := event["selector"].(string)
	
	// Check if this is a Transfer event
	if topics != u.TransferStarknetSelector {
		logger.WithFields(logger.Fields{
			"TxHash": transactionHash,
			"Topics": topics,
		}).Warnf("Event is not a Transfer event, skipping transformation")
		return nil
	}
	
	dataDecoded, _ := event["dataDecoded"].([]interface{})
	keys, _ := event["keys"].([]interface{})

	if len(keys) == 0 {
		return nil
	}
	
	nonIndexedParams := make(map[string]interface{})

	for _, keyItem := range dataDecoded {
		if keyMap, ok := keyItem.(map[string]interface{}); ok {
			keyName, _ := keyMap["name"].(string)
			keyValue, _ := keyMap["value"].(string)
			switch keyName {
				case "from", "to":
					nonIndexedParams[keyName] = keyValue
				case "value":
					transferAmount, err := u.ParseStringAsDecimals(keyValue)
					if err != nil {
						logger.WithFields(logger.Fields{
							"TxHash": transactionHash,
							"Value":  keyValue,
							"Error":  err.Error(),
						}).Warnf("Failed to parse transfer value")
						return nil
					}
					nonIndexedParams[keyName] = transferAmount
			}
		}
	}

	// Extract transfer fields
	from, _ := nonIndexedParams["from"].(string)
	to, _ := nonIndexedParams["to"].(string)
	value, _ := nonIndexedParams["value"].(decimal.Decimal)
	
	if from == "" || to == "" || value.IsZero() {
		logger.WithFields(logger.Fields{
			"TxHash": transactionHash,
			"From":   from,
			"To":     to,
			"Value":  value,
		}).Warnf("Missing required transfer fields in RPC event")
		return nil
	}
	
	// Create RPC transfer format
	rpcTransfer := map[string]interface{}{
		"transaction_hash": transactionHash,
		"block_number":     blockNumber,
		"topics":           topics,
		"decoded": map[string]interface{}{
			"non_indexed_params": map[string]interface{}{
				"from":  cryptoUtils.NormalizeStarknetAddress(from),
				"to":    cryptoUtils.NormalizeStarknetAddress(to),
				"value": value,
			},
			"indexed_params": map[string]interface{}{},
		},
	}
	
	return rpcTransfer
}

// GetAddressTokenTransfersImmediate fetches token transfers immediately without queuing
func (s *VoyagerService) GetAddressTokenTransfersImmediate(ctx context.Context, tokenAddress string, limit int, fromBlock int64, toBlock int64, fromAddress string, toAddress string) ([]map[string]interface{}, error) {
	// Try Voyager API first - find a non-rate-limited worker
	voyagerWorkerMutex.RLock()
	var worker *VoyagerWorker
	var rateLimitedCount int
	for _, w := range voyagerWorkers {
		if w.isRateLimited() {
			rateLimitedCount++
		} else if worker == nil {
			worker = w
		}
	}
	voyagerWorkerMutex.RUnlock()

	if worker == nil {
		// All workers rate limited or no workers available, skip directly to RPC
		logger.WithFields(logger.Fields{
			"TokenAddress": tokenAddress,
		}).Debugf("All Voyager workers rate limited, using RPC directly")
		return s.getAddressTokenTransfersRPC(ctx, tokenAddress, limit, fromBlock, toBlock)
	}

	request := VoyagerRequest{
		ID:           fmt.Sprintf("transfers_%s_%d", toAddress, limit),
		RequestType:  "transfers",
		ContractAddr: tokenAddress,
		Address:      tokenAddress,
		Limit:        limit,
		FromBlock:    fromBlock,
		ToBlock:      toBlock,
		FromAddress:  fromAddress,
		ToAddress:    toAddress,
	}

	transfers, err := worker.makeVoyagerTransfersAPICall(request)
	if err == nil {
		logger.WithFields(logger.Fields{
			"tokenAddress":  tokenAddress,
			"ToAddress":     toAddress,
			"TransferCount": len(transfers),
			"WorkerID":      worker.WorkerID,
		}).Infof("Voyager API call successful for token transfers")
		// Mark Voyager data as needing transformation
		for i := range transfers {
			transfers[i]["needs_transformation"] = true
		}
		return transfers, nil
	}

	// Voyager failed, fallback to RPC
	logger.WithFields(logger.Fields{
		"tokenAddress":  tokenAddress,
		"ToAddress":     toAddress,
		"FromBlock":     fromBlock,
		"ToBlock":       toBlock,
		"WorkerID":      worker.WorkerID,
		"VoyagerError":  err.Error(),
		"FallbackToRPC": true,
	}).Infof("Voyager failed, falling back to RPC for token transfers")

	rpcTransfers, rpcErr := s.getAddressTokenTransfersRPC(ctx, tokenAddress, limit, fromBlock, toBlock)
	if rpcErr == nil {
		// Mark RPC data as NOT needing transformation
		for i := range rpcTransfers {
			rpcTransfers[i]["needs_transformation"] = false
		}
	}
	return rpcTransfers, rpcErr
}

// getAddressTokenTransfersRPC fetches token transfers using RPC as fallback
func (s *VoyagerService) getAddressTokenTransfersRPC(ctx context.Context, tokenAddress string, limit int, fromBlock int64, toBlock int64) ([]map[string]interface{}, error) {
	client, err := getStarknetRPCClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create RPC client: %w", err)
	}

	addressFelt, err := utils.HexToFelt(tokenAddress)
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
func (s *VoyagerService) GetAddressTokenTransfers(ctx context.Context, tokenAddress string, limit int, fromBlock int64, toBlock int64, fromAddress string, toAddress string) ([]map[string]interface{}, error) {
	// Create request ID
	requestID := fmt.Sprintf("transfers_%s_%d_%d_%d", toAddress, limit, fromBlock, toBlock)

	// Create request context with 120s timeout to account for:
	// - Queue wait time (if workers are busy)
	// - Worker processing time (30s API timeout + overhead)
	// - Block-to-timestamp conversion (2 additional API calls)
	reqCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
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

	// Check for duplicate request - share the response instead of creating new requests
	if existingCtx, exists := voyagerPendingRequests.Load(requestID); exists {
		if existingReqCtx, ok := existingCtx.(*VoyagerRequestContext); ok {
			// Wait for the existing request to complete
			select {
			case <-existingReqCtx.Done:
				// Request completed, check stored response
				existingReqCtx.responseMutex.RLock()
				storedResponse := existingReqCtx.StoredResponse
				existingReqCtx.responseMutex.RUnlock()

				if storedResponse == nil {
					// Request was cleaned up without response, make immediate request
					return s.GetAddressTokenTransfersImmediate(ctx, tokenAddress, limit, fromBlock, toBlock, fromAddress, toAddress)
				}

				if storedResponse.Error != nil {
					// Original request failed, fallback to RPC (single fallback for all waiters)
					return s.getAddressTokenTransfersRPC(ctx, tokenAddress, limit, fromBlock, toBlock)
				}

				if transfers, ok := storedResponse.Data.([]map[string]interface{}); ok {
					return transfers, nil
				}
				return []map[string]interface{}{}, nil
			case <-reqCtx.Done():
				return nil, reqCtx.Err()
			}
		}
	}

	// Track the pending request
	voyagerPendingRequests.Store(requestID, requestContext)

	// Create the request
	request := VoyagerRequest{
		ID:           requestID,
		RequestType:  "transfers",
		ContractAddr: tokenAddress,
		Limit:        limit,
		FromBlock:    fromBlock,
		ToBlock:      toBlock,
		FromAddress:  fromAddress,
		ToAddress:    toAddress,
		CreatedAt:    time.Now(),
		Timeout:      30,
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

	logger.WithFields(logger.Fields{
		"RequestID":       requestID,
		"ContractAddress": tokenAddress,
		"ToAddress":       toAddress,
		"FromBlock":       fromBlock,
		"ToBlock":         toBlock,
		"RequestType":     "transfers",
	}).Infof("Voyager request queued")

	// Wait for response
	select {
	case response := <-responseChan:
		if response.Error != nil {
			// Voyager failed, fallback to RPC
			logger.WithFields(logger.Fields{
				"ContractAddress": tokenAddress,
				"ToAddress":       toAddress,
				"VoyagerError":    response.Error.Error(),
				"FallbackToRPC":   true,
			}).Warnf("Voyager failed, falling back to RPC for token transfers")
			return s.getAddressTokenTransfersRPC(ctx, tokenAddress, limit, fromBlock, toBlock)
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
	// Try Voyager API first - find a non-rate-limited worker
	voyagerWorkerMutex.RLock()
	var worker *VoyagerWorker
	for _, w := range voyagerWorkers {
		if !w.isRateLimited() {
			worker = w
			break
		}
	}
	voyagerWorkerMutex.RUnlock()

	if worker == nil {
		// All workers rate limited or no workers available, skip directly to RPC
		logger.WithFields(logger.Fields{
			"Contract": contractAddress,
		}).Debugf("All Voyager workers rate limited, using RPC directly")
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
		// Mark Voyager data as needing transformation
		for i := range events {
			events[i]["needs_transformation"] = true
		}
		return events, nil
	}

	logger.WithFields(logger.Fields{
		"Contract":      contractAddress,
		"VoyagerError":  err.Error(),
		"FallbackToRPC": true,
	}).Warnf("Voyager failed, falling back to RPC for contract events")

	rpcEvents, rpcErr := s.getContractEventsRPC(ctx, contractAddress, limit, fromBlock, toBlock)
	if rpcErr == nil {
		// Mark RPC data as NOT needing transformation
		for i := range rpcEvents {
			rpcEvents[i]["needs_transformation"] = false
		}
	}
	return rpcEvents, rpcErr
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

	// Use 120s timeout to account for queue wait + processing time
	reqCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
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
			// Wait for the existing request to complete
			select {
			case <-existingReqCtx.Done:
				// Request completed, check stored response
				existingReqCtx.responseMutex.RLock()
				storedResponse := existingReqCtx.StoredResponse
				existingReqCtx.responseMutex.RUnlock()

				if storedResponse == nil {
					// Request was cleaned up without response, make immediate request
					return s.GetContractEventsImmediate(ctx, contractAddress, limit, fromBlock, toBlock)
				}

				if storedResponse.Error != nil {
					// Original request failed, fallback to RPC (single fallback for all waiters)
					return s.getContractEventsRPC(ctx, contractAddress, limit, fromBlock, toBlock)
				}

				if events, ok := storedResponse.Data.([]map[string]interface{}); ok {
					return events, nil
				}
				return []map[string]interface{}{}, nil
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
	// Try Voyager API first - find a non-rate-limited worker
	voyagerWorkerMutex.RLock()
	var worker *VoyagerWorker
	for _, w := range voyagerWorkers {
		if !w.isRateLimited() {
			worker = w
			break
		}
	}
	voyagerWorkerMutex.RUnlock()

	if worker == nil {
		// All workers rate limited or no workers available, skip directly to RPC
		logger.WithFields(logger.Fields{
			"TxHash": txHash,
		}).Debugf("All Voyager workers rate limited, using RPC directly")
		return s.GetEventsByTransactionHashRPC(ctx, txHash)
	}

	request := VoyagerRequest{
		ID:          fmt.Sprintf("events_tx_%s", txHash),
		RequestType: "events_by_tx",
		TxHash:      txHash,
		Limit:       limit,
	}

	events, err := worker.makeVoyagerEventsByTxAPICall(request)
	if err == nil {
		// Mark Voyager data as needing transformation
		for i := range events {
			events[i]["needs_transformation"] = true
		}
		return events, nil
	}

	logger.WithFields(logger.Fields{
		"TxHash":        txHash,
		"VoyagerError":  err.Error(),
		"FallbackToRPC": true,
	}).Warnf("Voyager failed, falling back to RPC for events by transaction hash")

	rpcEvents, rpcErr := s.GetEventsByTransactionHashRPC(ctx, txHash)
	if rpcErr == nil {
		// Mark RPC data as NOT needing transformation
		for i := range rpcEvents {
			rpcEvents[i]["needs_transformation"] = false
		}
	}
	return rpcEvents, rpcErr
}

// GetEventsByTransactionHashRPC fetches events by transaction hash using RPC as fallback
func (s *VoyagerService) GetEventsByTransactionHashRPC(ctx context.Context, txHash string) ([]map[string]interface{}, error) {
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

	// Use 120s timeout to account for queue wait + processing time
	reqCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
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
			// Wait for the existing request to complete
			select {
			case <-existingReqCtx.Done:
				// Request completed, check stored response
				existingReqCtx.responseMutex.RLock()
				storedResponse := existingReqCtx.StoredResponse
				existingReqCtx.responseMutex.RUnlock()

				if storedResponse == nil {
					// Request was cleaned up without response, make immediate request
					return s.GetEventsByTransactionHashImmediate(ctx, txHash, limit)
				}

				if storedResponse.Error != nil {
					// Original request failed, fallback to RPC (single fallback for all waiters)
					return s.GetEventsByTransactionHashRPC(ctx, txHash)
				}

				if events, ok := storedResponse.Data.([]map[string]interface{}); ok {
					return events, nil
				}
				return []map[string]interface{}{}, nil
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
			return s.GetEventsByTransactionHashRPC(ctx, txHash)
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

// GetLatestBlockNumberImmediate fetches the latest block number immediately without queuing
func (s *VoyagerService) GetLatestBlockNumberImmediate(ctx context.Context) (uint64, error) {
	voyagerWorkerMutex.RLock()
	var worker *VoyagerWorker
	if len(voyagerWorkers) > 0 {
		worker = voyagerWorkers[0]
	}
	voyagerWorkerMutex.RUnlock()

	if worker == nil {
		return s.getLatestBlockNumberRPC(ctx)
	}

	block, err := worker.makeVoyagerBlocksAPICall()
	if err == nil {
		if blockNum, ok := block["blockNumber"].(float64); ok {
			return uint64(blockNum), nil
		}
	}

	logger.WithFields(logger.Fields{
		"VoyagerError":  err.Error(),
		"FallbackToRPC": true,
	}).Warnf("Voyager failed, falling back to RPC for latest block number")

	return s.getLatestBlockNumberRPC(ctx)
}

// GetLatestBlockNumber fetches the latest block number from Voyager
func (s *VoyagerService) GetLatestBlockNumber(ctx context.Context) (uint64, error) {
	requestID := "blocks_latest"

	// Use 120s timeout to account for queue wait + processing time
	reqCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
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
				// This prevents infinite recursion that could occur with recursive GetLatestBlockNumber calls
				return s.GetLatestBlockNumberImmediate(ctx)
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
