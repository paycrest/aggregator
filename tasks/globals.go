package tasks

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils/logger"
)

var orderConf = config.OrderConfig()
var serverConf = config.ServerConfig()

// Provider balances warmup readiness gate (Option B).
// We start an initial pull of provider balances asynchronously at startup and gate
// sender order creation until the warmup completes.
var (
	providerBalancesWarmupStarted atomic.Bool
	providerBalancesWarmupDone    atomic.Bool
	providerBalancesWarmupErr     atomic.Value // stores string
)

func init() {
	// Ensure Load is safe before any Store.
	providerBalancesWarmupErr.Store("")
}

// StartProviderBalancesWarmup starts the initial provider balance fetch in the background.
// It is safe to call multiple times; only the first call starts the warmup.
func StartProviderBalancesWarmup() {
	if !providerBalancesWarmupStarted.CompareAndSwap(false, true) {
		return
	}

	providerBalancesWarmupDone.Store(false)
	providerBalancesWarmupErr.Store("")

	go func() {
		logger.Infof("Provider balances warmup started")
		if err := FetchProviderBalances(); err != nil {
			providerBalancesWarmupErr.Store(err.Error())
			logger.Errorf("Provider balances warmup finished with error: %v", err)
		} else {
			logger.Infof("Provider balances warmup completed successfully")
		}
		providerBalancesWarmupDone.Store(true)
	}()
}

// ProviderBalancesWarmupStatus returns warmup state for readiness endpoints/middleware.
func ProviderBalancesWarmupStatus() (started bool, done bool, errMsg string) {
	started = providerBalancesWarmupStarted.Load()
	done = providerBalancesWarmupDone.Load()
	if v := providerBalancesWarmupErr.Load(); v != nil {
		if s, ok := v.(string); ok {
			errMsg = s
		}
	}
	return started, done, errMsg
}

// Indexing coordination: track addresses currently being indexed to prevent duplicate work
var (
	indexingAddresses sync.Map // address_chainID -> time.Time (when indexing started)
	recentlyIndexed   sync.Map // address_chainID -> time.Time (when last indexed)

	// Minimum time between indexing same address
	indexingCooldown = 10 * time.Second

	// Maximum time an address can be "in progress" before considering it stale
	indexingTimeout = 2 * time.Minute

	// Cleanup interval for stale entries in indexing maps
	indexingCleanupInterval = 3 * time.Minute
)

// acquireDistributedLock acquires a distributed lock using Redis SetNX
// Returns:
//   - cleanup: function to release the lock (call with defer)
//   - acquired: true if lock was acquired, false if another instance has the lock
//   - err: error if lock acquisition failed
func acquireDistributedLock(ctx context.Context, lockKey string, ttl time.Duration, functionName string) (cleanup func(), acquired bool, err error) {
	lockAcquired, err := storage.RedisClient.SetNX(ctx, lockKey, "1", ttl).Result()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
		}).Errorf("%s: Failed to acquire lock", functionName)
		return nil, false, err
	}
	if !lockAcquired {
		// Another instance is already running; skip.
		return nil, false, nil
	}

	// Return cleanup function to release the lock
	cleanup = func() {
		_ = storage.RedisClient.Del(ctx, lockKey).Err()
	}
	return cleanup, true, nil
}

// cleanupIndexingMaps removes stale entries from indexing coordination maps
func cleanupIndexingMaps() {
	now := time.Now()
	var cleanedIndexing, cleanedRecent int

	// Clean up stale "in progress" entries
	indexingAddresses.Range(func(key, value interface{}) bool {
		if startTime, ok := value.(time.Time); ok {
			if now.Sub(startTime) > indexingTimeout {
				indexingAddresses.Delete(key)
				cleanedIndexing++
			}
		}
		return true
	})

	// Clean up old "recently indexed" entries (older than cooldown + 1 hour buffer)
	recentlyIndexed.Range(func(key, value interface{}) bool {
		if lastIndexed, ok := value.(time.Time); ok {
			if now.Sub(lastIndexed) > indexingCooldown+1*time.Hour {
				recentlyIndexed.Delete(key)
				cleanedRecent++
			}
		}
		return true
	})

	if cleanedIndexing > 0 || cleanedRecent > 0 {
		logger.WithFields(logger.Fields{
			"CleanedIndexing": cleanedIndexing,
			"CleanedRecent":   cleanedRecent,
		}).Debugf("Cleaned up stale indexing map entries")
	}
}
