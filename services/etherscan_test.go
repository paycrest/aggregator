package services

import (
	"context"
	"testing"
	"time"

	"github.com/paycrest/aggregator/config"
	"github.com/stretchr/testify/assert"
)

func TestEtherscanService_RateLimiting(t *testing.T) {
	// Reset global rate limiter for clean test state
	globalEtherscanLimiter.mu.Lock()
	globalEtherscanLimiter.tokens = 1
	globalEtherscanLimiter.maxTokens = 1
	globalEtherscanLimiter.lastRefill = time.Now()
	globalEtherscanLimiter.mu.Unlock()

	// Create a service instance directly for testing
	service := &EtherscanService{
		config: &config.EtherscanConfiguration{
			ApiKey: "test-key",
		},
	}

	// Test that multiple calls respect the rate limit
	ctx := context.Background()

	// First call should consume the only available token
	err := service.waitForGlobalRateLimit(ctx)
	assert.NoError(t, err)

	// Second call should wait for token refill
	start := time.Now()
	err = service.waitForGlobalRateLimit(ctx)
	elapsed := time.Since(start)

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, elapsed, 240*time.Millisecond) // Should wait at least 240ms (4 tokens/sec = 250ms per token)
	assert.Less(t, elapsed, 300*time.Millisecond)           // But not more than 300ms
}

func TestEtherscanService_ContextCancellation(t *testing.T) {
	// Reset global rate limiter for clean test state
	globalEtherscanLimiter.mu.Lock()
	globalEtherscanLimiter.tokens = 0 // Start with no tokens to force waiting
	globalEtherscanLimiter.maxTokens = 1
	globalEtherscanLimiter.lastRefill = time.Now()
	globalEtherscanLimiter.mu.Unlock()

	// Create a service instance directly for testing
	service := &EtherscanService{
		config: &config.EtherscanConfiguration{
			ApiKey: "test-key",
		},
	}

	// Create a context that will be cancelled after a short delay
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// This call should wait but then be cancelled
	start := time.Now()
	err := service.waitForGlobalRateLimit(ctx)
	elapsed := time.Since(start)

	// Should return context error and not wait the full 200ms
	assert.Error(t, err)
	assert.Equal(t, context.DeadlineExceeded, err)
	assert.Less(t, elapsed, 100*time.Millisecond) // Should be cancelled before 100ms
}
