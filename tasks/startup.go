package tasks

import (
	"context"
	"time"

	"github.com/go-co-op/gocron"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils/logger"
)

// SubscribeToRedisKeyspaceEvents subscribes to redis keyspace events according to redis.conf settings
func SubscribeToRedisKeyspaceEvents() {
	ctx := context.Background()

	// Handle expired or deleted order request key events
	orderRequest := storage.RedisClient.PSubscribe(
		ctx,
		"__keyevent@0__:expired:order_request_*",
		"__keyevent@0__:del:order_request_*",
	)
	orderRequestChan := orderRequest.Channel()

	// Start the goroutine with proper cleanup on context cancellation
	go func() {
		defer func() {
			if err := orderRequest.Close(); err != nil {
				logger.Errorf("Error closing Redis subscription: %v", err)
			}
		}()
		ReassignStaleOrderRequest(ctx, orderRequestChan)
	}()
}

// StartCronJobs starts cron jobs
func StartCronJobs() {
	// Use the system's local timezone instead of hardcoded UTC to prevent timezone conflicts
	scheduler := gocron.NewScheduler(time.Local)
	priorityQueue := services.NewPriorityQueueService()

	err := ComputeMarketRate()
	if err != nil {
		logger.Errorf("StartCronJobs for ComputeMarketRate: %v", err)
	}

	if serverConf.Environment != "production" {
		err = priorityQueue.ProcessBucketQueues()
		if err != nil {
			logger.Errorf("StartCronJobs for ProcessBucketQueues: %v", err)
		}
	}

	// Compute market rate every 9 minutes
	_, err = scheduler.Every(9).Minutes().Do(ComputeMarketRate)
	if err != nil {
		logger.Errorf("StartCronJobs for ComputeMarketRate: %v", err)
	}

	// Refresh provision bucket priority queues every X minutes
	_, err = scheduler.Every(orderConf.BucketQueueRebuildInterval).Minutes().Do(priorityQueue.ProcessBucketQueues)
	if err != nil {
		logger.Errorf("StartCronJobs for ProcessBucketQueues: %v", err)
	}

	// Retry failed webhook notifications every 13 minutes
	_, err = scheduler.Every(13).Minutes().Do(RetryFailedWebhookNotifications)
	if err != nil {
		logger.Errorf("StartCronJobs for RetryFailedWebhookNotifications: %v", err)
	}

	// Sync payment order fulfillments every 32 seconds
	_, err = scheduler.Every(32).Seconds().Do(SyncPaymentOrderFulfillments)
	if err != nil {
		logger.Errorf("StartCronJobs for SyncPaymentOrderFulfillments: %v", err)
	}

	// Handle receive address validity every 6 minutes
	_, err = scheduler.Every(6).Minutes().Do(HandleReceiveAddressValidity)
	if err != nil {
		logger.Errorf("StartCronJobs for HandleReceiveAddressValidity: %v", err)
	}

	// Retry stale user operations every 60 seconds
	_, err = scheduler.Every(60).Seconds().Do(RetryStaleUserOperations)
	if err != nil {
		logger.Errorf("StartCronJobs for RetryStaleUserOperations: %v", err)
	}

	// Resolve payment order mishaps every 14 seconds
	_, err = scheduler.Every(14).Seconds().Do(ResolvePaymentOrderMishaps)
	if err != nil {
		logger.Errorf("StartCronJobs for ResolvePaymentOrderMishaps: %v", err)
	}

	// Process stuck validated orders every 12 minutes
	_, err = scheduler.Every(12).Minutes().Do(ProcessStuckValidatedOrders)
	if err != nil {
		logger.Errorf("StartCronJobs for ProcessStuckValidatedOrders: %v", err)
	}

	// Index blockchain events every 4 seconds
	_, err = scheduler.Every(4).Seconds().Do(TaskIndexBlockchainEvents)
	if err != nil {
		logger.Errorf("StartCronJobs for IndexBlockchainEvents: %v", err)
	}

	// Process expired orders refunds every RefundsInterval
	_, err = scheduler.Every(RefundsInterval).Minutes().Do(ProcessExpiredOrdersRefunds)
	if err != nil {
		logger.Errorf("StartCronJobs for ProcessExpiredOrdersRefunds: %v", err)
	}

	// Cleanup stale entries in indexing coordination maps
	_, err = scheduler.Every(indexingCleanupInterval).Do(cleanupIndexingMaps)
	if err != nil {
		logger.Errorf("StartCronJobs for cleanupIndexingMaps: %v", err)
	}

	// Start scheduler
	scheduler.StartAsync()
}
