package services

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerbalances"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/provisionbucket"
	"github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/services/balance"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

var (
	serverConf = config.ServerConfig()
	orderConf  = config.OrderConfig()
)

type PriorityQueueService struct {
	balanceService *balance.Service
}

// NewPriorityQueueService creates a new instance of PriorityQueueService
func NewPriorityQueueService() *PriorityQueueService {
	return &PriorityQueueService{
		balanceService: balance.New(),
	}
}

// ProcessBucketQueues creates a priority queue for each bucket and saves it to redis
func (s *PriorityQueueService) ProcessBucketQueues() error {
	// ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	// defer cancel()
	ctx := context.Background()

	buckets, err := s.GetProvisionBuckets(ctx)
	if err != nil {
		return fmt.Errorf("ProcessBucketQueues.GetProvisionBuckets: %w", err)
	}

	for _, bucket := range buckets {
		go s.CreatePriorityQueueForBucket(ctx, bucket)
	}

	return nil
}

// GetProvisionBuckets returns a list of buckets with their providers
func (s *PriorityQueueService) GetProvisionBuckets(ctx context.Context) ([]*ent.ProvisionBucket, error) {
	buckets, err := storage.Client.ProvisionBucket.Query().WithCurrency().All(ctx)
	if err != nil {
		return nil, err
	}

	// Filter providers by currency availability and balance for each bucket.
	// Always reconcile provider-bucket links from order tokens (overlap rule, same as profile)
	// so missing links are fixed on each run without waiting for profile updates.
	for _, bucket := range buckets {
		// 1. Reconcile links: find providers whose order tokens overlap this bucket (in bucket currency)
		// and add missing links; optionally remove links for providers who no longer qualify.
		orderTokens, err := storage.Client.ProviderOrderToken.Query().
			Where(
				providerordertoken.HasCurrencyWith(fiatcurrency.IDEQ(bucket.Edges.Currency.ID)),
				providerordertoken.HasProviderWith(providerprofile.IsActive(true)),
			).
			WithProvider().
			WithCurrency().
			All(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":           fmt.Sprintf("%v", err),
				"BucketMinAmount": bucket.MinAmount,
				"BucketMaxAmount": bucket.MaxAmount,
				"Currency":        bucket.Edges.Currency.Code,
			}).Errorf("Failed to get order tokens for bucket reconciliation")
			continue
		}

		shouldBeLinkedProviderIDs := make(map[string]bool)
		// TODO: this could be done in batch and processed in parallel for better performance
		for _, orderToken := range orderTokens {
			rate := s.tokenRateForBucket(orderToken)
			if rate.IsZero() {
				// Currency edge unloaded or missing; cannot compute overlap. Skip this token so we don't
				// silently exclude the provider, and log so operators see data/loading issues.
				logger.WithFields(logger.Fields{
					"ProviderID":     orderToken.Edges.Provider.ID,
					"BucketID":       bucket.ID,
					"BucketCurrency": bucket.Edges.Currency.Code,
					"OrderTokenID":   orderToken.ID,
				}).Errorf("Skipping overlap check: token rate is zero (currency edge missing or not loaded for order token)")
				continue
			}
			convertedMin := orderToken.MinOrderAmount.Mul(rate)
			convertedMax := orderToken.MaxOrderAmount.Mul(rate)
			// Overlap: bucket [Min, Max] overlaps provider [convertedMin, convertedMax]
			if bucket.MinAmount.LessThanOrEqual(convertedMax) && bucket.MaxAmount.GreaterThanOrEqual(convertedMin) {
				providerID := orderToken.Edges.Provider.ID
				shouldBeLinkedProviderIDs[providerID] = true
				exists, err := orderToken.Edges.Provider.QueryProvisionBuckets().
					Where(provisionbucket.IDEQ(bucket.ID)).
					Exist(ctx)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":          fmt.Sprintf("%v", err),
						"ProviderID":     providerID,
						"BucketCurrency": bucket.Edges.Currency.Code,
					}).Errorf("Failed to check existing bucket for provider")
					continue
				}
				if exists {
					continue
				}
				_, err = storage.Client.ProviderProfile.Update().
					Where(providerprofile.IDEQ(providerID)).
					AddProvisionBuckets(bucket).
					Save(ctx)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":           fmt.Sprintf("%v", err),
						"ProviderID":      providerID,
						"BucketCurrency":  bucket.Edges.Currency.Code,
						"BucketMinAmount": bucket.MinAmount,
						"BucketMaxAmount": bucket.MaxAmount,
					}).Errorf("Failed to add provision bucket to provider")
				}
			}
		}

		// 2. Remove stale links: providers linked to this bucket but no longer having an overlapping token.
		linkedProviders, err := bucket.QueryProviderProfiles().All(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":  fmt.Sprintf("%v", err),
				"Bucket": bucket.ID,
			}).Errorf("Failed to get linked providers for bucket")
		} else {
			for _, p := range linkedProviders {
				if !shouldBeLinkedProviderIDs[p.ID] {
					_, err = storage.Client.ProviderProfile.Update().
						Where(providerprofile.IDEQ(p.ID)).
						RemoveProvisionBuckets(bucket).
						Save(ctx)
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error":      fmt.Sprintf("%v", err),
							"ProviderID": p.ID,
							"BucketID":   bucket.ID,
						}).Errorf("Failed to remove stale provision bucket link")
					}
				}
			}
		}

		// 3. Get available providers (linked + balance + active); requery so newly linked are included.
		availableProviders, err := bucket.QueryProviderProfiles().
			Where(
				providerprofile.IsActive(true),
				providerprofile.VisibilityModeEQ(providerprofile.VisibilityModePublic),
				providerprofile.HasProviderBalancesWith(
					providerbalances.HasFiatCurrencyWith(fiatcurrency.IDEQ(bucket.Edges.Currency.ID)),
					providerbalances.AvailableBalanceGT(bucket.MinAmount),
					providerbalances.IsAvailableEQ(true),
				),
			).
			All(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":           fmt.Sprintf("%v", err),
				"BucketMinAmount": bucket.MinAmount,
				"BucketMaxAmount": bucket.MaxAmount,
				"Currency":        bucket.Edges.Currency.Code,
			}).Errorf("Failed to get available providers for bucket")
			continue
		}

		bucket.Edges.ProviderProfiles = availableProviders

		// If no providers are eligible for this bucket, log balance health for a small sample of
		// candidate providers to aid ops debugging (no new endpoints).
		if len(bucket.Edges.ProviderProfiles) == 0 {
			logger.WithFields(logger.Fields{
				"BucketMinAmount": bucket.MinAmount,
				"BucketMaxAmount": bucket.MaxAmount,
				"Currency":        bucket.Edges.Currency.Code,
			}).Warnf("No eligible providers found for bucket")

			// Sample a few providers linked to this bucket (best effort; avoid heavy DB reads).
			candidates, candErr := bucket.QueryProviderProfiles().
				Where(
					providerprofile.IsActive(true),
					providerprofile.VisibilityModeEQ(providerprofile.VisibilityModePublic),
				).
				Limit(3).
				All(ctx)
			if candErr != nil {
				continue
			}

			for _, p := range candidates {
				bals, balErr := s.balanceService.GetProviderBalances(ctx, p.ID)
				if balErr != nil {
					logger.WithFields(logger.Fields{
						"ProviderID": p.ID,
						"Currency":   bucket.Edges.Currency.Code,
						"Error":      fmt.Sprintf("%v", balErr),
					}).Errorf("Balance health check: failed to load provider balances")
					continue
				}

				for _, b := range bals {
					// Only inspect the relevant fiat currency for this bucket.
					if b.Edges.FiatCurrency == nil || !b.IsAvailable || b.Edges.FiatCurrency.Code != bucket.Edges.Currency.Code {
						continue
					}
					report := s.balanceService.CheckBalanceHealth(b)
					if report == nil || report.Status == "HEALTHY" {
						continue
					}
					logger.WithFields(logger.Fields{
						"ProviderID":       report.ProviderID,
						"CurrencyCode":     report.CurrencyCode,
						"Status":           report.Status,
						"Severity":         report.Severity,
						"AvailableBalance": report.AvailableBalance.String(),
						"ReservedBalance":  report.ReservedBalance.String(),
						"TotalBalance":     report.TotalBalance.String(),
						"IsAvailable":      b.IsAvailable,
						"Issues":           report.Issues,
						"Recommendations":  report.Recommendations,
						"BucketMinAmount":  bucket.MinAmount,
						"BucketMaxAmount":  bucket.MaxAmount,
					}).Errorf("Bucket provider candidate has unhealthy balance")
				}
			}
		}
	}

	return buckets, nil
}

// tokenRateForBucket returns the fiat rate for the order token (token amount -> bucket currency).
// The token must be loaded with WithCurrency() so Edges.Currency and MarketRate are set.
// Returns decimal.Zero when the currency edge is missing (e.g. eager-load failed); callers must
// treat zero as "cannot compute overlap" and log/skip instead of silently excluding providers.
func (s *PriorityQueueService) tokenRateForBucket(orderToken *ent.ProviderOrderToken) decimal.Decimal {
	if orderToken.Edges.Currency == nil {
		return decimal.Zero
	}
	if orderToken.ConversionRateType == providerordertoken.ConversionRateTypeFixed {
		return orderToken.FixedConversionRate
	}
	return orderToken.Edges.Currency.MarketRate.Add(orderToken.FloatingConversionRate)
}

// GetProviderRate returns the rate for a provider
func (s *PriorityQueueService) GetProviderRate(ctx context.Context, provider *ent.ProviderProfile, tokenSymbol string, currency string) (decimal.Decimal, error) {
	// Fetch the token config for the provider
	tokenConfig, err := provider.QueryOrderTokens().
		Where(
			providerordertoken.HasProviderWith(providerprofile.IDEQ(provider.ID)),
			providerordertoken.HasTokenWith(token.SymbolEQ(tokenSymbol)),
			providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(currency)),
		).
		WithProvider().
		WithCurrency().
		Select(
			providerordertoken.FieldConversionRateType,
			providerordertoken.FieldFixedConversionRate,
			providerordertoken.FieldFloatingConversionRate,
		).
		First(ctx)
	if err != nil {
		return decimal.Decimal{}, err
	}

	var rate decimal.Decimal

	if tokenConfig.ConversionRateType == providerordertoken.ConversionRateTypeFixed {
		rate = tokenConfig.FixedConversionRate
	} else {
		// Handle floating rate case
		marketRate := tokenConfig.Edges.Currency.MarketRate
		floatingRate := tokenConfig.FloatingConversionRate // in percentage

		// Calculate the floating rate based on the market rate
		rate = marketRate.Add(floatingRate).RoundBank(2)
	}

	return rate, nil
}

// deleteQueue deletes existing circular queue
func (s *PriorityQueueService) deleteQueue(ctx context.Context, key string) error {
	_, err := storage.RedisClient.Del(ctx, key).Result()
	if err != nil {
		return err
	}

	return nil
}

// CreatePriorityQueueForBucket creates a priority queue for a bucket and saves it to redis
func (s *PriorityQueueService) CreatePriorityQueueForBucket(ctx context.Context, bucket *ent.ProvisionBucket) {
	providers := bucket.Edges.ProviderProfiles

	// Randomize the order of providers
	rand.Shuffle(len(providers), func(i, j int) {
		providers[i], providers[j] = providers[j], providers[i]
	})

	redisKey := fmt.Sprintf("bucket_%s_%s_%s", bucket.Edges.Currency.Code, bucket.MinAmount, bucket.MaxAmount)
	prevRedisKey := redisKey + "_prev"
	tempRedisKey := redisKey + "_temp"

	// Copy the current queue to the previous queue (backup before rebuilding)
	prevData, err := storage.RedisClient.LRange(ctx, redisKey, 0, -1).Result()
	if err != nil && err != context.Canceled {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Key":   redisKey,
		}).Errorf("failed to fetch provider rates")
		// If we can't read current queue, abort to prevent data loss
		return
	}

	// Convert []string to []interface{}
	prevValues := make([]interface{}, len(prevData))
	for i, v := range prevData {
		prevValues[i] = v
	}

	// Delete the previous queue before backing up
	err = s.deleteQueue(ctx, prevRedisKey)
	if err != nil && err != context.Canceled {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Key":   prevRedisKey,
		}).Errorf("failed to delete previous provider queue")
	}

	// Update the previous queue with current queue data (backup)
	if len(prevValues) > 0 {
		err = storage.RedisClient.RPush(ctx, prevRedisKey, prevValues...).Err()
		if err != nil && err != context.Canceled {
			logger.WithFields(logger.Fields{
				"Error":  fmt.Sprintf("%v", err),
				"Key":    prevRedisKey,
				"Values": prevValues,
			}).Errorf("failed to store previous provider rates")
			// If backup fails, abort to prevent data loss
			return
		}
	}

	// Delete the temporary queue if it exists (from a previous failed build)
	err = s.deleteQueue(ctx, tempRedisKey)
	if err != nil && err != context.Canceled {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Key":   tempRedisKey,
		}).Errorf("failed to delete temporary provider queue")
	}

	// TODO: add also the checks for all the currencies that a provider has

	// Build new queue in temporary key first
	newQueueEntries := 0
	for _, provider := range providers {
		if orderConf.FallbackProviderID != "" && provider.ID == orderConf.FallbackProviderID {
			continue
		}
		exists, err := provider.QueryProviderBalances().
			Where(providerbalances.HasFiatCurrencyWith(fiatcurrency.IDEQ(bucket.Edges.Currency.ID))).
			Exist(ctx)
		if err != nil || !exists {
			continue
		}
		orderTokens, err := storage.Client.ProviderOrderToken.
			Query().
			Where(
				providerordertoken.HasProviderWith(providerprofile.IDEQ(provider.ID)),
				providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(bucket.Edges.Currency.Code)),
				providerordertoken.SettlementAddressNEQ(""),
			).
			WithToken().
			All(ctx)
		if err != nil {
			if err != context.Canceled {
				logger.WithFields(logger.Fields{
					"Error":      fmt.Sprintf("%v", err),
					"ProviderID": provider.ID,
					"Currency":   bucket.Edges.Currency.Code,
				}).Errorf("failed to get tokens for provider")
			}
			continue
		}

		// Use map to deduplicate by symbol:network combination
		// This allows same token symbol on different networks (e.g., USDT on Ethereum vs Tron)
		tokenKeys := make(map[string]bool)
		for _, orderToken := range orderTokens {
			// Create a unique key combining symbol and network
			tokenKey := fmt.Sprintf("%s:%s", orderToken.Edges.Token.Symbol, orderToken.Network)
			if tokenKeys[tokenKey] {
				continue
			}
			tokenKeys[tokenKey] = true

			rate, err := s.GetProviderRate(ctx, provider, orderToken.Edges.Token.Symbol, bucket.Edges.Currency.Code)
			if err != nil {
				if err != context.Canceled {
					logger.WithFields(logger.Fields{
						"Error":      fmt.Sprintf("%v", err),
						"ProviderID": provider.ID,
						"Token":      orderToken.Edges.Token.Symbol,
						"Currency":   bucket.Edges.Currency.Code,
					}).Errorf("failed to get rate for provider")
				}
				continue
			}

			if rate.IsZero() {
				continue
			}

			// Check provider's rate against the market rate to ensure it's not too far off
			percentDeviation := utils.AbsPercentageDeviation(bucket.Edges.Currency.MarketRate, rate)

			isLocalStablecoin := strings.Contains(orderToken.Edges.Token.Symbol, bucket.Edges.Currency.Code)
			if serverConf.Environment == "production" && percentDeviation.GreaterThan(orderConf.PercentDeviationFromMarketRate) && !isLocalStablecoin {
				// Skip this provider if the rate is too far off
				// TODO: add a logic to notify the provider(s) to update his rate since it's stale. could be a cron job
				continue
			}

			// Serialize the provider ID, token, network, rate, min and max order amount into a single string
			data := fmt.Sprintf("%s:%s:%s:%s:%s:%s", provider.ID, orderToken.Edges.Token.Symbol, orderToken.Network, rate, orderToken.MinOrderAmount, orderToken.MaxOrderAmount)

			// Enqueue the serialized data into the temporary circular queue
			err = storage.RedisClient.RPush(ctx, tempRedisKey, data).Err()
			if err == nil {
				newQueueEntries++
			} else if err != context.Canceled {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"Key":   tempRedisKey,
					"Data":  data,
				}).Errorf("failed to enqueue provider data to circular queue")
			}
		}
	}

	// Only swap queues if new queue has entries, otherwise keep the old queue
	if newQueueEntries > 0 {
		// Delete the current queue
		err = s.deleteQueue(ctx, redisKey)
		if err != nil && err != context.Canceled {
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
				"Key":   redisKey,
			}).Errorf("failed to delete existing circular queue")
			// Clean up temp queue if deletion failed
			_ = s.deleteQueue(ctx, tempRedisKey)
			return
		}

		// Rename temp queue to current queue (atomic operation)
		// Since Redis doesn't have RENAME for lists, we copy and delete
		tempData, err := storage.RedisClient.LRange(ctx, tempRedisKey, 0, -1).Result()
		if err != nil && err != context.Canceled {
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
				"Key":   tempRedisKey,
			}).Errorf("failed to read temporary queue for swap")
			// Clean up temp queue
			_ = s.deleteQueue(ctx, tempRedisKey)
			return
		}

		// Copy temp queue to current queue
		if len(tempData) > 0 {
			tempValues := make([]interface{}, len(tempData))
			for i, v := range tempData {
				tempValues[i] = v
			}
			err = storage.RedisClient.RPush(ctx, redisKey, tempValues...).Err()
			if err != nil && err != context.Canceled {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"Key":   redisKey,
				}).Errorf("failed to copy temporary queue to current queue")
				// Clean up temp queue
				_ = s.deleteQueue(ctx, tempRedisKey)
				return
			}
		}

		// Delete temporary queue after successful swap
		err = s.deleteQueue(ctx, tempRedisKey)
		if err != nil && err != context.Canceled {
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
				"Key":   tempRedisKey,
			}).Errorf("failed to delete temporary queue after swap (non-critical)")
		}
	} else {
		// New queue is empty, keep the old queue and clean up temp
		_ = s.deleteQueue(ctx, tempRedisKey)
		// Sanitize retained queue: remove fallback provider entries when config dictates
		if orderConf.FallbackProviderID != "" {
			oldData, err := storage.RedisClient.LRange(ctx, redisKey, 0, -1).Result()
			if err == nil && len(oldData) > 0 {
				var filtered []interface{}
				for _, entry := range oldData {
					parts := strings.SplitN(entry, ":", 2)
					if len(parts) >= 1 && parts[0] != orderConf.FallbackProviderID {
						filtered = append(filtered, entry)
					}
				}
				if len(filtered) < len(oldData) {
					_ = s.deleteQueue(ctx, redisKey)
					if len(filtered) > 0 {
						_ = storage.RedisClient.RPush(ctx, redisKey, filtered...).Err()
					}
				}
			}
		}
	}
}

// AssignPaymentOrder assigns payment orders to providers
func (s *PriorityQueueService) AssignPaymentOrder(ctx context.Context, order types.PaymentOrderFields) error {
	orderIDPrefix := strings.Split(order.ID.String(), "-")[0]

	// Both regular and OTC orders must have a provision bucket
	if order.ProvisionBucket == nil {
		logger.WithFields(logger.Fields{
			"OrderID":   order.ID.String(),
			"OrderType": order.OrderType,
			"Reason":    "internal: Order missing provision bucket",
		}).Errorf("AssignPaymentOrder.MissingProvisionBucket")
		return fmt.Errorf("order %s (type: %s) is missing provision bucket", order.ID.String(), order.OrderType)
	}
	if order.ProvisionBucket.Edges.Currency == nil {
		logger.WithFields(logger.Fields{
			"OrderID":   order.ID.String(),
			"OrderType": order.OrderType,
			"Reason":    "internal: Provision bucket missing currency",
		}).Errorf("AssignPaymentOrder.MissingCurrency")
		return fmt.Errorf("provision bucket for order %s (type: %s) is missing currency", order.ID.String(), order.OrderType)
	}

	// Defensive check: Verify order is in a valid state for assignment
	// This prevents duplicate assignments from concurrent sources
	currentOrder, err := storage.Client.PaymentOrder.Get(ctx, order.ID)
	if err == nil {
		// Order exists - check if it's in a state that allows assignment
		if currentOrder.Status != paymentorder.StatusPending {
			logger.WithFields(logger.Fields{
				"OrderID": order.ID.String(),
				"Status":  currentOrder.Status,
			}).Errorf("AssignPaymentOrder: Order is not in pending state, skipping assignment")
			return nil // Not an error, just skip
		}

		// Check if order request already exists in Redis (idempotency check)
		orderKey := fmt.Sprintf("order_request_%s", order.ID)
		exists, err := storage.RedisClient.Exists(ctx, orderKey).Result()
		if err == nil && exists > 0 {
			logger.WithFields(logger.Fields{
				"OrderID": order.ID.String(),
				"Status":  currentOrder.Status,
			}).Errorf("AssignPaymentOrder: Order request already exists, skipping duplicate assignment")
			return nil // Not an error, already assigned
		}
	} else if !ent.IsNotFound(err) {
		// Error fetching order (other than not found)
		logger.WithFields(logger.Fields{
			"Error":   fmt.Sprintf("%v", err),
			"OrderID": order.ID.String(),
		}).Errorf("AssignPaymentOrder: Failed to check order status")
		// Continue anyway - might be a new order
	}

	excludeList, err := storage.RedisClient.LRange(ctx, fmt.Sprintf("order_exclude_list_%s", order.ID), 0, -1).Result()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
		}).Errorf("failed to get exclude list")
		return err
	}

	// Sends order directly to the specified provider in order.
	// Incase of failure, do nothing. The order will eventually refund
	// For OTC orders: skip if provider appears in exclude list at all
	// For regular orders: only skip if provider has exceeded max retry attempts
	if order.ProviderID != "" {
		excludeCount := s.countProviderInExcludeList(excludeList, order.ProviderID)
		shouldSkip := false
		if order.OrderType == "otc" {
			// OTC orders skip immediately if provider is in exclude list
			shouldSkip = excludeCount > 0
		} else {
			// Regular orders allow up to max retry attempts
			shouldSkip = excludeCount >= orderConf.ProviderMaxRetryAttempts
		}
		if shouldSkip {
			// Provider should be skipped, continue to queue matching
		} else {
			provider, err := storage.Client.ProviderProfile.
				Query().
				Where(
					providerprofile.IDEQ(order.ProviderID),
				).
				Only(ctx)

			if err == nil {
				// TODO: check for provider's minimum and maximum rate for negotiation
				// Update the rate with the current rate if order was last updated more than 10 mins ago
				if !order.UpdatedAt.IsZero() && order.UpdatedAt.Before(time.Now().Add(-10*time.Minute)) {
					order.Rate, err = s.GetProviderRate(ctx, provider, order.Token.Symbol, order.ProvisionBucket.Edges.Currency.Code)
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error":      fmt.Sprintf("%v", err),
							"OrderID":    order.ID.String(),
							"ProviderID": order.ProviderID,
						}).Errorf("failed to get rate for provider")
					}
					_, err = storage.Client.PaymentOrder.
						Update().
						Where(paymentorder.MessageHashEQ(order.MessageHash)).
						SetRate(order.Rate).
						Save(ctx)
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error":      fmt.Sprintf("%v", err),
							"OrderID":    order.ID.String(),
							"ProviderID": order.ProviderID,
						}).Errorf("failed to update rate for provider")
					}
				}

				// Handle OTC orders differently - no balance reservation, no provision node request
				if order.OrderType == "otc" {
					if err := s.assignOtcOrder(ctx, order); err != nil {
						return err
					}
					return nil
				} else {
					// Regular orders: send order request (balance reservation + provision node)
					err = s.sendOrderRequest(ctx, order)
					if err == nil {
						return nil
					}
					logger.WithFields(logger.Fields{
						"Error":      fmt.Sprintf("%v", err),
						"OrderID":    order.ID.String(),
						"ProviderID": order.ProviderID,
					}).Errorf("failed to send order request to specific provider")
				}
			} else {
				logger.WithFields(logger.Fields{
					"Error":      fmt.Sprintf("%v", err),
					"OrderID":    order.ID.String(),
					"ProviderID": order.ProviderID,
				}).Errorf("failed to get provider")
			}

			if provider != nil && provider.VisibilityMode == providerprofile.VisibilityModePrivate {
				return nil
			}
		}
	}

	// Get the first provider from the circular queue
	redisKey := fmt.Sprintf("bucket_%s_%s_%s", order.ProvisionBucket.Edges.Currency.Code, order.ProvisionBucket.MinAmount, order.ProvisionBucket.MaxAmount)

	// partnerProviders := []string{}

	err = s.matchRate(ctx, redisKey, orderIDPrefix, order, excludeList)
	if err != nil {
		prevRedisKey := redisKey + "_prev"
		err = s.matchRate(ctx, prevRedisKey, orderIDPrefix, order, excludeList)
		if err != nil && !strings.Contains(fmt.Sprintf("%v", err), "redis: nil") {
			return err
		}
	}

	return nil
}

// TryFallbackAssignment attempts to assign the order to the configured fallback provider using only rate and balance checks.
// It accepts *ent.PaymentOrder and converts to the internal assignment type; callers do not need to build PaymentOrderFields.
// Slippage is taken from the fallback provider's ProviderOrderToken (rate_slippage). Returns a clear error if fallback
// was attempted but order rate is outside the fallback provider's acceptable slippage.
func (s *PriorityQueueService) TryFallbackAssignment(ctx context.Context, order *ent.PaymentOrder) error {
	fallbackID := config.OrderConfig().FallbackProviderID
	if fallbackID == "" {
		return fmt.Errorf("fallback provider not configured")
	}
	if order.OrderType == paymentorder.OrderTypeOtc {
		return fmt.Errorf("fallback is only for regular orders, not OTC")
	}

	// Check idempotency first (before any DB state check) to avoid race: another process may assign between state check and assignment.
	orderKey := fmt.Sprintf("order_request_%s", order.ID)
	exists, err := storage.RedisClient.Exists(ctx, orderKey).Result()
	if err != nil {
		return fmt.Errorf("fallback: failed to check order_request: %w", err)
	}
	if exists > 0 {
		return fmt.Errorf("fallback: order %s already has an active order_request", order.ID)
	}

	// Verify order is still in a state that allows assignment; DB-level idempotency for fallback.
	// Eagerly load ProvisionBucket+Currency so we never need a separate fallback query for them.
	currentOrder, err := storage.Client.PaymentOrder.Query().
		Where(paymentorder.IDEQ(order.ID)).
		WithProvisionBucket(func(pb *ent.ProvisionBucketQuery) {
			pb.WithCurrency()
		}).
		Only(ctx)
	if err != nil {
		return fmt.Errorf("fallback: failed to load order: %w", err)
	}
	if !currentOrder.FallbackTriedAt.IsZero() {
		return fmt.Errorf("fallback: order %s already had fallback assignment tried", order.ID)
	}
	if currentOrder.Status != paymentorder.StatusPending && currentOrder.Status != paymentorder.StatusCancelled {
		return fmt.Errorf("fallback: order %s is in state %s, not assignable", order.ID, currentOrder.Status)
	}

	// Convert ent order to PaymentOrderFields for the rest of the fallback logic
	if order.AccountIdentifier == "" || order.Institution == "" || order.AccountName == "" {
		return fmt.Errorf("fallback: order %s has no recipient information", order.ID.String())
	}
	fields := types.PaymentOrderFields{
		ID:                order.ID,
		OrderType:         order.OrderType.String(),
		Token:             order.Edges.Token,
		Network:           nil,
		GatewayID:         order.GatewayID,
		Amount:            order.Amount,
		Rate:              order.Rate,
		Institution:       order.Institution,
		AccountIdentifier: order.AccountIdentifier,
		AccountName:       order.AccountName,
		ProviderID:        "",
		ProvisionBucket:   currentOrder.Edges.ProvisionBucket,
		MessageHash:       order.MessageHash,
		Memo:              order.Memo,
		UpdatedAt:         order.UpdatedAt,
		CreatedAt:         order.CreatedAt,
	}
	if order.Edges.Token != nil && order.Edges.Token.Edges.Network != nil {
		fields.Network = order.Edges.Token.Edges.Network
	}

	if fields.Token == nil {
		return fmt.Errorf("fallback: order %s has no token", order.ID.String())
	}

	// If order has no bucket yet, resolve one from institution currency + fiat amount.
	if fields.ProvisionBucket == nil {
		institution, instErr := utils.GetInstitutionByCode(ctx, order.Institution, true)
		if instErr != nil {
			return fmt.Errorf("fallback: cannot resolve bucket for order %s: institution lookup failed: %w", fields.ID.String(), instErr)
		}
		if institution.Edges.FiatCurrency == nil {
			return fmt.Errorf("fallback: cannot resolve bucket for order %s: institution %s has no fiat currency", fields.ID.String(), order.Institution)
		}
		fiatAmount := order.Amount.Mul(order.Rate)
		bucket, bErr := storage.Client.ProvisionBucket.
			Query().
			Where(
				provisionbucket.MaxAmountGTE(fiatAmount),
				provisionbucket.MinAmountLTE(fiatAmount),
				provisionbucket.HasCurrencyWith(fiatcurrency.IDEQ(institution.Edges.FiatCurrency.ID)),
			).
			WithCurrency().
			Only(ctx)
		if bErr != nil {
			return fmt.Errorf("fallback: no matching provision bucket for order %s (fiat %s %s): %w",
				fields.ID.String(), fiatAmount.String(), institution.Edges.FiatCurrency.Code, bErr)
		}
		fields.ProvisionBucket = bucket
		// Persist so later flows (e.g. FulfillOrder) see the bucket and do not panic on nil ProvisionBucket
		if _, upErr := storage.Client.PaymentOrder.UpdateOneID(fields.ID).SetProvisionBucket(bucket).Save(ctx); upErr != nil {
			return fmt.Errorf("fallback: failed to set provision bucket on order %s: %w", fields.ID.String(), upErr)
		}
	}

	bucketCurrency := fields.ProvisionBucket.Edges.Currency
	if bucketCurrency == nil {
		return fmt.Errorf("fallback: provision bucket %d missing currency", fields.ProvisionBucket.ID)
	}

	// Resolve fallback provider
	provider, err := storage.Client.ProviderProfile.Get(ctx, fallbackID)
	if err != nil {
		if ent.IsNotFound(err) {
			return fmt.Errorf("fallback provider %s not found", fallbackID)
		}
		return fmt.Errorf("failed to get fallback provider: %w", err)
	}

	network := fields.Token.Edges.Network
	if network == nil {
		var nErr error
		network, nErr = fields.Token.QueryNetwork().Only(ctx)
		if nErr != nil {
			return fmt.Errorf("fallback: token missing network: %w", nErr)
		}
	}

	// ProviderOrderToken for fallback (token, network, currency) – same pattern as matchRate, carries provider-configured rate_slippage.
	// IsAvailableEQ(true) is intentional: fallback is only used when it has available balance for the currency, same as regular queue.
	providerToken, err := storage.Client.ProviderOrderToken.
		Query().
		Where(
			providerordertoken.NetworkEQ(network.Identifier),
			providerordertoken.HasProviderWith(
				providerprofile.IDEQ(fallbackID),
				providerprofile.HasProviderBalancesWith(
					providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(bucketCurrency.Code)),
					providerbalances.IsAvailableEQ(true),
				),
			),
			providerordertoken.HasTokenWith(token.IDEQ(fields.Token.ID)),
			providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(bucketCurrency.Code)),
			providerordertoken.SettlementAddressNEQ(""),
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return fmt.Errorf("fallback provider %s has no order token for %s/%s/%s", fallbackID, fields.Token.Symbol, network.Identifier, bucketCurrency.Code)
		}
		return fmt.Errorf("fallback: failed to get provider order token: %w", err)
	}

	// Rate check: must match what fallback provider can take (use token's rate_slippage)
	providerRate, err := s.GetProviderRate(ctx, provider, fields.Token.Symbol, bucketCurrency.Code)
	if err != nil {
		return fmt.Errorf("fallback: failed to get provider rate: %w", err)
	}
	allowedDeviation := fields.Rate.Mul(providerToken.RateSlippage.Div(decimal.NewFromInt(100)))
	if providerRate.Sub(fields.Rate).Abs().GreaterThan(allowedDeviation) {
		logger.WithFields(logger.Fields{
			"OrderID":      fields.ID.String(),
			"FallbackID":   fallbackID,
			"OrderRate":    fields.Rate.String(),
			"ProviderRate": providerRate.String(),
			"SlippagePct":  providerToken.RateSlippage.String(),
		}).Errorf("[FALLBACK_ASSIGNMENT] fallback assignment attempted but order rate is too far from what fallback node can fulfill")
		return fmt.Errorf("fallback assignment attempted for order %s but order rate is too far from what fallback provider %s can fulfill (provider rate %s, order rate %s, allowed slippage %s%%)",
			fields.ID.String(), fallbackID, providerRate.String(), fields.Rate.String(), providerToken.RateSlippage.String())
	}

	// Balance check (same as matchRate)
	bal, err := s.balanceService.GetProviderFiatBalance(ctx, fallbackID, bucketCurrency.Code)
	if err != nil {
		return fmt.Errorf("fallback: failed to get provider balance: %w", err)
	}
	if !s.balanceService.CheckBalanceSufficiency(bal, fields.Amount.Mul(fields.Rate).RoundBank(0)) {
		return fmt.Errorf("fallback provider %s has insufficient balance for order %s", fallbackID, fields.ID.String())
	}

	// Assign to fallback (regular orders only; OTC excluded above)
	fields.ProviderID = fallbackID

	if err := s.sendOrderRequest(ctx, fields); err != nil {
		return fmt.Errorf("fallback: send order request: %w", err)
	}
	if _, setErr := storage.Client.PaymentOrder.UpdateOneID(fields.ID).
		SetFallbackTriedAt(time.Now()).
		SetOrderPercent(decimal.NewFromInt(100)).
		Save(ctx); setErr != nil {
		logger.WithFields(logger.Fields{"OrderID": fields.ID.String(), "Error": setErr}).Errorf("[FALLBACK_ASSIGNMENT] failed to set fallback_tried_at on order")
		return fmt.Errorf("fallback: failed to set fallback_tried_at (idempotency): %w", setErr)
	}
	logger.WithFields(logger.Fields{"OrderID": fields.ID.String(), "FallbackID": fallbackID}).Infof("[FALLBACK_ASSIGNMENT] successful fallback assignment")
	return nil
}

// assignOtcOrder assigns an OTC order to a provider and creates a Redis key for reassignment.
// DB updates are committed first; Redis operations run afterward to avoid mixing transaction scope with Redis.
func (s *PriorityQueueService) assignOtcOrder(ctx context.Context, order types.PaymentOrderFields) error {
	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
		}).Errorf("Failed to start transaction for OTC order assignment")
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// DB only: assign OTC order to provider (no balance reservation, no provision node request)
	if order.ProviderID != "" {
		provider, qErr := tx.ProviderProfile.Query().Where(providerprofile.IDEQ(order.ProviderID)).Only(ctx)
		if qErr != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", qErr),
				"OrderID":    order.ID.String(),
				"ProviderID": order.ProviderID,
			}).Errorf("failed to get provider for OTC order assignment")
			return fmt.Errorf("failed to get provider: %w", qErr)
		}
		if provider != nil {
			_, err = tx.PaymentOrder.
				Update().
				Where(paymentorder.IDEQ(order.ID)).
				SetProvider(provider).
				Save(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":      fmt.Sprintf("%v", err),
					"OrderID":    order.ID.String(),
					"ProviderID": order.ProviderID,
				}).Errorf("failed to assign OTC order to provider")
				return fmt.Errorf("failed to assign OTC order: %w", err)
			}
		}
	}

	if err = tx.Commit(); err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
		}).Errorf("Failed to commit OTC order assignment transaction")
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Redis operations after DB commit to avoid mixing transaction scope with Redis
	orderKey := fmt.Sprintf("order_request_%s", order.ID)
	exists, err := storage.RedisClient.Exists(ctx, orderKey).Result()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"OrderKey":   orderKey,
		}).Errorf("Failed to check if OTC order request exists in Redis")
		return fmt.Errorf("failed to check order_request in Redis: %w", err)
	}
	if exists > 0 {
		// Verify provider matches to avoid DB/Redis inconsistency (same as sendOrderRequest).
		existingProviderID, hgetErr := storage.RedisClient.HGet(ctx, orderKey, "providerId").Result()
		if hgetErr == nil && existingProviderID == order.ProviderID {
			logger.WithFields(logger.Fields{
				"OrderID":    order.ID.String(),
				"ProviderID": order.ProviderID,
				"OrderKey":   orderKey,
			}).Warnf("OTC order request already exists in Redis for same provider - skipping duplicate creation")
			return nil
		}
		if hgetErr == nil && existingProviderID != order.ProviderID {
			logger.WithFields(logger.Fields{
				"OrderID":            order.ID.String(),
				"ProviderID":         order.ProviderID,
				"ExistingProviderID": existingProviderID,
				"OrderKey":           orderKey,
			}).Errorf("OTC order request exists for different provider - DB/Redis consistency issue")
			return fmt.Errorf("order_request exists for different provider (redis=%s, current=%s)", existingProviderID, order.ProviderID)
		}
		// HGet failed or key has no providerId - treat as inconsistency
		verifyErr := hgetErr
		if verifyErr == nil {
			verifyErr = fmt.Errorf("providerId missing in Redis hash")
		}
		logger.WithFields(logger.Fields{
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"OrderKey":   orderKey,
			"Error":      verifyErr,
		}).Errorf("OTC order request exists but could not verify provider - skipping to avoid inconsistency")
		return fmt.Errorf("order_request exists but provider could not be verified: %w", verifyErr)
	}

	orderRequestData := map[string]interface{}{
		"type":       "otc",
		"providerId": order.ProviderID,
	}
	if err = storage.RedisClient.HSet(ctx, orderKey, orderRequestData).Err(); err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"OrderKey":   orderKey,
		}).Errorf("Failed to create Redis key for OTC order")
		return fmt.Errorf("failed to create order_request in Redis: %w", err)
	}
	if err = storage.RedisClient.ExpireAt(ctx, orderKey, time.Now().Add(orderConf.OrderRequestValidityOtc)).Err(); err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"OrderKey":   orderKey,
		}).Errorf("Failed to set TTL for OTC order request")
		_ = storage.RedisClient.Del(ctx, orderKey).Err()
		return fmt.Errorf("failed to set TTL for order_request: %w", err)
	}

	return nil
}

// countProviderInExcludeList counts how many times a provider appears in the exclude list
func (s *PriorityQueueService) countProviderInExcludeList(excludeList []string, providerID string) int {
	count := 0
	for _, id := range excludeList {
		if id == providerID {
			count++
		}
	}
	return count
}

// addProviderToExcludeList adds a provider to the order exclude list with TTL
// This is a best-effort operation - errors are logged but don't fail the operation
func (s *PriorityQueueService) addProviderToExcludeList(ctx context.Context, orderID string, providerID string, ttl time.Duration) {
	orderKey := fmt.Sprintf("order_exclude_list_%s", orderID)
	_, err := storage.RedisClient.RPush(ctx, orderKey, providerID).Result()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    orderID,
			"ProviderID": providerID,
		}).Errorf("failed to push provider to order exclude list")
		return
	}

	// Set TTL for the exclude list
	err = storage.RedisClient.ExpireAt(ctx, orderKey, time.Now().Add(ttl)).Err()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"OrderKey": orderKey,
		}).Errorf("failed to set TTL for order exclude list")
	}
}

// sendOrderRequest sends an order request to a provider
func (s *PriorityQueueService) sendOrderRequest(ctx context.Context, order types.PaymentOrderFields) error {
	// Reserve balance for this order
	currency := order.ProvisionBucket.Edges.Currency.Code
	amount := order.Amount.Mul(order.Rate).RoundBank(0)

	// Start a transaction for the entire operation
	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"Currency":   currency,
			"Amount":     amount.String(),
		}).Errorf("Failed to start transaction for order processing")
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Reserve balance within the transaction
	err = s.balanceService.ReserveFiatBalance(ctx, order.ProviderID, currency, amount, tx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"Currency":   currency,
			"Amount":     amount.String(),
		}).Errorf("Failed to reserve balance for order")
		return err
	}

	// Assign the order to the provider and save it to Redis
	orderKey := fmt.Sprintf("order_request_%s", order.ID)

	// Check if order request already exists to prevent duplicate notifications
	exists, err := storage.RedisClient.Exists(ctx, orderKey).Result()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"OrderKey":   orderKey,
		}).Errorf("Failed to check if order request exists in Redis")
		return err
	}
	if exists > 0 {
		// Order request already exists - this prevents double processing
		// Verify it's for the same provider to avoid provider mismatch issues
		existingProviderID, err := storage.RedisClient.HGet(ctx, orderKey, "providerId").Result()
		if err == nil && existingProviderID == order.ProviderID {
			logger.WithFields(logger.Fields{
				"OrderID":    order.ID.String(),
				"ProviderID": order.ProviderID,
				"OrderKey":   orderKey,
			}).Errorf("Order request already exists in Redis - skipping duplicate notification")
			// Order request already sent, commit transaction and return success
			err = tx.Commit()
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":      fmt.Sprintf("%v", err),
					"OrderID":    order.ID.String(),
					"ProviderID": order.ProviderID,
				}).Errorf("Failed to commit transaction for existing order request")
				return fmt.Errorf("failed to commit transaction: %w", err)
			}
			return nil
		} else if err == nil && existingProviderID != order.ProviderID {
			// Different provider - this shouldn't happen but log it
			logger.WithFields(logger.Fields{
				"OrderID":            order.ID.String(),
				"ProviderID":         order.ProviderID,
				"ExistingProviderID": existingProviderID,
				"OrderKey":           orderKey,
			}).Errorf("Order request exists for different provider - potential race condition")
			_ = tx.Rollback()
			return fmt.Errorf("order request exists for different provider")
		}
	}

	// TODO: Now we need to add currency
	orderRequestData := map[string]interface{}{
		"amount":      order.Amount.Mul(order.Rate).RoundBank(0).String(),
		"institution": order.Institution,
		"currency":    order.ProvisionBucket.Edges.Currency.Code,
		"providerId":  order.ProviderID,
	}

	err = storage.RedisClient.HSet(ctx, orderKey, orderRequestData).Err()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"OrderKey":   orderKey,
		}).Errorf("Failed to map order to a provider in Redis")
		return err
	}

	// Persist order request metadata in a separate key so we can recover provider/currency/amount
	// after the main order_request key expires (Redis expiry events fire after deletion).
	metaKey := fmt.Sprintf("order_request_meta_%s", order.ID)
	metaData := map[string]interface{}{
		"amount":     orderRequestData["amount"],
		"currency":   orderRequestData["currency"],
		"providerId": orderRequestData["providerId"],
	}
	err = storage.RedisClient.HSet(ctx, metaKey, metaData).Err()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"MetaKey":    metaKey,
		}).Errorf("Failed to persist order request metadata in Redis")
		// Cleanup: delete the orphaned order request key before returning
		_ = storage.RedisClient.Del(ctx, orderKey).Err()
		return err
	}

	// Set a TTL for the order request
	err = storage.RedisClient.ExpireAt(ctx, orderKey, time.Now().Add(orderConf.OrderRequestValidity)).Err()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"OrderKey": orderKey,
		}).Errorf("Failed to set TTL for order request")
		// Cleanup: delete the orphaned keys before returning
		cleanupErr := storage.RedisClient.Del(ctx, orderKey).Err()
		if cleanupErr != nil {
			logger.WithFields(logger.Fields{
				"Error":    fmt.Sprintf("%v", cleanupErr),
				"OrderKey": orderKey,
			}).Errorf("Failed to cleanup orderKey after ExpireAt failure")
		}
		_ = storage.RedisClient.Del(ctx, metaKey).Err()
		return err
	}

	// Set TTL for metadata key longer than the order request key to ensure it exists during expiry handling.
	err = storage.RedisClient.ExpireAt(ctx, metaKey, time.Now().Add(orderConf.OrderRequestValidity*2)).Err()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"MetaKey":    metaKey,
		}).Errorf("Failed to set TTL for order request metadata key")
		// Cleanup: delete keys before returning
		_ = storage.RedisClient.Del(ctx, orderKey).Err()
		_ = storage.RedisClient.Del(ctx, metaKey).Err()
		return err
	}

	// Notify the provider
	orderRequestData["orderId"] = order.ID
	err = s.notifyProvider(ctx, orderRequestData)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
		}).Errorf("Failed to notify provider")
		// Cleanup: delete the orphaned keys before returning
		cleanupErr := storage.RedisClient.Del(ctx, orderKey).Err()
		if cleanupErr != nil {
			logger.WithFields(logger.Fields{
				"Error":    fmt.Sprintf("%v", cleanupErr),
				"OrderKey": orderKey,
			}).Errorf("Failed to cleanup orderKey after notifyProvider failure")
		}
		_ = storage.RedisClient.Del(ctx, metaKey).Err()
		return err
	}

	// Commit the transaction if everything succeeded
	err = tx.Commit()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
		}).Errorf("Failed to commit order processing transaction")
		// Cleanup Redis keys since DB transaction failed
		_ = storage.RedisClient.Del(ctx, orderKey).Err()
		_ = storage.RedisClient.Del(ctx, metaKey).Err()
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	logger.WithFields(logger.Fields{
		"OrderID":    order.ID.String(),
		"ProviderID": order.ProviderID,
		"Currency":   currency,
		"Amount":     amount.String(),
	}).Infof("Order processed successfully with balance reserved")

	return nil
}

// notifyProvider sends an order request notification to a provider
// TODO: ideally notifications should be moved to a notification service
func (s *PriorityQueueService) notifyProvider(ctx context.Context, orderRequestData map[string]interface{}) error {
	// TODO: can we add mode and host identifier to redis during priority queue creation?
	providerID := orderRequestData["providerId"].(string)
	delete(orderRequestData, "providerId")

	// Call provider /new_order endpoint using utility function
	data, err := utils.CallProviderWithHMAC(ctx, providerID, "POST", "/new_order", orderRequestData)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
		}).Errorf("failed to call provider /new_order endpoint")
		return err
	}

	// Log successful response data for debugging
	logger.WithFields(logger.Fields{
		"ProviderID": providerID,
		"Data":       data,
	}).Infof("successfully called provider /new_order endpoint")

	return nil
}

// matchRate matches order rate with a provider rate
func (s *PriorityQueueService) matchRate(ctx context.Context, redisKey string, orderIDPrefix string, order types.PaymentOrderFields, excludeList []string) error {
	for index := 0; ; index++ {
		providerData, err := storage.RedisClient.LIndex(ctx, redisKey, int64(index)).Result()
		if err != nil {
			return err
		}

		// if providerData == "" {
		// 	// Reached the end of the queue
		// 	logger.Errorf("%s - rate didn't match a provider, finding a partner provider", orderIDPrefix)

		// 	if len(partnerProviders) == 0 {
		// 		logger.Errorf("%s - no partner providers found", orderIDPrefix)
		// 		return nil
		// 	}

		// 	// Pick a random partner provider
		// 	randomIndex := rand.New(rand.NewSource(time.Now().UnixNano())).Intn(len(partnerProviders))
		// 	providerData = partnerProviders[randomIndex]
		// }

		// Extract the rate from the data (format "providerID:token:network:rate:minAmount:maxAmount")
		parts := strings.Split(providerData, ":")
		if len(parts) != 6 {
			logger.WithFields(logger.Fields{
				"Error":        fmt.Sprintf("%v", err),
				"OrderID":      order.ID.String(),
				"ProviderID":   order.ProviderID,
				"ProviderData": providerData,
			}).Errorf("invalid data format at index %d when matching rate", index)
			continue // Skip this entry due to invalid format
		}

		order.ProviderID = parts[0]

		// Skip entry based on order type and exclude list count
		excludeCount := s.countProviderInExcludeList(excludeList, order.ProviderID)
		shouldSkip := false
		if order.OrderType == "otc" {
			// OTC orders skip immediately if provider is in exclude list
			shouldSkip = excludeCount > 0
		} else {
			// Regular orders allow up to max retry attempts
			shouldSkip = excludeCount >= orderConf.ProviderMaxRetryAttempts
		}
		if shouldSkip {
			continue
		}

		// Skip entry if token doesn't match
		if parts[1] != order.Token.Symbol {
			continue
		}

		// Skip entry if network doesn't match
		network := order.Token.Edges.Network
		if network == nil {
			network, err = order.Token.QueryNetwork().Only(ctx)
			if err != nil {
				continue
			}
		}
		if parts[2] != network.Identifier {
			continue
		}

		// Parse min/max order amounts and validate against order amount
		minOrderAmount, err := decimal.NewFromString(parts[4])
		if err != nil {
			continue
		}
		maxOrderAmount, err := decimal.NewFromString(parts[5])
		if err != nil {
			continue
		}

		// Check if order amount is within provider's min/max order amount limits
		if order.Amount.LessThan(minOrderAmount) {
			// Order amount is below provider's minimum - skip this provider
			continue
		}

		rate, err := decimal.NewFromString(parts[3])
		if err != nil {
			continue
		}

		// Fetch ProviderOrderToken for rate slippage and OTC limit checks
		bucketCurrency := order.ProvisionBucket.Edges.Currency
		if bucketCurrency == nil {
			bucketCurrency, err = order.ProvisionBucket.QueryCurrency().Only(ctx)
			if err != nil {
				continue
			}
		}

		providerToken, err := storage.Client.ProviderOrderToken.
			Query().
			Where(
				providerordertoken.NetworkEQ(network.Identifier),
				providerordertoken.HasProviderWith(
					providerprofile.IDEQ(order.ProviderID),
					providerprofile.HasProviderBalancesWith(
						providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(bucketCurrency.Code)),
						providerbalances.IsAvailableEQ(true),
					),
				),
				providerordertoken.HasTokenWith(token.IDEQ(order.Token.ID)),
				providerordertoken.HasCurrencyWith(
					fiatcurrency.CodeEQ(bucketCurrency.Code),
				),
				providerordertoken.SettlementAddressNEQ(""),
			).
			First(ctx)
		if err != nil {
			continue
		}

		// Check if order amount exceeds provider's max order amount
		if order.Amount.GreaterThan(maxOrderAmount) {
			// Amount exceeds regular max - check OTC limits as fallback
			if providerToken.MinOrderAmountOtc.IsZero() || providerToken.MaxOrderAmountOtc.IsZero() {
				// OTC limits not configured - skip this provider
				continue
			}
			if order.Amount.LessThan(providerToken.MinOrderAmountOtc) || order.Amount.GreaterThan(providerToken.MaxOrderAmountOtc) {
				// Amount outside OTC limits - skip this provider
				continue
			}
		}

		// Calculate allowed deviation based on slippage
		allowedDeviation := order.Rate.Mul(providerToken.RateSlippage.Div(decimal.NewFromInt(100)))

		if rate.Sub(order.Rate).Abs().LessThanOrEqual(allowedDeviation) {
			// Found a match for the rate - handle index pop once (common for both OTC and regular)
			if index == 0 {
				// Match found at index 0, perform LPOP to dequeue
				data, err := storage.RedisClient.LPop(ctx, redisKey).Result()
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":         fmt.Sprintf("%v", err),
						"OrderID":       order.ID.String(),
						"ProviderID":    order.ProviderID,
						"redisKey":      redisKey,
						"orderIDPrefix": orderIDPrefix,
					}).Errorf("failed to dequeue from circular queue when matching rate")
					return err
				}

				// Enqueue data to the end of the queue
				err = storage.RedisClient.RPush(ctx, redisKey, data).Err()
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":         fmt.Sprintf("%v", err),
						"OrderID":       order.ID.String(),
						"ProviderID":    order.ProviderID,
						"redisKey":      redisKey,
						"orderIDPrefix": orderIDPrefix,
					}).Errorf("failed to enqueue to circular queue when matching rate")
					return err
				}
			}

			// For OTC orders, skip balance check and assign order to provider
			if order.OrderType == "otc" {
				if err := s.assignOtcOrder(ctx, order); err != nil {
					logger.WithFields(logger.Fields{
						"Error":      fmt.Sprintf("%v", err),
						"OrderID":    order.ID.String(),
						"ProviderID": order.ProviderID,
					}).Errorf("failed to assign OTC order to provider when matching rate")

					// Add provider to exclude list before continuing to next provider
					s.addProviderToExcludeList(ctx, order.ID.String(), order.ProviderID, orderConf.OrderRequestValidityOtc*2)
					continue
				}
				break
			} else {
				// Regular order - check balance sufficiency
				bal, err := s.balanceService.GetProviderFiatBalance(ctx, order.ProviderID, bucketCurrency.Code)
				if err != nil {
					logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "OrderID": order.ID.String(), "ProviderID": order.ProviderID, "Currency": bucketCurrency.Code}).Errorf("failed to get provider fiat balance")
					continue
				}
				if !s.balanceService.CheckBalanceSufficiency(bal, order.Amount.Mul(order.Rate).RoundBank(0)) {
					logger.WithFields(logger.Fields{"OrderID": order.ID.String(), "ProviderID": order.ProviderID, "Currency": bucketCurrency.Code, "Amount": order.Amount.String()}).Errorf("insufficient balance")
					continue
				}

				// Assign the order to the provider and save it to Redis
				err = s.sendOrderRequest(ctx, order)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":         fmt.Sprintf("%v", err),
						"OrderID":       order.ID.String(),
						"ProviderID":    order.ProviderID,
						"redisKey":      redisKey,
						"orderIDPrefix": orderIDPrefix,
					}).Errorf("failed to send order request to specific provider when matching rate")

					// Add provider to exclude list before reassigning
					s.addProviderToExcludeList(ctx, order.ID.String(), order.ProviderID, orderConf.OrderRequestValidity*4)

					// Note: Balance cleanup is now handled in sendOrderRequest via defer
					// Reassign the payment order to another provider
					return s.AssignPaymentOrder(ctx, order)
				}

				break
			}
		}
	}

	return nil
}
