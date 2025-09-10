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
	"github.com/paycrest/aggregator/ent/providercurrencies"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/user"
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
	balanceService *BalanceManagementService
}

// NewPriorityQueueService creates a new instance of PriorityQueueService
func NewPriorityQueueService() *PriorityQueueService {
	return &PriorityQueueService{
		balanceService: NewBalanceManagementService(),
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

func (s *PriorityQueueService) GetProvisionBuckets(ctx context.Context) ([]*ent.ProvisionBucket, error) {
	buckets, err := storage.Client.ProvisionBucket.Query().WithCurrency().All(ctx)
	if err != nil {
		return nil, err
	}

	// Use existing balance service with its config
	for _, bucket := range buckets {
		healthyProviders, err := s.balanceService.GetHealthyProvidersForCurrency(ctx, bucket.Edges.Currency.Code)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"CurrencyID": bucket.Edges.Currency.ID,
			}).Errorf("Failed to get healthy providers for bucket")
			continue
		}

		bucket.Edges.ProviderProfiles = healthyProviders
	}

	return buckets, nil
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
	// Create a slice to store the provider profiles sorted by trust score
	providers := bucket.Edges.ProviderProfiles
	// sort.SliceStable(providers, func(i, j int) bool {
	// 	trustScoreI, _ := providers[i].Edges.ProviderRating.TrustScore.Float64()
	// 	trustScoreJ, _ := providers[j].Edges.ProviderRating.TrustScore.Float64()
	// 	return trustScoreI > trustScoreJ // Sort in descending order
	// })

	// Randomize the order of providers
	rand.Shuffle(len(providers), func(i, j int) {
		providers[i], providers[j] = providers[j], providers[i]
	})

	redisKey := fmt.Sprintf("bucket_%s_%s_%s", bucket.Edges.Currency.Code, bucket.MinAmount, bucket.MaxAmount)
	prevRedisKey := redisKey + "_prev"

	// Delete the previous queue
	err := s.deleteQueue(ctx, prevRedisKey)
	if err != nil && err != context.Canceled {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Key":   prevRedisKey,
		}).Errorf("failed to delete previous provider queue")
	}

	// Copy the current queue to the previous queue
	prevData, err := storage.RedisClient.LRange(ctx, redisKey, 0, -1).Result()
	if err != nil && err != context.Canceled {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Key":   redisKey,
		}).Errorf("failed to fetch provider rates")
	}

	// Convert []string to []interface{}
	prevValues := make([]interface{}, len(prevData))
	for i, v := range prevData {
		prevValues[i] = v
	}

	// Update the previous queue
	if len(prevValues) > 0 {
		err = storage.RedisClient.RPush(ctx, prevRedisKey, prevValues...).Err()
		if err != nil && err != context.Canceled {
			logger.WithFields(logger.Fields{
				"Error":  fmt.Sprintf("%v", err),
				"Key":    prevRedisKey,
				"Values": prevValues,
			}).Errorf("failed to store previous provider rates")
		}
	}

	// Delete the current queue
	err = s.deleteQueue(ctx, redisKey)
	if err != nil && err != context.Canceled {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Key":   redisKey,
		}).Errorf("failed to delete existing circular queue")
	}

	// TODO: add also the checks for all the currencies that a provider has

	for _, provider := range providers {
		exists, err := provider.QueryProviderCurrencies().
			Where(providercurrencies.HasCurrencyWith(fiatcurrency.IDEQ(bucket.Edges.Currency.ID))).
			Exist(ctx)
		if err != nil || !exists {
			continue
		}
		orderTokens, err := storage.Client.ProviderOrderToken.
			Query().
			Where(
				providerordertoken.HasProviderWith(providerprofile.IDEQ(provider.ID)),
				providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(bucket.Edges.Currency.Code)),
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

		tokenSymbols := []string{}
		for _, orderToken := range orderTokens {
			if utils.ContainsString(tokenSymbols, orderToken.Edges.Token.Symbol) {
				continue
			}
			tokenSymbols = append(tokenSymbols, orderToken.Edges.Token.Symbol)

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

			isLocalStablecoin := strings.Contains(orderToken.Edges.Token.Symbol, bucket.Edges.Currency.Code) && !strings.Contains(orderToken.Edges.Token.Symbol, "USD")
			if serverConf.Environment == "production" && percentDeviation.GreaterThan(orderConf.PercentDeviationFromMarketRate) && !isLocalStablecoin {
				// Skip this provider if the rate is too far off
				// TODO: add a logic to notify the provider(s) to update his rate since it's stale. could be a cron job
				continue
			}

			// Serialize the provider ID, token, rate, min and max order amount into a single string
			data := fmt.Sprintf("%s:%s:%s:%s:%s", provider.ID, orderToken.Edges.Token.Symbol, rate, orderToken.MinOrderAmount, orderToken.MaxOrderAmount)

			// Enqueue the serialized data into the circular queue
			err = storage.RedisClient.RPush(ctx, redisKey, data).Err()
			if err != nil && err != context.Canceled {
				logger.WithFields(logger.Fields{
					"Error": fmt.Sprintf("%v", err),
					"Key":   redisKey,
					"Data":  data,
				}).Errorf("failed to enqueue provider data to circular queue")
			}
		}
	}
}

// AssignLockPaymentOrders assigns lock payment orders to providers
func (s *PriorityQueueService) AssignLockPaymentOrder(ctx context.Context, order types.LockPaymentOrderFields) error {
	orderIDPrefix := strings.Split(order.ID.String(), "-")[0]

	excludeList, err := storage.RedisClient.LRange(ctx, fmt.Sprintf("order_exclude_list_%s", order.ID), 0, -1).Result()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
		}).Errorf("failed to get exclude list")
		return err
	}

	// If specific provider is requested, validate their health first
	if order.ProviderID != "" && !utils.ContainsString(excludeList, order.ProviderID) {
		// Check provider health before assignment
		balanceService := NewBalanceManagementService()
		isHealthy, err := balanceService.IsProviderHealthyForCurrency(ctx, order.ProviderID, order.ProvisionBucket.Edges.Currency.Code)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"OrderID":    order.ID.String(),
				"ProviderID": order.ProviderID,
			}).Errorf("failed to check provider health")
		} else if !isHealthy {
			logger.WithFields(logger.Fields{
				"OrderID":    order.ID.String(),
				"ProviderID": order.ProviderID,
			}).Warnf("requested provider is not healthy, falling back to queue")
			order.ProviderID = "" // Clear provider ID to use queue
		} else {
			// Provider is healthy, proceed with assignment
			provider, err := storage.Client.ProviderProfile.
				Query().
				Where(providerprofile.IDEQ(order.ProviderID)).
				Only(ctx)

			if err == nil {
				// Update rate if needed
				if order.UpdatedAt.Before(time.Now().Add(-10 * time.Minute)) {
					order.Rate, err = s.GetProviderRate(ctx, provider, order.Token.Symbol, order.ProvisionBucket.Edges.Currency.Code)
					if err != nil {
						logger.WithFields(logger.Fields{
							"Error":      fmt.Sprintf("%v", err),
							"OrderID":    order.ID.String(),
							"ProviderID": order.ProviderID,
						}).Errorf("failed to get rate for provider")
					} else {
						_, err = storage.Client.PaymentOrder.
							Update().
							Where(paymentorder.IDEQ(order.ID)).
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
				}

				// Validate balance health before sending order
				healthReport, err := balanceService.ValidateProviderBalanceHealth(ctx, order.ProviderID, order.ProvisionBucket.Edges.Currency.Code, order.Amount.Mul(order.Rate).RoundBank(0))
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":      fmt.Sprintf("%v", err),
						"OrderID":    order.ID.String(),
						"ProviderID": order.ProviderID,
					}).Errorf("failed to validate provider balance health")
				} else if healthReport.Status != "healthy" {
					logger.WithFields(logger.Fields{
						"OrderID":      order.ID.String(),
						"ProviderID":   order.ProviderID,
						"HealthStatus": healthReport.Status,
						"Issues":       healthReport.Issues,
					}).Warnf("provider balance health check failed, falling back to queue")
					order.ProviderID = "" // Clear provider ID to use queue
				} else {
					// Provider is healthy, send order
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
				logger.WithFields(logger.Fields{
					"OrderID":    order.ID.String(),
					"ProviderID": order.ProviderID,
				}).Warnf("requested provider is private, falling back to queue")
				order.ProviderID = "" // use queue below
			}
		}
	}

	// Use queue-based assignment with health checks
	redisKey := fmt.Sprintf("bucket_%s_%s_%s", order.ProvisionBucket.Edges.Currency.Code, order.ProvisionBucket.MinAmount, order.ProvisionBucket.MaxAmount)

	err = s.matchRateWithHealthCheck(ctx, redisKey, orderIDPrefix, order, excludeList)
	if err != nil {
		prevRedisKey := redisKey + "_prev"
		err = s.matchRateWithHealthCheck(ctx, prevRedisKey, orderIDPrefix, order, excludeList)
		if err != nil && !strings.Contains(fmt.Sprintf("%v", err), "redis: nil") {
			return err
		}
	}

	return nil
}

// sendOrderRequest sends an order request to a provider
func (s *PriorityQueueService) sendOrderRequest(ctx context.Context, order types.LockPaymentOrderFields) error {
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
	err = s.balanceService.ReserveBalance(ctx, order.ProviderID, currency, amount, tx)
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

	// TODO: Now we need to add currency
	orderRequestData := map[string]interface{}{
		"amount":      order.Amount.Mul(order.Rate).RoundBank(0).String(),
		"institution": order.Institution,
		"currency":    order.ProvisionBucket.Edges.Currency.Code,
		"providerId":  order.ProviderID,
	}

	if err := storage.RedisClient.HSet(ctx, orderKey, orderRequestData).Err(); err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"OrderKey":   orderKey,
		}).Errorf("Failed to map order to a provider in Redis")
		return err
	}

	// Set a TTL for the order request
	err = storage.RedisClient.ExpireAt(ctx, orderKey, time.Now().Add(orderConf.OrderRequestValidity)).Err()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"OrderKey": orderKey,
		}).Errorf("Failed to set TTL for order request")
	}

	// Notify the provider
	orderRequestData["orderId"] = order.ID
	if err := s.notifyProvider(ctx, orderRequestData); err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
		}).Errorf("Failed to notify provider")
		return err
	}

	// Commit the transaction if everything succeeded
	if err := tx.Commit(); err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
		}).Errorf("Failed to commit order processing transaction")
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
// func (s *PriorityQueueService) matchRate(ctx context.Context, redisKey string, orderIDPrefix string, order types.LockPaymentOrderFields, excludeList []string) error {
// 	for index := 0; ; index++ {
// 		providerData, err := storage.RedisClient.LIndex(ctx, redisKey, int64(index)).Result()
// 		if err != nil {
// 			return err
// 		}

// 		// if providerData == "" {
// 		// 	// Reached the end of the queue
// 		// 	logger.Errorf("%s - rate didn't match a provider, finding a partner provider", orderIDPrefix)

// 		// 	if len(partnerProviders) == 0 {
// 		// 		logger.Errorf("%s - no partner providers found", orderIDPrefix)
// 		// 		return nil
// 		// 	}

// 		// 	// Pick a random partner provider
// 		// 	randomIndex := rand.New(rand.NewSource(time.Now().UnixNano())).Intn(len(partnerProviders))
// 		// 	providerData = partnerProviders[randomIndex]
// 		// }

// 		// Extract the rate from the data (assuming it's in the format "providerID:token:rate:minAmount:maxAmount")
// 		parts := strings.Split(providerData, ":")
// 		if len(parts) != 5 {
// 			logger.WithFields(logger.Fields{
// 				"Error":        fmt.Sprintf("%v", err),
// 				"OrderID":      order.ID.String(),
// 				"ProviderID":   order.ProviderID,
// 				"ProviderData": providerData,
// 			}).Errorf("invalid data format at index %d when matching rate", index)
// 			continue // Skip this entry due to invalid format
// 		}

// 		order.ProviderID = parts[0]

// 		// Skip entry if provider is excluded
// 		if utils.ContainsString(excludeList, order.ProviderID) {
// 			continue
// 		}

// 		// Skip entry if token doesn't match
// 		if parts[1] != order.Token.Symbol {
// 			continue
// 		}

// 		// Skip entry if order amount is not within provider's min and max order amount
// 		minOrderAmount, err := decimal.NewFromString(parts[3])
// 		if err != nil {
// 			continue
// 		}

// 		maxOrderAmount, err := decimal.NewFromString(parts[4])
// 		if err != nil {
// 			continue
// 		}

// 		normalizedAmount := order.Amount
// 		bucketCurrency := order.ProvisionBucket.Edges.Currency
// 		if bucketCurrency == nil {
// 			bucketCurrency, err = order.ProvisionBucket.QueryCurrency().Only(ctx)
// 			if err != nil {
// 				continue
// 			}
// 		}
// 		if strings.EqualFold(order.Token.BaseCurrency, bucketCurrency.Code) && order.Token.BaseCurrency != "USD" {
// 			rateResponse, err := utils.GetTokenRateFromQueue("USDT", normalizedAmount, bucketCurrency.Code, bucketCurrency.MarketRate)
// 			if err != nil {
// 				continue
// 			}
// 			normalizedAmount = order.Amount.Div(rateResponse)
// 		}
// 		if normalizedAmount.LessThan(minOrderAmount) || normalizedAmount.GreaterThan(maxOrderAmount) {
// 			continue
// 		}

// 		// Fetch and check provider for rate match
// 		rate, err := decimal.NewFromString(parts[2])
// 		if err != nil {
// 			continue
// 		}

// 		network := order.Token.Edges.Network
// 		if network == nil {
// 			network, err = order.Token.QueryNetwork().Only(ctx)
// 			if err != nil {
// 				continue
// 			}
// 		}

// 		providerToken, err := storage.Client.ProviderOrderToken.
// 			Query().
// 			Where(
// 				providerordertoken.NetworkEQ(network.Identifier),
// 				providerordertoken.HasProviderWith(
// 					providerprofile.IDEQ(order.ProviderID),
// 					providerprofile.HasProviderCurrenciesWith(
// 						providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(bucketCurrency.Code)),
// 						providercurrencies.IsAvailableEQ(true),
// 					),
// 				),
// 				providerordertoken.HasTokenWith(token.IDEQ(order.Token.ID)),
// 				providerordertoken.HasCurrencyWith(
// 					fiatcurrency.CodeEQ(bucketCurrency.Code),
// 				),
// 				providerordertoken.AddressNEQ(""),
// 			).
// 			First(ctx)
// 		if err != nil {
// 			continue
// 		}

// 		// Calculate allowed deviation based on slippage
// 		allowedDeviation := order.Rate.Mul(providerToken.RateSlippage.Div(decimal.NewFromInt(100)))

// 		if rate.Sub(order.Rate).Abs().LessThanOrEqual(allowedDeviation) {
// 			// Check if provider has sufficient balance for this order
// 			hasSufficientBalance, err := s.balanceService.CheckBalanceSufficiency(ctx, order.ProviderID, bucketCurrency.Code, order.Amount.Mul(order.Rate).RoundBank(0))
// 			if err != nil {
// 				logger.WithFields(logger.Fields{
// 					"Error":      fmt.Sprintf("%v", err),
// 					"OrderID":    order.ID.String(),
// 					"ProviderID": order.ProviderID,
// 					"Currency":   bucketCurrency.Code,
// 					"Amount":     order.Amount.String(),
// 				}).Errorf("failed to check balance sufficiency")
// 				continue
// 			}

// 			if !hasSufficientBalance {
// 				// TODO: send notification to the provider
// 				logger.WithFields(logger.Fields{
// 					"OrderID":    order.ID.String(),
// 					"ProviderID": order.ProviderID,
// 					"Currency":   bucketCurrency.Code,
// 					"Amount":     order.Amount.String(),
// 				}).Warnf("provider has insufficient balance, skipping")
// 				continue
// 			}

// 			// Found a match for the rate and sufficient balance
// 			if index == 0 {
// 				// Match found at index 0, perform LPOP to dequeue
// 				data, err := storage.RedisClient.LPop(ctx, redisKey).Result()
// 				if err != nil {
// 					logger.WithFields(logger.Fields{
// 						"Error":         fmt.Sprintf("%v", err),
// 						"OrderID":       order.ID.String(),
// 						"ProviderID":    order.ProviderID,
// 						"redisKey":      redisKey,
// 						"orderIDPrefix": orderIDPrefix,
// 					}).Errorf("failed to dequeue from circular queue when matching rate")
// 					return err
// 				}

// 				// Enqueue data to the end of the queue
// 				err = storage.RedisClient.RPush(ctx, redisKey, data).Err()
// 				if err != nil {
// 					logger.WithFields(logger.Fields{
// 						"Error":         fmt.Sprintf("%v", err),
// 						"OrderID":       order.ID.String(),
// 						"ProviderID":    order.ProviderID,
// 						"redisKey":      redisKey,
// 						"orderIDPrefix": orderIDPrefix,
// 					}).Errorf("failed to enqueue to circular queue when matching rate")
// 					return err
// 				}
// 			}

// 			// Assign the order to the provider and save it to Redis
// 			err = s.sendOrderRequest(ctx, order)
// 			if err != nil {
// 				logger.WithFields(logger.Fields{
// 					"Error":         fmt.Sprintf("%v", err),
// 					"OrderID":       order.ID.String(),
// 					"ProviderID":    order.ProviderID,
// 					"redisKey":      redisKey,
// 					"orderIDPrefix": orderIDPrefix,
// 				}).Errorf("failed to send order request to specific provider when matching rate")

// 				// Push provider ID to order exclude list
// 				orderKey := fmt.Sprintf("order_exclude_list_%s", order.ID)
// 				_, err = storage.RedisClient.RPush(ctx, orderKey, order.ProviderID).Result()
// 				if err != nil {
// 					logger.WithFields(logger.Fields{
// 						"Error":         fmt.Sprintf("%v", err),
// 						"OrderID":       order.ID.String(),
// 						"ProviderID":    order.ProviderID,
// 						"redisKey":      redisKey,
// 						"orderIDPrefix": orderIDPrefix,
// 					}).Errorf("failed to push provider to order exclude list when matching rate")
// 				}

// 				// Note: Balance cleanup is now handled in sendOrderRequest via defer
// 				// Reassign the lock payment order to another provider
// 				return s.AssignLockPaymentOrder(ctx, order)
// 			}

// 			break
// 		}
// 	}

// 	return nil
// }

// providerMeetsBucketRequirements checks if a provider meets specific bucket requirements
func (s *PriorityQueueService) providerMeetsBucketRequirements(ctx context.Context, provider *ent.ProviderProfile, bucket *ent.ProvisionBucket) (bool, error) {
	// Check KYB verification status
	if provider.Edges.User == nil || provider.Edges.User.KybVerificationStatus != user.KybVerificationStatusApproved {
		return false, nil
	}

	// Check visibility mode
	if provider.VisibilityMode != providerprofile.VisibilityModePublic {
		return false, nil
	}

	// Check if provider has sufficient balance for bucket minimum amount
	hasBalance, err := s.balanceService.HasSufficientBalance(ctx, provider.ID, bucket.Edges.Currency.Code, bucket.MinAmount)
	if err != nil {
		return false, err
	}

	return hasBalance, nil
}

func (s *PriorityQueueService) matchRateWithHealthCheck(ctx context.Context, redisKey, orderIDPrefix string, order types.LockPaymentOrderFields, excludeList []string) error {
	// Get providers from Redis queue
	providers, err := storage.RedisClient.LRange(ctx, redisKey, 0, -1).Result()
	if err != nil {
		return fmt.Errorf("failed to get providers from queue: %w", err)
	}

	if len(providers) == 0 {
		return fmt.Errorf("no providers available in queue")
	}

	// Try each provider in order
	for i, providerData := range providers {
		parts := strings.Split(providerData, ":")
		// Expected: providerID:token:rate:minAmount:maxAmount
		if len(parts) != 5 {
			continue
		}

		providerID := parts[0]

		queueToken := parts[1]
		minOrderAmount, err := decimal.NewFromString(parts[3])
		if err != nil {
			continue
		}
		maxOrderAmount, err := decimal.NewFromString(parts[4])
		if err != nil {
			continue
		}

		// Token must match
		if !strings.EqualFold(queueToken, order.Token.Symbol) {
			continue
		}

		// Skip if provider is in exclude list
		if utils.ContainsString(excludeList, providerID) {
			continue
		}

		// Check provider health before processing
		balanceService := NewBalanceManagementService()
		isHealthy, err := balanceService.IsProviderHealthyForCurrency(ctx, providerID, order.ProvisionBucket.Edges.Currency.Code)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"OrderID":    order.ID.String(),
				"ProviderID": providerID,
			}).Errorf("failed to check provider health")
			continue
		}

		if !isHealthy {
			logger.WithFields(logger.Fields{
				"OrderID":    order.ID.String(),
				"ProviderID": providerID,
			}).Warnf("provider is not healthy, skipping")
			continue
		}

		// Set provider ID and try to process
		order.ProviderID = providerID

		// Get provider rate
		provider, err := storage.Client.ProviderProfile.Query().Where(providerprofile.IDEQ(providerID)).Only(ctx)
		if err != nil {
			continue
		}

		rate, err := s.GetProviderRate(ctx, provider, order.Token.Symbol, order.ProvisionBucket.Edges.Currency.Code)
 		if err != nil {
 			continue
 		}

		// Validate rate and balance
		providerToken, err := storage.Client.ProviderOrderToken.
			Query().
			Where(
				providerordertoken.HasProviderWith(providerprofile.IDEQ(providerID)),
				providerordertoken.HasTokenWith(token.SymbolEQ(order.Token.Symbol)),
				providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(order.ProvisionBucket.Edges.Currency.Code)),
			).
			Only(ctx)
		if err != nil {
			continue
		}

		allowedDeviation := order.Rate.Mul(providerToken.RateSlippage.Div(decimal.NewFromInt(100)))
		if rate.Sub(order.Rate).Abs().LessThanOrEqual(allowedDeviation) {
			// Enforce provider min/max order constraints from queue snapshot
			normalizedAmount := order.Amount
			if normalizedAmount.LessThan(minOrderAmount) || normalizedAmount.GreaterThan(maxOrderAmount) {
				continue
			}

			// Check balance sufficiency with health validation
			hasSufficientBalance, err := s.balanceService.HasSufficientBalance(ctx, providerID, order.ProvisionBucket.Edges.Currency.Code, order.Amount.Mul(order.Rate).RoundBank(0))
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":      fmt.Sprintf("%v", err),
					"OrderID":    order.ID.String(),
					"ProviderID": providerID,
				}).Errorf("failed to check balance sufficiency")
				continue
			}

			if !hasSufficientBalance {
				logger.WithFields(logger.Fields{
					"OrderID":    order.ID.String(),
					"ProviderID": providerID,
				}).Warnf("provider has insufficient balance, skipping")
				continue
			}

			// Found a healthy provider with sufficient balance
			if i == 0 {
				// Match found at index 0, perform LPOP to dequeue
				err = storage.RedisClient.LPop(ctx, redisKey).Err()
				if err != nil {
					logger.Errorf("Failed to dequeue provider: %v", err)
				}
			} else {
				// Match found at other index, move to end of queue
				err = storage.RedisClient.LRem(ctx, redisKey, 1, providerData).Err()
				if err != nil {
					logger.Errorf("Failed to remove provider from queue: %v", err)
				}
				err = storage.RedisClient.RPush(ctx, redisKey, providerData).Err()
				if err != nil {
					logger.Errorf("Failed to add provider to end of queue: %v", err)
				}
			}

			// Send order request
			err = s.sendOrderRequest(ctx, order)
			if err == nil {
				return nil
			}

			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"OrderID":    order.ID.String(),
				"ProviderID": providerID,
			}).Errorf("failed to send order request")
		}
	}

	return fmt.Errorf("no healthy providers found for order")
}
