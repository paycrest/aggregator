package services

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providercurrencies"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/provisionbucket"
	"github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/user"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/logger"
	tokenUtils "github.com/paycrest/aggregator/utils/token"
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

// GetProvisionBuckets returns a list of buckets with their providers
func (s *PriorityQueueService) GetProvisionBuckets(ctx context.Context) ([]*ent.ProvisionBucket, error) {
	buckets, err := storage.Client.ProvisionBucket.
		Query().
		Select(provisionbucket.FieldMinAmount, provisionbucket.FieldMaxAmount).
		WithProviderProfiles(func(ppq *ent.ProviderProfileQuery) {
			// ppq.WithProviderRating(func(prq *ent.ProviderRatingQuery) {
			// 	prq.Select(providerrating.FieldTrustScore)
			// })
			ppq.Select(providerprofile.FieldID)

			// Filter only providers that are active and verified
			ppq.Where(
				providerprofile.IsActive(true),
				providerprofile.HasUserWith(user.KybVerificationStatusEQ(user.KybVerificationStatusApproved)),
				providerprofile.VisibilityModeEQ(providerprofile.VisibilityModePublic),
			)
		}).
		WithCurrency().
		All(ctx)
	if err != nil {
		return nil, err
	}

	// Filter providers by currency availability for each bucket
	for _, bucket := range buckets {
		var availableProviders []*ent.ProviderProfile
		for _, provider := range bucket.Edges.ProviderProfiles {
			// Check if provider is available for this currency
			available, err := storage.Client.ProviderCurrencies.
				Query().
				Where(
					providercurrencies.HasProviderWith(providerprofile.IDEQ(provider.ID)),
					providercurrencies.HasCurrencyWith(fiatcurrency.IDEQ(bucket.Edges.Currency.ID)),
					providercurrencies.IsAvailableEQ(true),
					providercurrencies.AvailableBalanceGT(bucket.MinAmount),
				).
				Exist(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":      fmt.Sprintf("%v", err),
					"ProviderID": provider.ID,
					"CurrencyID": bucket.Edges.Currency.ID,
				}).Errorf("Failed to check provider currency availability")
				continue
			}
			if available {
				availableProviders = append(availableProviders, provider)
			}
		}
		bucket.Edges.ProviderProfiles = availableProviders
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

	// Sends order directly to the specified provider in order.
	// Incase of failure, do nothing. The order will eventually refund
	if order.ProviderID != "" && !utils.ContainsString(excludeList, order.ProviderID) {
		provider, err := storage.Client.ProviderProfile.
			Query().
			Where(
				providerprofile.IDEQ(order.ProviderID),
			).
			Only(ctx)

		if err == nil {
			// TODO: check for provider's minimum and maximum rate for negotiation
			// Update the rate with the current rate if order was last updated more than 10 mins ago
			if order.UpdatedAt.Before(time.Now().Add(-10 * time.Minute)) {
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
			err = s.sendOrderRequest(ctx, order)
			if err == nil {
				return nil
			}
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"OrderID":    order.ID.String(),
				"ProviderID": order.ProviderID,
			}).Errorf("failed to send order request to specific provider")
		} else {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"OrderID":    order.ID.String(),
				"ProviderID": order.ProviderID,
			}).Errorf("failed to get provider")
		}

		if provider.VisibilityMode == providerprofile.VisibilityModePrivate {
			return nil
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

// sendOrderRequest sends an order request to a provider
func (s *PriorityQueueService) sendOrderRequest(ctx context.Context, order types.LockPaymentOrderFields) error {
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
		}).Errorf("failed to map order to a provider in Redis")
		return err
	}

	// Set a TTL for the order request
	err := storage.RedisClient.ExpireAt(ctx, orderKey, time.Now().Add(orderConf.OrderRequestValidity)).Err()
	if err != nil {
		// logger.Errorf("failed to set TTL for order request: %v", err)
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"orderKey": orderKey,
		}).Errorf("failed to set TTL for order request")
		return err
	}

	// Notify the provider
	orderRequestData["orderId"] = order.ID
	if err := s.notifyProvider(ctx, orderRequestData); err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
		}).Errorf("failed to notify provider")
		return err
	}

	return nil
}

// notifyProvider sends an order request notification to a provider
// TODO: ideally notifications should be moved to a notification service
func (s *PriorityQueueService) notifyProvider(ctx context.Context, orderRequestData map[string]interface{}) error {
	// TODO: can we add mode and host identifier to redis during priority queue creation?
	providerID := orderRequestData["providerId"].(string)
	delete(orderRequestData, "providerId")

	provider, err := storage.Client.ProviderProfile.
		Query().
		Where(providerprofile.IDEQ(providerID)).
		WithAPIKey().
		Only(ctx)
	if err != nil {
		return err
	}

	// Compute HMAC
	decodedSecret, err := base64.StdEncoding.DecodeString(provider.Edges.APIKey.Secret)
	if err != nil {
		return err
	}
	decryptedSecret, err := cryptoUtils.DecryptPlain(decodedSecret)
	if err != nil {
		return err
	}

	signature := tokenUtils.GenerateHMACSignature(orderRequestData, string(decryptedSecret))

	// Send POST request to the provider's node
	res, err := fastshot.NewClient(provider.HostIdentifier).
		Config().SetTimeout(30*time.Second).
		Header().Add("X-Request-Signature", signature).
		Build().POST("/new_order").
		Body().AsJSON(orderRequestData).
		Send()
	if err != nil {
		return err
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
		}).Errorf("failed to parse JSON response after new order request with data: %v", data)
		return err
	}

	return nil
}

// matchRate matches order rate with a provider rate
func (s *PriorityQueueService) matchRate(ctx context.Context, redisKey string, orderIDPrefix string, order types.LockPaymentOrderFields, excludeList []string) error {
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

		// Extract the rate from the data (assuming it's in the format "providerID:token:rate:minAmount:maxAmount")
		parts := strings.Split(providerData, ":")
		if len(parts) != 5 {
			logger.WithFields(logger.Fields{
				"Error":        fmt.Sprintf("%v", err),
				"OrderID":      order.ID.String(),
				"ProviderID":   order.ProviderID,
				"ProviderData": providerData,
			}).Errorf("invalid data format at index %d when matching rate", index)
			continue // Skip this entry due to invalid format
		}

		order.ProviderID = parts[0]

		// Skip entry if provider is excluded
		if utils.ContainsString(excludeList, order.ProviderID) {
			continue
		}

		// Skip entry if token doesn't match
		if parts[1] != order.Token.Symbol {
			continue
		}

		// Skip entry if order amount is not within provider's min and max order amount
		minOrderAmount, err := decimal.NewFromString(parts[3])
		if err != nil {
			continue
		}

		maxOrderAmount, err := decimal.NewFromString(parts[4])
		if err != nil {
			continue
		}

		normalizedAmount := order.Amount
		bucketCurrency := order.ProvisionBucket.Edges.Currency
		if bucketCurrency == nil {
			bucketCurrency, err = order.ProvisionBucket.QueryCurrency().Only(ctx)
			if err != nil {
				continue
			}
		}
		if strings.EqualFold(order.Token.BaseCurrency, bucketCurrency.Code) && order.Token.BaseCurrency != "USD" {
			rateResponse, err := utils.GetTokenRateFromQueue("USDT", normalizedAmount, bucketCurrency.Code, bucketCurrency.MarketRate)
			if err != nil {
				continue
			}
			normalizedAmount = order.Amount.Div(rateResponse)
		}
		if normalizedAmount.LessThan(minOrderAmount) || normalizedAmount.GreaterThan(maxOrderAmount) {
			continue
		}

		// Fetch and check provider for rate match
		rate, err := decimal.NewFromString(parts[2])
		if err != nil {
			continue
		}

		network := order.Token.Edges.Network
		if network == nil {
			network, err = order.Token.QueryNetwork().Only(ctx)
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
					providerprofile.HasProviderCurrenciesWith(
						providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(bucketCurrency.Code)),
						providercurrencies.IsAvailableEQ(true),
					),
				),
				providerordertoken.HasTokenWith(token.IDEQ(order.Token.ID)),
				providerordertoken.HasCurrencyWith(
					fiatcurrency.CodeEQ(bucketCurrency.Code),
				),
				providerordertoken.AddressNEQ(""),
			).
			First(ctx)
		if err != nil {
			continue
		}

		// Calculate allowed deviation based on slippage
		allowedDeviation := order.Rate.Mul(providerToken.RateSlippage.Div(decimal.NewFromInt(100)))

		if rate.Sub(order.Rate).Abs().LessThanOrEqual(allowedDeviation) {
			// Check if provider has sufficient balance for this order
			hasSufficientBalance, err := s.balanceService.CheckBalanceSufficiency(ctx, order.ProviderID, bucketCurrency.Code, order.Amount)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":      fmt.Sprintf("%v", err),
					"OrderID":    order.ID.String(),
					"ProviderID": order.ProviderID,
					"Currency":   bucketCurrency.Code,
					"Amount":     order.Amount.String(),
				}).Errorf("failed to check balance sufficiency")
				continue
			}

			if !hasSufficientBalance {
				// TODO: send notification to the provider
				logger.WithFields(logger.Fields{
					"OrderID":    order.ID.String(),
					"ProviderID": order.ProviderID,
					"Currency":   bucketCurrency.Code,
					"Amount":     order.Amount.String(),
				}).Warnf("provider has insufficient balance, skipping")
				continue
			}

			// Found a match for the rate and sufficient balance
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

				// Push provider ID to order exclude list
				orderKey := fmt.Sprintf("order_exclude_list_%s", order.ID)
				_, err = storage.RedisClient.RPush(ctx, orderKey, order.ProviderID).Result()
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":         fmt.Sprintf("%v", err),
						"OrderID":       order.ID.String(),
						"ProviderID":    order.ProviderID,
						"redisKey":      redisKey,
						"orderIDPrefix": orderIDPrefix,
					}).Errorf("failed to push provider to order exclude list when matching rate")
				}

				// Reassign the lock payment order to another provider
				return s.AssignLockPaymentOrder(ctx, order)
			}

			break
		}
	}

	return nil
}
