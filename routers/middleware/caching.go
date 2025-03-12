package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paycrest/aggregator/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
)

// CacheMetrics holds the metrics for cache hits and misses
type CacheMetrics struct {
	hits   prometheus.Counter
	misses prometheus.Counter
}

// CacheService handles Redis operations
type CacheService struct {
	client  *redis.Client
	metrics CacheMetrics
}

type CacheConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
}

// NewCacheService creates a new Redis cache service
func NewCacheService(config config.RedisConfiguration) (*CacheService, error) {
	metrics := CacheMetrics{
		hits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cache_hits_total",
			Help: "Total number of cache hits",
		}),
		misses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cache_misses_total",
			Help: "Total number of cache misses",
		}),
	}
	prometheus.MustRegister(metrics.hits, metrics.misses)

	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", config.Host, config.Port),
		Password: config.Password,
		DB:       config.DB,
	})

	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %v", err)
	}

	return &CacheService{client: client, metrics: metrics}, nil
}

func generateCacheKey(c *gin.Context) string {
	conf := config.RedisConfig()
	path := c.Request.URL.Path
	switch {
	case path == "/v1/currencies":
		return fmt.Sprintf("%s:api:currencies:list", conf.CacheVersion)
	case path == "/v1/pubkey":
		return fmt.Sprintf("%s:api:aggregator:pubkey", conf.CacheVersion)
	case len(c.Param("currency_code")) > 0:
		return fmt.Sprintf("%s:api:institutions:%s", conf.CacheVersion, c.Param("currency_code"))
	default:
		return fmt.Sprintf("%s:api:%s", conf.CacheVersion, path)
	}
}

func generateETag(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (s *CacheService) CacheMiddleware(duration time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := generateCacheKey(c)
		ctx := context.Background()

		// Check ETag
		if etag := c.GetHeader("If-None-Match"); etag != "" {
			if storedETag, _ := s.client.Get(ctx, key+":etag").Result(); etag == storedETag {
				c.Status(http.StatusNotModified)
				return
			}
		}

		// Try to get from cache
		val, err := s.client.Get(ctx, key).Result()
		if err == nil {
			s.metrics.hits.Inc()
			etag, _ := s.client.Get(ctx, key+":etag").Result()

			c.Header("X-Cache", "HIT")
			c.Header("Cache-Control", fmt.Sprintf("max-age=%d, stale-while-revalidate=60", int(duration.Seconds())))
			c.Header("ETag", etag)
			c.String(200, val)

			// Background revalidation if approaching expiry
			if ttl, _ := s.client.TTL(ctx, key).Result(); ttl < time.Minute {
				go s.revalidateCache(c.Copy(), key, duration)
			}
			return
		}

		s.metrics.misses.Inc()
		c.Header("X-Cache", "MISS") // Add this line
		c.Writer = &cacheWriter{ResponseWriter: c.Writer, body: make([]byte, 0)}
		c.Next()

		if c.Writer.Status() == 200 {
			response := c.Writer.(*cacheWriter).body
			etag := generateETag(response)

			s.client.Set(ctx, key, string(response), duration)
			s.client.Set(ctx, key+":etag", etag, duration)

			c.Header("ETag", etag)
			c.Header("Cache-Control", fmt.Sprintf("max-age=%d, stale-while-revalidate=60", int(duration.Seconds())))
		}
	}
}

type cacheWriter struct {
	gin.ResponseWriter
	body []byte
}

func (w *cacheWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return w.ResponseWriter.Write(b)
}

func (s *CacheService) WarmCache(ctx context.Context) error {
	conf := config.ServerConfig()
	baseURL := conf.HostDomain
	if baseURL == "" {
		return fmt.Errorf("host domain is not set in the server configuration")
	}

	// Create HTTP client with timeout
	client := &http.Client{Timeout: 10 * time.Second}

	// Fetch currencies first
	currenciesURL := fmt.Sprintf("%s/v1/currencies", baseURL)
	resp, err := client.Get(currenciesURL)
	if err != nil {
		return fmt.Errorf("failed to fetch currencies from %s: %v", currenciesURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch currencies: status code %d", resp.StatusCode)
	}

	var currencies []string
	if err := json.NewDecoder(resp.Body).Decode(&currencies); err != nil {
		return fmt.Errorf("failed to decode currencies response: %v", err)
	}

	// Use default currencies if none found
	if len(currencies) == 0 {
		currencies = []string{"USD", "EUR", "GBP"}
	}

	// Cache currencies
	currenciesKey := fmt.Sprintf("v1:api:currencies:list")
	currenciesData, err := json.Marshal(currencies)
	if err != nil {
		return fmt.Errorf("failed to marshal currencies: %v", err)
	}
	if err := s.client.Set(ctx, currenciesKey, string(currenciesData), time.Duration(conf.CurrenciesCacheDuration)*time.Hour).Err(); err != nil {
		return fmt.Errorf("failed to cache currencies: %v", err)
	}

	// Cache pubkey
	pubkeyURL := fmt.Sprintf("%s/v1/pubkey", baseURL)
	if err := s.cacheEndpoint(ctx, pubkeyURL, "v1:api:aggregator:pubkey", time.Duration(conf.PubKeyCacheDuration)*time.Hour); err != nil {
		return fmt.Errorf("failed to cache pubkey: %v", err)
	}

	// Cache institutions for each currency
	for _, currency := range currencies {
		institutionsURL := fmt.Sprintf("%s/v1/institutions/%s", baseURL, currency)
		key := fmt.Sprintf("v1:api:institutions:%s", currency)
		if err := s.cacheEndpoint(ctx, institutionsURL, key, time.Duration(conf.InstitutionsCacheDuration)*time.Hour); err != nil {
			return fmt.Errorf("failed to cache institutions for %s: %v", currency, err)
		}
	}

	return nil
}

func (s *CacheService) cacheEndpoint(ctx context.Context, url, key string, duration time.Duration) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch from %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-200 status code (%d) from %s", resp.StatusCode, url)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body from %s: %v", url, err)
	}

	// Verify the response is valid JSON
	var jsonCheck interface{}
	if err := json.Unmarshal(body, &jsonCheck); err != nil {
		return fmt.Errorf("invalid JSON response from %s: %v", url, err)
	}

	// Generate and store ETag
	etag := generateETag(body)
	if err := s.client.Set(ctx, key+":etag", etag, duration).Err(); err != nil {
		return fmt.Errorf("failed to cache etag for %s: %v", url, err)
	}

	// Cache the response
	if err := s.client.Set(ctx, key, string(body), duration).Err(); err != nil {
		return fmt.Errorf("failed to cache response for %s: %v", url, err)
	}

	return nil
}

func (s *CacheService) revalidateCache(c *gin.Context, key string, duration time.Duration) {
	ctx := context.Background()
	req, _ := http.NewRequest(c.Request.Method, c.Request.URL.String(), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		etag := generateETag(body)
		s.client.Set(ctx, key, string(body), duration)
		s.client.Set(ctx, key+":etag", etag, duration)
	}
}
