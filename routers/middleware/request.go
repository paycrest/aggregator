package middleware

import (
	"net/http"
	"sync"
	"time"

	ratelimit "github.com/JGLTechnologies/gin-rate-limit"
	"github.com/gin-gonic/gin"
	"github.com/paycrest/aggregator/config"
	u "github.com/paycrest/aggregator/utils"
)

var (
	unauthenticatedLimiter gin.HandlerFunc
	authenticatedLimiter   gin.HandlerFunc
	initOnce               sync.Once
	blacklistedIPs         = make(map[string]time.Time)
	blacklistMutex         = sync.RWMutex{}
)

// addToBlacklist adds an IP to the blacklist with timestamp
func addToBlacklist(ip string) {
	blacklistMutex.Lock()
	defer blacklistMutex.Unlock()
	blacklistedIPs[ip] = time.Now()
}

// isBlacklisted checks if an IP is blacklisted
func isBlacklisted(ip string) bool {
	blacklistMutex.RLock()
	defer blacklistMutex.RUnlock()
	_, exists := blacklistedIPs[ip]
	return exists
}

// RateLimitMiddleware applies rate limiting based on the request type (authenticated/unauthenticated)
func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		
		// Check if IP is blacklisted
		if isBlacklisted(clientIP) {
			u.APIResponse(
				c,
				http.StatusForbidden,
				"error",
				"IP address is temporarily blocked due to rate limit violations",
				map[string]interface{}{
					"blocked_until": "server restart",
				},
			)
			c.Abort()
			return
		}

		initOnce.Do(func() {
			conf := config.ServerConfig()

			// Unauthenticated limiter
			unauthenticatedStore := ratelimit.InMemoryStore(&ratelimit.InMemoryOptions{
				Rate:  time.Second,
				Limit: uint(conf.RateLimitUnauthenticated),
			})
			unauthenticatedLimiter = ratelimit.RateLimiter(unauthenticatedStore, &ratelimit.Options{
				ErrorHandler: func(c *gin.Context, info ratelimit.Info) {
					ip := c.ClientIP()
					// Add IP to blacklist when rate limited
					addToBlacklist(ip)
					
					u.APIResponse(
						c,
						http.StatusTooManyRequests,
						"error",
						"Too many requests from this IP address. IP has been temporarily blocked.",
						map[string]interface{}{
							"retry_after": time.Until(info.ResetTime).Seconds(),
							"limit":       info.Limit,
							"blocked_until": "server restart",
						},
					)
					c.Abort()
				},
				KeyFunc: func(c *gin.Context) string {
					return "ip:" + c.ClientIP()
				},
			})

			// Authenticated limiter
			authenticatedStore := ratelimit.InMemoryStore(&ratelimit.InMemoryOptions{
				Rate:  time.Second,
				Limit: uint(conf.RateLimitAuthenticated),
			})
			authenticatedLimiter = ratelimit.RateLimiter(authenticatedStore, &ratelimit.Options{
				ErrorHandler: func(c *gin.Context, info ratelimit.Info) {
					ip := c.ClientIP()
					// Add IP to blacklist when rate limited
					addToBlacklist(ip)
					
					u.APIResponse(
						c,
						http.StatusTooManyRequests,
						"error",
						"Too many requests for this API key. IP has been temporarily blocked.",
						map[string]interface{}{
							"retry_after": time.Until(info.ResetTime).Seconds(),
							"limit":       info.Limit,
							"blocked_until": "server restart",
						},
					)
					c.Abort()
				},
				KeyFunc: func(c *gin.Context) string {
					return "auth:" + c.GetHeader("Authorization")
				},
			})
		})

		// Apply appropriate limiter based on authentication status
		if token := c.GetHeader("Authorization"); token != "" {
			authenticatedLimiter(c)
		} else {
			unauthenticatedLimiter(c)
		}

		c.Next()
	}
}