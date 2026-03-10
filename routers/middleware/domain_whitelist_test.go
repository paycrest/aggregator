// Domain whitelist middleware tests.
// Run from the aggregator module root: go test ./routers/middleware/... -run TestDomainWhitelist -v
package middleware

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/utils/test"
	"github.com/stretchr/testify/assert"
)

func TestDomainWhitelistMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("no sender in context allows request", func(t *testing.T) {
		router := gin.New()
		router.GET("/test", DomainWhitelistMiddleware, func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		w, _ := test.PerformRequest(t, "GET", "/test", nil, nil, router)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("sender with empty whitelist allows any origin", func(t *testing.T) {
		router := gin.New()
		router.GET("/test", setSenderProfile(&ent.SenderProfile{DomainWhitelist: nil}), DomainWhitelistMiddleware, func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		headers := map[string]string{"Origin": "https://any-domain.com"}
		w, _ := test.PerformRequest(t, "GET", "/test", nil, headers, router)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("sender with empty whitelist slice allows any origin", func(t *testing.T) {
		router := gin.New()
		router.GET("/test", setSenderProfile(&ent.SenderProfile{DomainWhitelist: []string{}}), DomainWhitelistMiddleware, func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		headers := map[string]string{"Origin": "https://any-domain.com"}
		w, _ := test.PerformRequest(t, "GET", "/test", nil, headers, router)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("sender with whitelist allows whitelisted origin", func(t *testing.T) {
		router := gin.New()
		router.GET("/test", setSenderProfile(&ent.SenderProfile{DomainWhitelist: []string{"example.com"}}), DomainWhitelistMiddleware, func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		headers := map[string]string{"Origin": "https://example.com"}
		w, _ := test.PerformRequest(t, "GET", "/test", nil, headers, router)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("sender with whitelist allows whitelisted subdomain", func(t *testing.T) {
		router := gin.New()
		router.GET("/test", setSenderProfile(&ent.SenderProfile{DomainWhitelist: []string{"example.com"}}), DomainWhitelistMiddleware, func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		headers := map[string]string{"Origin": "https://app.example.com"}
		w, _ := test.PerformRequest(t, "GET", "/test", nil, headers, router)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("sender with whitelist blocks non-whitelisted origin", func(t *testing.T) {
		router := gin.New()
		router.GET("/test", setSenderProfile(&ent.SenderProfile{DomainWhitelist: []string{"example.com"}}), DomainWhitelistMiddleware, func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		headers := map[string]string{"Origin": "https://evil.com"}
		w, _ := test.PerformRequest(t, "GET", "/test", nil, headers, router)
		assert.Equal(t, http.StatusForbidden, w.Code)
		body := decodeResponseBody(t, w)
		assert.Equal(t, "error", body["status"])
		assert.Equal(t, "Domain not allowed", body["message"])
	})

	t.Run("sender with whitelist but no origin or referer returns 403", func(t *testing.T) {
		router := gin.New()
		router.GET("/test", setSenderProfile(&ent.SenderProfile{DomainWhitelist: []string{"example.com"}}), DomainWhitelistMiddleware, func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		w, _ := test.PerformRequest(t, "GET", "/test", nil, nil, router)
		assert.Equal(t, http.StatusForbidden, w.Code)
		body := decodeResponseBody(t, w)
		assert.Equal(t, "error", body["status"])
		assert.Equal(t, "Origin or Referer required when domain whitelist is configured", body["message"])
	})

	t.Run("sender with whitelist allows referer when origin missing", func(t *testing.T) {
		router := gin.New()
		router.GET("/test", setSenderProfile(&ent.SenderProfile{DomainWhitelist: []string{"example.com"}}), DomainWhitelistMiddleware, func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		headers := map[string]string{"Referer": "https://example.com/page"}
		w, _ := test.PerformRequest(t, "GET", "/test", nil, headers, router)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// setSenderProfile returns a handler that sets the given sender profile in context.
func setSenderProfile(profile *ent.SenderProfile) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("sender", profile)
		c.Next()
	}
}
