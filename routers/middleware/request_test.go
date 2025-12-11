package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paycrest/aggregator/utils/test"
	"github.com/stretchr/testify/assert"
)

func TestRateLimit(t *testing.T) {
	// Set Gin mode for testing
	gin.SetMode(gin.TestMode)

	// Initialize router
	router := gin.New()
	router.Use(RateLimitMiddleware())

	// Add test route
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	t.Run("TestRateLimitMiddleware", func(t *testing.T) {
		tests := []struct {
			name           string
			authenticated  bool
			numRequests    int
			expectedStatus int
			token          string
		}{
			{
				name:           "Unauthenticated Under Limit",
				authenticated:  false,
				numRequests:    4,
				expectedStatus: http.StatusOK,
			},
			{
				name:           "Unauthenticated Over Limit",
				authenticated:  false,
				numRequests:    25,
				expectedStatus: http.StatusTooManyRequests,
			},
			{
				name:           "Authenticated Under Limit",
				authenticated:  true,
				numRequests:    45,
				expectedStatus: http.StatusOK,
				token:          "test-token",
			},
			{
				name:           "Authenticated Over Limit",
				authenticated:  true,
				numRequests:    550,
				expectedStatus: http.StatusTooManyRequests,
				token:          "test-token",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// Wait for the rate limit to reset
				time.Sleep(1 * time.Second)

				headers := map[string]string{}
				if tt.authenticated {
					headers["Authorization"] = tt.token
				}

				var lastStatus int
				for i := 0; i < tt.numRequests; i++ {
					w, _ := test.PerformRequest(t, "GET", "/test", nil, headers, router)
					lastStatus = w.Code
					// Break early once we detect rate limiting for "Over Limit" tests
					if tt.expectedStatus == http.StatusTooManyRequests && lastStatus == http.StatusTooManyRequests {
						break
					}
				}

				assert.Equal(t, tt.expectedStatus, lastStatus)
			})
		}
	})

	t.Run("TestRateLimitErrorResponse", func(t *testing.T) {
		// Test unauthenticated rate limit error response
		headers := map[string]string{}
		var response map[string]interface{}

		for i := 0; i < 25; i++ {
			w, _ := test.PerformRequest(t, "GET", "/test", nil, headers, router)
			if w.Code == http.StatusTooManyRequests {
				response = decodeResponseBody(t, w)
				break
			}
		}

		// Verify the top-level structure of the response
		assert.Equal(t, "error", response["status"])
		assert.Equal(t, "Too many requests from this IP address", response["message"])

		// Check nested data fields
		data, ok := response["data"].(map[string]interface{})
		assert.True(t, ok, "data field should be a map")
		assert.Contains(t, data, "retry_after")
		assert.Contains(t, data, "limit")

		// Verify values
		assert.Greater(t, data["retry_after"].(float64), 0.0)
		assert.Equal(t, 20, int(data["limit"].(float64)))

		// Test authenticated rate limit error response
		time.Sleep(1 * time.Second) // Wait for rate limit to reset
		headers["Authorization"] = "test-token"

		for i := 0; i < 550; i++ {
			w, _ := test.PerformRequest(t, "GET", "/test", nil, headers, router)
			if w.Code == http.StatusTooManyRequests {
				response = decodeResponseBody(t, w)
				break
			}
		}

		// Verify authenticated rate limit response
		data = response["data"].(map[string]interface{})
		assert.Equal(t, 500, int(data["limit"].(float64)))
	})
}

// Helper function to decode JSON responses
func decodeResponseBody(t *testing.T, body *httptest.ResponseRecorder) map[string]interface{} {
	var response map[string]interface{}
	err := json.NewDecoder(body.Body).Decode(&response)
	assert.NoError(t, err)
	return response
}
