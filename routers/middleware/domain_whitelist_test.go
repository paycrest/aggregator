package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/ent"
)

func TestDomainWhitelistMiddleware(t *testing.T) {
	// Create a mock sender profile for testing
	senderProfile := &ent.SenderProfile{
		ID:              uuid.New(),
		DomainWhitelist: []string{},
		IsActive:        true,
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Add middleware
	router.Use(func(c *gin.Context) {
		c.Set("sender", senderProfile)
		c.Next()
	})
	router.Use(DomainWhitelistMiddleware())

	router.GET("/sender/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "success"})
	})

	tests := []struct {
		name            string
		origin          string
		whitelist       []string
		expectedStatus  int
		expectedMessage string
	}{
		{
			name:           "Empty whitelist allows all",
			origin:         "https://example.com",
			whitelist:      []string{},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Whitelisted domain allowed",
			origin:         "https://example.com",
			whitelist:      []string{"example.com"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Non-whitelisted domain blocked",
			origin:         "https://malicious.com",
			whitelist:      []string{"example.com"},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Subdomain allowed",
			origin:         "https://api.example.com",
			whitelist:      []string{"example.com"},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Update the mock sender profile whitelist
			senderProfile.DomainWhitelist = tt.whitelist

			// Create request
			req := httptest.NewRequest("GET", "/sender/test", nil)
			req.Header.Set("Origin", tt.origin)

			// Create response recorder
			w := httptest.NewRecorder()

			// Perform request
			router.ServeHTTP(w, req)

			// Check status
			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}
