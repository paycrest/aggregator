package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/paycrest/aggregator/services"
	u "github.com/paycrest/aggregator/utils"
)

// TurnstileMiddleware is a middleware that verifies Turnstile tokens
func TurnstileMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		turnstileService := services.NewTurnstileService()

		// Get token from header or query parameter
		token := c.GetHeader("X-Turnstile-Token")
		if token == "" {
			token = c.Query("turnstile_token")
		}

		// Verify the token
		if err := turnstileService.VerifyToken(token, c.ClientIP()); err != nil {
			u.APIResponse(c, http.StatusBadRequest, "error",
				"Security check verification failed", nil)
			c.Abort()
			return
		}

		c.Next()
	}
}
