package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/paycrest/aggregator/tasks"
	u "github.com/paycrest/aggregator/utils"
)

// OrdersReadinessMiddleware gates sender order creation until initial provider balance warmup completes.
// This prevents creating orders immediately after startup when provider balances haven't been pulled yet.
func OrdersReadinessMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, done, _ := tasks.ProviderBalancesWarmupStatus()
		if done {
			c.Next()
			return
		}

		u.APIResponse(c, http.StatusServiceUnavailable, "error", "Service warming up, please retry shortly", map[string]interface{}{
			"ready": false,
		})
		c.Abort()
	}
}
