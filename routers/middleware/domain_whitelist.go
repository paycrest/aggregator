package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/paycrest/aggregator/ent"
	u "github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

func DomainWhitelistMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !strings.Contains(c.Request.URL.Path, "/sender/") {
			c.Next()
			return
		}

		senderCtx, ok := c.Get("sender")
		if !ok || senderCtx == nil {
			c.Next()
			return
		}

		sender := senderCtx.(*ent.SenderProfile)

		if !sender.IsActive {
			c.Next()
			return
		}

		origin := c.GetHeader("Origin")
		referer := c.GetHeader("Referer")

		requestDomain, err := u.ExtractDomainFromRequest(origin, referer)
		if err != nil {
			logger.WithFields(logger.Fields{
				"origin":  origin,
				"referer": referer,
				"error":   err.Error(),
			}).Warnf("Failed to extract domain from request headers")

			if len(sender.DomainWhitelist) > 0 {
				u.APIResponse(c, http.StatusBadRequest, "error",
					"Invalid request origin", nil)
				c.Abort()
				return
			}

			c.Next()
			return
		}

		if !u.IsDomainAllowed(requestDomain, sender.DomainWhitelist) {
			logger.WithFields(logger.Fields{
				"sender_id":      sender.ID.String(),
				"request_domain": requestDomain,
				"whitelist":      sender.DomainWhitelist,
				"origin":         origin,
				"referer":        referer,
			}).Warnf("Request blocked due to domain whitelist violation")

			u.APIResponse(c, http.StatusForbidden, "error",
				"Access denied: Domain not whitelisted", map[string]interface{}{
					"domain": requestDomain,
				})
			c.Abort()
			return
		}

		logger.WithFields(logger.Fields{
			"sender_id":      sender.ID.String(),
			"request_domain": requestDomain,
		}).Debugf("Domain whitelist validation passed")

		c.Next()
	}
}
