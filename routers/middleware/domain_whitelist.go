package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/paycrest/aggregator/ent"
	u "github.com/paycrest/aggregator/utils"
)

// DomainWhitelistMiddleware enforces the sender profile's domain_whitelist.
// Must run after auth middleware so "sender" is in context.
// - No sender in context: pass through (e.g. provider routes).
// - Empty whitelist: allow (backward compatibility).
// - Non-empty whitelist: allow only if Origin/Referer domain is in whitelist; otherwise 403.
func DomainWhitelistMiddleware(c *gin.Context) {
	val, exists := c.Get("sender")
	if !exists || val == nil {
		c.Next()
		return
	}
	profile, ok := val.(*ent.SenderProfile)
	if !ok || profile == nil {
		c.Next()
		return
	}
	whitelist := profile.DomainWhitelist
	if len(whitelist) == 0 {
		c.Next()
		return
	}
	origin := c.GetHeader("Origin")
	referer := c.GetHeader("Referer")
	domain := u.ExtractRequestDomain(origin, referer)
	if u.IsDomainAllowed(domain, whitelist) {
		c.Next()
		return
	}
	// When whitelist is set but no domain could be extracted, block (e.g. missing Origin/Referer).
	if domain == "" {
		u.APIResponse(c, http.StatusForbidden, "error", "Origin or Referer required when domain whitelist is configured", nil)
		c.Abort()
		return
	}
	u.APIResponse(c, http.StatusForbidden, "error", "Domain not allowed", nil)
	c.Abort()
}
