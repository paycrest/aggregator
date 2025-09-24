package middleware

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/gin-gonic/gin"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/apikey"
	"github.com/paycrest/aggregator/ent/senderprofile"
	"github.com/paycrest/aggregator/storage"
	u "github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

// DomainWhitelistMiddleware validates requests against sender's domain whitelist
func DomainWhitelistMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only apply to sender-specific routes
		if !strings.Contains(c.Request.URL.Path, "/sender/") {
			c.Next()
			return
		}
		
		// Get sender profile from context (set by auth middleware)
		senderCtx, ok := c.Get("sender")
		if !ok || senderCtx == nil {
			// No sender context - let auth middleware handle this
			c.Next()
			return
		}
		
		sender := senderCtx.(*ent.SenderProfile)
		
		// Skip validation if sender profile is not active
		if !sender.IsActive {
			c.Next()
			return
		}
		
		// Extract domain from request headers
		origin := c.GetHeader("Origin")
		referer := c.GetHeader("Referer")
		
		requestDomain, err := u.ExtractDomainFromRequest(origin, referer)
		if err != nil {
			logger.WithFields(logger.Fields{
				"origin":  origin,
				"referer": referer,
				"error":   err.Error(),
			}).Warnf("Failed to extract domain from request headers")
			
			// If we can't extract domain, allow for backward compatibility
			c.Next()
			return
		}
		
		// Check if domain is allowed
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
		
		// Log successful validation for monitoring
		logger.WithFields(logger.Fields{
			"sender_id":      sender.ID.String(),
			"request_domain": requestDomain,
		}).Debugf("Domain whitelist validation passed")
		
		c.Next()
	}
}

// DomainWhitelistMiddlewareForAPIKey validates requests for API key authenticated routes
func DomainWhitelistMiddlewareForAPIKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only apply to sender-specific routes
		if !strings.Contains(c.Request.URL.Path, "/sender/") {
			c.Next()
			return
		}
		
		// Get API key from header
		apiKey := c.GetHeader("API-Key")
		if apiKey == "" {
			c.Next()
			return
		}
		
		apiKeyUUID, err := uuid.Parse(apiKey)
		if err != nil {
			c.Next()
			return
		}
		
		// Fetch sender profile with domain whitelist
		senderProfile, err := storage.Client.SenderProfile.
			Query().
			Where(senderprofile.HasAPIKeyWith(apikey.IDEQ(apiKeyUUID))).
			Only(c)
		if err != nil {
			// Let API key middleware handle authentication errors
			c.Next()
			return
		}
		
		// Skip validation if sender profile is not active
		if !senderProfile.IsActive {
			c.Next()
			return
		}
		
		// Extract domain from request headers
		origin := c.GetHeader("Origin")
		referer := c.GetHeader("Referer")
		
		requestDomain, err := u.ExtractDomainFromRequest(origin, referer)
		if err != nil {
			logger.WithFields(logger.Fields{
				"origin":  origin,
				"referer": referer,
				"error":   err.Error(),
			}).Warnf("Failed to extract domain from request headers")
			
			// If we can't extract domain, allow for backward compatibility
			c.Next()
			return
		}
		
		// Check if domain is allowed
		if !u.IsDomainAllowed(requestDomain, senderProfile.DomainWhitelist) {
			logger.WithFields(logger.Fields{
				"sender_id":      senderProfile.ID.String(),
				"request_domain": requestDomain,
				"whitelist":      senderProfile.DomainWhitelist,
				"origin":         origin,
				"referer":        referer,
			}).Warnf("API key request blocked due to domain whitelist violation")
			
			u.APIResponse(c, http.StatusForbidden, "error", 
				"Access denied: Domain not whitelisted", map[string]interface{}{
					"domain": requestDomain,
				})
			c.Abort()
			return
		}
		
		c.Next()
	}
}
