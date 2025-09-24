package middleware

import (
	"log"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/apikey"
	"github.com/paycrest/aggregator/ent/senderprofile"
	"github.com/paycrest/aggregator/storage"
	u "github.com/paycrest/aggregator/utils"
)

// CORSMiddleware is a middleware that adds CORS headers to response
func CORSMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		origin := ctx.GetHeader("Origin")

		// Default to allow all origins for non-sender routes
		allowedOrigin := "*"

		// For sender routes, validate against domain whitelist
		if strings.Contains(ctx.Request.URL.Path, "/sender/") {
			allowedOrigin = getCORSOrigin(ctx, origin)
		}

		ctx.Writer.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		ctx.Writer.Header().Set("Access-Control-Max-Age", "86400")
		ctx.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
		ctx.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, api_key, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, API-Key, Client-Type")
		ctx.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Length")
		ctx.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		ctx.Writer.Header().Set("Cache-Control", "no-cache")

		if ctx.Request.Method == "OPTIONS" {
			log.Println("OPTIONS")
			ctx.AbortWithStatus(200)
		} else {
			ctx.Next()
		}
	}
}

// getCORSOrigin determines the appropriate CORS origin for sender routes
func getCORSOrigin(ctx *gin.Context, requestOrigin string) string {
	if requestOrigin == "" {
		return "*"
	}
	
	// Try to get sender from context (set by auth middleware)
	senderCtx, ok := ctx.Get("sender")
	if !ok || senderCtx == nil {
		// No sender context - allow all origins for backward compatibility
		return "*"
	}
	
	sender := senderCtx.(*ent.SenderProfile)
	
	// If sender has no domain whitelist, allow all origins
	if len(sender.DomainWhitelist) == 0 {
		return "*"
	}
	
	// Extract domain from request origin
	requestDomain, err := u.ExtractDomainFromOrigin(requestOrigin)
	if err != nil {
		return "*"
	}
	
	// Check if the requesting domain is whitelisted
	if u.IsDomainAllowed(requestDomain, sender.DomainWhitelist) {
		return requestOrigin
	}
	
	// Domain not whitelisted - return null to block
	return "null"
}

// CORSMiddlewareForAPIKey handles CORS for API key authenticated routes
func CORSMiddlewareForAPIKey() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		origin := ctx.GetHeader("Origin")
		
		// Default to allow all origins for non-sender routes
		allowedOrigin := "*"
		
		// For sender routes, validate against domain whitelist
		if strings.Contains(ctx.Request.URL.Path, "/sender/") {
			allowedOrigin = getCORSOriginForAPIKey(ctx, origin)
		}
		
		ctx.Writer.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		ctx.Writer.Header().Set("Access-Control-Max-Age", "86400")
		ctx.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
		ctx.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, api_key, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, API-Key, Client-Type")
		ctx.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Length")
		ctx.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		ctx.Writer.Header().Set("Cache-Control", "no-cache")

		if ctx.Request.Method == "OPTIONS" {
			log.Println("OPTIONS")
			ctx.AbortWithStatus(200)
		} else {
			ctx.Next()
		}
	}
}

// getCORSOriginForAPIKey determines CORS origin for API key routes
func getCORSOriginForAPIKey(ctx *gin.Context, requestOrigin string) string {
	if requestOrigin == "" {
		return "*"
	}
	
	// Get API key from header
	apiKey := ctx.GetHeader("API-Key")
	apiKeyUUID, err := uuid.Parse(apiKey)
	if err != nil {
		return "*"
	}
	
	if apiKey == "" {
		return "*"
	}
	
	// Fetch sender profile with domain whitelist
	senderProfile, err := storage.Client.SenderProfile.
		Query().
		Where(senderprofile.HasAPIKeyWith(apikey.IDEQ(apiKeyUUID))).
		Only(ctx)
	if err != nil {
		return "*"
	}
	
	// If sender has no domain whitelist, allow all origins
	if len(senderProfile.DomainWhitelist) == 0 {
		return "*"
	}
	
	// Extract domain from request origin
	requestDomain, err := u.ExtractDomainFromOrigin(requestOrigin)
	if err != nil {
		return "*"
	}
	
	// Check if the requesting domain is whitelisted
	if u.IsDomainAllowed(requestDomain, senderProfile.DomainWhitelist) {
		return requestOrigin
	}
	
	// Domain not whitelisted - return null to block
	return "null"
}
