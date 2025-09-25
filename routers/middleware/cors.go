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

func CORSMiddleware() gin.HandlerFunc {
    return func(ctx *gin.Context) {
        origin := ctx.GetHeader("Origin")
        allowedOrigin := "*"
        
        if strings.Contains(ctx.Request.URL.Path, "/sender/") {
            allowedOrigin = getCORSOrigin(ctx, origin)
        }
        
        // Set all CORS headers
        setCORSHeaders(ctx, allowedOrigin)
        
        if ctx.Request.Method == "OPTIONS" {
            log.Println("OPTIONS")
            ctx.AbortWithStatus(200)
        } else {
            ctx.Next()
        }
    }
}

func getCORSOrigin(ctx *gin.Context, requestOrigin string) string {
    if requestOrigin == "" {
        return "*"
    }
    
    // Try JWT auth first (sender in context)
    if senderCtx, ok := ctx.Get("sender"); ok && senderCtx != nil {
        return validateDomainForSender(senderCtx.(*ent.SenderProfile), requestOrigin)
    }
    
    // Fall back to API key auth
    return validateDomainForAPIKey(ctx, requestOrigin)
}

func validateDomainForSender(sender *ent.SenderProfile, requestOrigin string) string {
    if len(sender.DomainWhitelist) == 0 {
        return "*"
    }
    
    requestDomain, err := u.ExtractDomainFromOrigin(requestOrigin)
    if err != nil {
        return "*"
    }
    
    if u.IsDomainAllowed(requestDomain, sender.DomainWhitelist) {
        return requestOrigin
    }
    
    return "null"
}

func validateDomainForAPIKey(ctx *gin.Context, requestOrigin string) string {
    apiKey := ctx.GetHeader("API-Key")
    if apiKey == "" {
        return "*"
    }
    
    apiKeyUUID, err := uuid.Parse(apiKey)
    if err != nil {
        return "*"
    }
    
    senderProfile, err := storage.Client.SenderProfile.
        Query().
        Where(senderprofile.HasAPIKeyWith(apikey.IDEQ(apiKeyUUID))).
        Only(ctx)
    if err != nil {
        return "*"
    }
    
    return validateDomainForSender(senderProfile, requestOrigin)
}

func setCORSHeaders(ctx *gin.Context, allowedOrigin string) {
    ctx.Writer.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
    ctx.Writer.Header().Set("Access-Control-Max-Age", "86400")
    ctx.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
    ctx.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, api_key, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, API-Key, Client-Type")
    ctx.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Length")
    ctx.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
    ctx.Writer.Header().Set("Cache-Control", "no-cache")
}
