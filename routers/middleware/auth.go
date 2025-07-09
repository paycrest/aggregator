package middleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/apikey"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/senderprofile"
	"github.com/paycrest/aggregator/ent/user"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/storage"
	u "github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/paycrest/aggregator/utils/token"
)

// JWTMiddleware is a middleware to handle JWT authentication
func JWTMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		u.APIResponse(c, http.StatusUnauthorized, "error",
			"Authorization header is missing", "Expected: Bearer <token>")
		c.Abort()
		return
	}

	// Split the Authorization header value into two parts: the authentication scheme and the token value
	authParts := strings.SplitN(authHeader, " ", 2)
	if len(authParts) != 2 || authParts[0] != "Bearer" {
		u.APIResponse(c, http.StatusUnauthorized, "error",
			"Invalid Authorization header format", "Expected: Bearer <token>")
		c.Abort()
		return
	}

	// Validate the token and extract the user ID
	claims, err := token.ValidateJWT(authParts[1])
	userID, ok := claims["sub"].(string)
	if err != nil || !ok {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Invalid or expired token", err.Error())
		c.Abort()
		return
	}
	scope, ok := claims["scope"].(string)
	if !ok {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Invalid or expired token", "Invalid scope in token")
		c.Abort()
		return
	}

	// Set the user_id value in the context of the request
	c.Set("user_id", userID)

	userUUID, _ := uuid.Parse(userID)

	senderAndProvider := strings.Contains(scope, "sender") && strings.Contains(scope, "provider")

	// Set user profiles based on scope
	if scope == "sender" || senderAndProvider {
		senderProfile, err := storage.Client.SenderProfile.
			Query().
			Where(senderprofile.HasUserWith(user.IDEQ(userUUID))).
			WithOrderTokens().
			Only(c)
		if err != nil {
			c.Set("sender", nil)
		}

		c.Set("sender", senderProfile)
	}

	if scope == "provider" || senderAndProvider {
		providerProfile, err := storage.Client.ProviderProfile.
			Query().
			Where(providerprofile.HasUserWith(user.IDEQ(userUUID))).
			Only(c)
		if err != nil && !senderAndProvider {
			fmt.Println("error", err)
			c.Set("provider", nil)
		}

		c.Set("provider", providerProfile)
	}

	c.Next()
}

type PrivyClaims struct {
	jwt.MapClaims
	AppId          string `json:"aud,omitempty"`
	Expiration     uint64 `json:"exp,omitempty"`
	Issuer         string `json:"iss,omitempty"`
	UserId         string `json:"sub,omitempty"`
	LinkedAccounts string `json:"linked_accounts,omitempty"`
}

type LinkedAccount struct {
	Type             string `json:"type"`
	Address          string `json:"address"`
	ChainType        string `json:"chain_type"`
	WalletClientType string `json:"wallet_client_type"`
	Lv               int64  `json:"lv"`
}

// PrivyMiddleware verifies the access token from a Privy (privy.io) login
func PrivyMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		u.APIResponse(c, http.StatusUnauthorized, "error",
			"Authorization header is missing", "Expected: Bearer <token>")
		c.Abort()
		return
	}

	// Split the Authorization header value into two parts: the authentication scheme and the token value
	authParts := strings.SplitN(authHeader, " ", 2)
	if len(authParts) != 2 || authParts[0] != "Bearer" {
		u.APIResponse(c, http.StatusUnauthorized, "error",
			"Invalid Authorization header format", "Expected: Bearer <token>")
		c.Abort()
		return
	}

	accessToken := authParts[1]
	identityConf := config.IdentityConfig()

	// Check the JWT signature and decode claims
	token, err := jwt.ParseWithClaims(accessToken, &PrivyClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != "ES256" {
			return nil, fmt.Errorf("unexpected signing method=%v", token.Header["alg"])
		}
		return jwt.ParseECPublicKeyFromPEM([]byte(identityConf.PrivyVerificationKey))
	})
	if err != nil {
		u.APIResponse(c, http.StatusUnauthorized, "error", "JWT signature is invalid.", err.Error())
		c.Abort()
		return
	}

	// Parse the JWT claims into your custom struct
	privyClaim, ok := token.Claims.(*PrivyClaims)
	if !ok {
		u.APIResponse(c, http.StatusUnauthorized, "error", "JWT does not have all the necessary claims.", nil)
		c.Abort()
		return
	}

	// Check the JWT claims
	if privyClaim.AppId != identityConf.PrivyAppID {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Invalid App ID", nil)
		c.Abort()
		return
	}

	if privyClaim.Issuer != "privy.io" {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Invalid Issuer", nil)
		c.Abort()
		return
	}

	if privyClaim.Expiration < uint64(time.Now().Unix()) {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Token is expired", nil)
		c.Abort()
		return
	}

	if privyClaim.LinkedAccounts == "" {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Missing linked accounts", nil)
		c.Abort()
		return
	}

	// Parse the linked accounts
	var accounts []LinkedAccount
	err = json.Unmarshal([]byte(privyClaim.LinkedAccounts), &accounts)
	if err != nil {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Failed to parse linked accounts", err.Error())
		c.Abort()
		return
	}
	c.Set("owner_address", determineOwnerAddress(accounts))

	c.Next()
}

// HMACVerificationMiddleware is a middleware for HMAC verification.
// It verifies the HMAC signature in the Authorization header of the request.
func HMACVerificationMiddleware(c *gin.Context) {
	// Get the authorization header value
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Missing Authorization header", nil)
		c.Abort()
		return
	}

	// Parse the authorization header
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "HMAC" {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Invalid Authorization header", "Expected: HMAC <public_key>:<signature>")
		c.Abort()
		return
	}

	// Avoid authorization header that doesn't match criteria
	if !strings.Contains(parts[1], ":") || len(parts[1]) < 4 {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Invalid Authorization header format", "Expected: HMAC <public_key>:<signature>")
		c.Abort()
		return
	}

	// Extract the public key and signature
	parts = strings.SplitN(parts[1], ":", 2)
	publicKey, signature := parts[0], parts[1]
	if publicKey == "" || signature == "" {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Invalid Authorization header format", "Expected: HMAC <public_key>:<signature>")
		c.Abort()
		return
	}

	var payloadData map[string]interface{}
	var err error

	// Handle GET and DELETE requests differently
	if c.Request.Method == "GET" || c.Request.Method == "DELETE" {
		payloadData = make(map[string]interface{})

		// // Extract the path parameters and include them in the payload
		// for _, param := range c.Params {
		// 	payloadData[param.Key] = param.Value
		// }

		// Extract the query parameters and include them in the payload
		for key, values := range c.Request.URL.Query() {
			if len(values) > 0 {
				payloadData[key] = values[0]
			}
		}
	} else {
		// For non-GET/non-DELETE requests, read the payload from the body
		payload, err := c.GetRawData()
		if err != nil {
			u.APIResponse(c, http.StatusInternalServerError, "error", "Failed to read request payload", err.Error())
			c.Abort()
			return
		}

		// Parse the payload to retrieve timestamp
		err = json.Unmarshal(payload, &payloadData)
		if err != nil {
			u.APIResponse(c, http.StatusBadRequest, "error", "Invalid payload format", err.Error())
			c.Abort()
			return
		}
	}

	// Convert the timestamp to float64 if it's a string
	if payloadData["timestamp"] != nil && reflect.TypeOf(payloadData["timestamp"]).String() == "string" {
		payloadData["timestamp"], err = strconv.ParseFloat(payloadData["timestamp"].(string), 64)
		if err != nil {
			u.APIResponse(c, http.StatusUnauthorized, "error", "Missing or invalid timestamp in payload", nil)
			c.Abort()
			return
		}
	}

	// Get the timestamp from the payload
	timestamp, ok := payloadData["timestamp"].(float64) // unix timestamp
	if !ok || timestamp == 0 {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Missing or invalid timestamp in payload", nil)
		c.Abort()
		return
	}

	var conf = config.AuthConfig()

	// Check if the timestamp is within the acceptable window
	if time.Now().Unix()-int64(timestamp) > int64(conf.HmacTimestampAge.Seconds()) {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Invalid timestamp", nil)
		c.Abort()
		return
	}

	// Parse the API key ID string to uuid.UUID
	apiKeyUUID, err := uuid.Parse(publicKey)
	if err != nil {
		logger.Errorf("error parsing API key ID: %v", err)
		u.APIResponse(c, http.StatusBadRequest, "error", "Invalid API key ID", nil)
		c.Abort()
		return
	}

	// Fetch the API key from the database
	apiKey, err := storage.Client.APIKey.
		Query().
		Where(apikey.IDEQ(apiKeyUUID)).
		WithSenderProfile().
		WithProviderProfile().
		Only(c)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(c, http.StatusNotFound, "error", "API key not found", nil)
		} else {
			logger.Errorf("error: %v", err)
			u.APIResponse(c, http.StatusInternalServerError, "error", "Failed to fetch API key", err.Error())
		}
		c.Abort()
		return
	}

	// Set the user profiles in the context of the request
	if apiKey.Edges.SenderProfile != nil {
		c.Set("sender", apiKey.Edges.SenderProfile)
	}

	if apiKey.Edges.ProviderProfile != nil {
		c.Set("provider", apiKey.Edges.ProviderProfile)
	}

	if apiKey.Edges.SenderProfile == nil && apiKey.Edges.ProviderProfile == nil {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		c.Abort()
		return
	}

	// Decode the stored secret key to bytes
	decodedSecret, err := base64.StdEncoding.DecodeString(apiKey.Secret)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(c, http.StatusInternalServerError, "error", "Failed to decode API key", err.Error())
		return
	}

	// Decrypt the decoded secret
	decryptedSecret, err := crypto.DecryptPlain(decodedSecret)
	if err != nil {
		logger.Errorf("error: %v", err)
		u.APIResponse(c, http.StatusInternalServerError, "error", "Failed to decrypt API key", err.Error())
		return
	}

	// Verify the HMAC signature
	valid := token.VerifyHMACSignature(payloadData, string(decryptedSecret), signature)
	if !valid {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Invalid HMAC signature", nil)
		c.Abort()
		return
	}

	// Remove the timestamp key from the payload
	delete(payloadData, "timestamp")

	// Convert the payload data back to JSON
	modifiedPayload, err := json.Marshal(payloadData)
	if err != nil {
		u.APIResponse(c, http.StatusInternalServerError, "error", "Failed to modify payload", err.Error())
		c.Abort()
		return
	}

	// Create a new buffer with the modified payload
	buffer := bytes.NewBuffer(modifiedPayload)

	// Set the modified payload as the request body
	c.Request.Body = io.NopCloser(buffer)

	// Continue to the next middleware
	c.Next()
}

// APIKeyMiddleware is a middleware to handle API key authentication
func APIKeyMiddleware(c *gin.Context) {
	// Get the API key from the request headers
	apiKey := c.GetHeader("API-Key")
	if apiKey == "" {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Missing API-Key header", nil)
		c.Abort()
		return
	}

	// Parse the API key ID string to uuid.UUID
	apiKeyUUID, err := uuid.Parse(apiKey)
	if err != nil {
		u.APIResponse(c, http.StatusBadRequest, "error", "Invalid API key ID", nil)
		c.Abort()
		return
	}

	// Fetch the API key from the database
	apiKeyEnt, err := storage.Client.APIKey.
		Query().
		Where(apikey.IDEQ(apiKeyUUID)).
		WithSenderProfile().
		WithProviderProfile().
		Only(c)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(c, http.StatusNotFound, "error", "API key not found", nil)
		} else {
			logger.Errorf("error: %v", err)
			u.APIResponse(c, http.StatusInternalServerError, "error", "Failed to fetch API key", err.Error())
		}
		c.Abort()
		return
	}

	// Set the user profiles in the context of the request
	if apiKeyEnt.Edges.SenderProfile != nil {
		c.Set("sender", apiKeyEnt.Edges.SenderProfile)
	}

	if apiKeyEnt.Edges.ProviderProfile != nil {
		c.Set("provider", apiKeyEnt.Edges.ProviderProfile)
	}

	if apiKeyEnt.Edges.SenderProfile == nil && apiKeyEnt.Edges.ProviderProfile == nil {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		c.Abort()
		return
	}

	// Continue to the next middleware
	c.Next()
}

// DynamicAuthMiddleware is a middleware that dynamically selects the authentication method
func DynamicAuthMiddleware(c *gin.Context) {
	// Check the request headers to determine the desired authentication method
	clientType := c.GetHeader("Client-Type")

	// Select the authentication middleware based on the client type
	switch clientType {
	case "web":
		JWTMiddleware(c)
	default:
		if strings.Contains(c.Request.URL.Path, "/sender/") && c.GetHeader("API-Key") != "" {
			APIKeyMiddleware(c)
		} else {
			HMACVerificationMiddleware(c)
		}
	}

	c.Next()
}

// OnlySenderMiddleware is a middleware that checks if the user scope is sender.
func OnlySenderMiddleware(c *gin.Context) {
	scope, ok := c.Get("sender")

	if !ok && scope == nil {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		c.Abort()
		return
	}

	c.Next()
}

// OnlyProviderMiddleware is a middleware that checks if the user scope is provider.
func OnlyProviderMiddleware(c *gin.Context) {
	scope, ok := c.Get("provider")

	if !ok && scope == nil {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Invalid API key or token", nil)
		c.Abort()
		return
	}

	c.Next()
}

// OnlyWebMiddleware is a middle that checks your Client-Type and allows for auth
func OnlyWebMiddleware(c *gin.Context) {
	// Check the request headers to determine the desired authentication method
	clientType := c.GetHeader("Client-Type")

	if clientType != "web" {
		u.APIResponse(c, http.StatusUnauthorized, "error", "Unrecognized Client-Type", nil)
		c.Abort()
		return
	}

	c.Next()
}

// determineOwnerAddress determines the owner address from the linked accounts
func determineOwnerAddress(accounts []LinkedAccount) string {
	var emailExists bool
	var privyWallet, nonPrivyEthereumWallet string

	for _, account := range accounts {
		switch {
		case account.Type == "email":
			emailExists = true
		case account.Type == "wallet" && account.ChainType == "ethereum":
			if account.WalletClientType == "privy" {
				privyWallet = account.Address
			} else if nonPrivyEthereumWallet == "" {
				nonPrivyEthereumWallet = account.Address
			}
		}
	}

	if emailExists && privyWallet != "" {
		return privyWallet
	}
	if nonPrivyEthereumWallet != "" {
		return nonPrivyEthereumWallet
	}
	if privyWallet != "" {
		return privyWallet
	}

	return ""
}

// TurnstileMiddleware is a middleware that verifies Turnstile tokens
func TurnstileMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		turnstileService := services.NewTurnstileService()

		// Get token from header, query parameter, or request body
		token := c.GetHeader("X-Turnstile-Token")
		if token == "" {
			token = c.Query("turnstile_token")
		}

		// If no token is found, allow the request to pass through
		if token == "" {
			c.Next()
			return
		}

		// Get client IP safely
		clientIP := c.ClientIP()
		if clientIP == "" {
			clientIP = "127.0.0.1" // fallback
		}

		// Verify the token
		if err := turnstileService.VerifyToken(token, clientIP); err != nil {
			u.APIResponse(c, http.StatusBadRequest, "error",
				"Security check verification failed", nil)
			c.Abort()
			return
		}

		c.Next()
	}
}
