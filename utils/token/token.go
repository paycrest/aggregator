package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/paycrest/aggregator/config"
)

var conf = config.AuthConfig()

// GenerateAccessJWT generates an access token with a short expiry time ~ 15 minutes
func GenerateAccessJWT(userID string, scope string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = userID
	claims["scope"] = scope
	claims["exp"] = time.Now().Add(conf.JwtAccessLifespan).Unix()

	return token.SignedString([]byte(conf.Secret))
}

// GenerateRefreshJWT generates a refresh token with a long expiry time >= 24 hours
func GenerateRefreshJWT(userID string, scope string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = userID
	claims["scope"] = scope
	claims["exp"] = time.Now().Add(conf.JwtRefreshLifespan).Unix()

	return token.SignedString([]byte(conf.Secret))
}

// GeneratePairJWT generates a pair of access and refresh tokens
func GeneratePairJWT(userID string, scope string) (string, string, error) {
	access, err := GenerateAccessJWT(userID, scope)
	if err != nil {
		return "", "", err
	}

	refresh, err := GenerateRefreshJWT(userID, scope)
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil
}

// ValidateJWT validates the JWT token string and returns the claims if valid.
func ValidateJWT(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(conf.Secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// GeneratePrivateKey generates a private key (Secret Key).
func GeneratePrivateKey() (string, error) {
	// Generate random bytes for the key
	keySize := 32 // 32 bytes = 256 bits -- for HMAC-SHA256 hashing function
	privateKeyBytes := make([]byte, keySize)
	_, err := rand.Read(privateKeyBytes)
	if err != nil {
		return "", err
	}

	// Encode private key to base64 string
	privateKey := base64.URLEncoding.EncodeToString(privateKeyBytes)

	return privateKey, nil
}

// VerifyHMACSignature verifies the HMAC signature for the given payload using the private key
// and returns true if the signature is valid.
func VerifyHMACSignature(payload map[string]interface{}, privateKey string, signature string) bool {
	expectedSignature := []byte(GenerateHMACSignature(payload, privateKey))
	computedSignature := []byte(signature)
	return hmac.Equal(expectedSignature, computedSignature)
}

// GenerateHMACSignature generates the HMAC signature for the given payload using the private key.
// The signature is returned as a hex-encoded string.
func GenerateHMACSignature(payload map[string]interface{}, privateKey string) string {
	key := []byte(privateKey)
	h := hmac.New(sha256.New, key)
	payloadBytes, _ := json.Marshal(payload)
	h.Write(payloadBytes)
	return hex.EncodeToString(h.Sum(nil))
}

// SortMapRecursively sorts a map recursively by its keys
func SortMapRecursively(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := m[k]
		switch v := v.(type) {
		case map[string]interface{}:
			result[k] = SortMapRecursively(v)
		case []interface{}:
			result[k] = SortSliceRecursively(v)
		default:
			result[k] = v
		}
	}
	return result
}

// SortMapRecursively sorts a map recursively by its keys
func SortSliceRecursively(s []interface{}) []interface{} {
	for i, v := range s {
		switch v := v.(type) {
		case map[string]interface{}:
			s[i] = SortMapRecursively(v)
		case []interface{}:
			s[i] = SortSliceRecursively(v)
		}
	}
	return s
}
