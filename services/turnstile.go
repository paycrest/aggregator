package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/utils/logger"
)

// TurnstileService handles Cloudflare Turnstile token validation
type TurnstileService struct{}

// TurnstileResponse represents the response from Cloudflare Turnstile verification
type TurnstileResponse struct {
	Success     bool     `json:"success"`
	ErrorCodes  []string `json:"error-codes,omitempty"`
	ChallengeTS string   `json:"challenge_ts,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
}

// NewTurnstileService creates a new instance of TurnstileService
func NewTurnstileService() *TurnstileService {
	return &TurnstileService{}
}

// VerifyToken validates a Turnstile token with Cloudflare
func (s *TurnstileService) VerifyToken(token, remoteIP string) error {
	authConf := config.AuthConfig()
	// Skip verification if Turnstile is disabled
	if !authConf.TurnstileEnabled {
		logger.Infof("Turnstile verification skipped (disabled)")
		return nil
	}

	// Validate required configuration
	if token == "" {
		return fmt.Errorf("Turnstile token is required")
	}

	if authConf.TurnstileSecretKey == "" {
		return fmt.Errorf("Turnstile secret key not configured")
	}

	// Prepare the verification request
	data := url.Values{}
	data.Set("secret", authConf.TurnstileSecretKey)
	data.Set("response", token)
	if remoteIP != "" {
		data.Set("remoteip", remoteIP)
	}

	// Make the verification request
	resp, err := http.Post(
		"https://challenges.cloudflare.com/turnstile/v0/siteverify",
		"application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		logger.Errorf("Failed to verify Turnstile token: %v", err)
		return fmt.Errorf("failed to verify security check")
	}
	defer resp.Body.Close()

	// Read and parse the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("Failed to read Turnstile response: %v", err)
		return fmt.Errorf("failed to verify security check")
	}

	var turnstileResp TurnstileResponse
	if err := json.Unmarshal(body, &turnstileResp); err != nil {
		logger.Errorf("Failed to parse Turnstile response: %v", err)
		return fmt.Errorf("failed to verify security check")
	}

	// Check if verification was successful
	if !turnstileResp.Success {
		logger.WithFields(logger.Fields{
			"ErrorCodes": turnstileResp.ErrorCodes,
			"Hostname":   turnstileResp.Hostname,
		}).Errorf("Turnstile verification failed")
		return fmt.Errorf("security check verification failed")
	}

	logger.Infof("Turnstile verification successful for hostname: %s", turnstileResp.Hostname)
	return nil
}
