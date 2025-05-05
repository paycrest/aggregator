package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/xeipuuv/gojsonschema"
)

type IDType struct {
	Type               string `json:"type"`
	VerificationMethod string `json:"verification_method"`
}

type Country struct {
	Name    string   `json:"name"`
	Code    string   `json:"code"`
	IDTypes []IDType `json:"id_types"`
}

type Continent struct {
	Name      string    `json:"name"`
	Countries []Country `json:"countries"`
}

type SmileIDConfig struct {
	Continents []Continent `json:"continents"`
}

// NewIDVerificationRequest is the request for a new identity verification request
type NewIDVerificationRequest struct {
	WalletAddress string `json:"walletAddress" binding:"required"`
	Signature     string `json:"signature" binding:"required"`
	Nonce         string `json:"nonce" binding:"required"`
}

// NewIDVerificationResponse is the response for a new identity verification request
type NewIDVerificationResponse struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type IDVerificationStatusResponse struct {
	Status string `json:"status"`
	URL    string `json:"url"`
}

// SmileIDWebhookPayload represents the payload structure from Smile Identity
type SmileIDWebhookPayload struct {
	ResultCode    string `json:"ResultCode"`
	PartnerParams struct {
		UserID string `json:"user_id"`
	} `json:"PartnerParams"`
	Signature string `json:"signature"`
	Timestamp string `json:"timestamp"`
	// Add other fields as needed
}

func ValidateSmileIDConfig(filePath string) error {
	// Read the config file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Validate against JSON schema
	schemaPath := "./id_types_schema.json"
	schemaLoader := gojsonschema.NewReferenceLoader("file://" + schemaPath)
	documentLoader := gojsonschema.NewBytesLoader(data)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return fmt.Errorf("failed to validate schema: %w", err)
	}
	if !result.Valid() {
		var errors []string
		for _, e := range result.Errors() {
			errors = append(errors, e.String())
		}
		return fmt.Errorf("schema validation failed: %v", errors)
	}

	// Ensure JSON is parseable into SmileIDConfig
	var config SmileIDConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	return nil
}
