package kyc

import (
	"time"
)


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


