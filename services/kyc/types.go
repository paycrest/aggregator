package kyc

import (
	"context"
	"time"
)

// VerificationRequest represents a generic KYC verification request
type VerificationRequest struct {
	WalletAddress string `json:"walletAddress"`
	Signature     string `json:"signature"`
	Nonce         string `json:"nonce"`
}

// VerificationResponse represents a generic KYC verification response
type VerificationResponse struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// VerificationStatus represents the status of a KYC verification
type VerificationStatus struct {
	URL    string `json:"url"`
	Status string `json:"status"`
}

// KYCProvider defines the interface for KYC verification providers
type KYCProvider interface {
	RequestVerification(ctx context.Context, req VerificationRequest) (*VerificationResponse, error)
	CheckStatus(ctx context.Context, walletAddress string) (*VerificationStatus, error)
	HandleWebhook(ctx context.Context, payload []byte) error
}
