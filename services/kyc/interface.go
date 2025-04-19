package kyc

import (
	"context"
)

type KYCProvider interface {
	RequestVerification(ctx context.Context, req NewIDVerificationRequest) (*NewIDVerificationResponse, error)
	CheckStatus(ctx context.Context, walletAddress string) (*IDVerificationStatusResponse, error)
	HandleWebhook(ctx context.Context, payload []byte) error
}
