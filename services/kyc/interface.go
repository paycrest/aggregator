package kyc

import (
	"context"

	"github.com/paycrest/aggregator/services/kyc/smile/config"
)

type KYCProvider interface {
	RequestVerification(ctx context.Context, req config.NewIDVerificationRequest) (*config.NewIDVerificationResponse, error)
	CheckStatus(ctx context.Context, walletAddress string) (*config.IDVerificationStatusResponse, error)
	HandleWebhook(ctx context.Context, payload []byte) error
}
