package services

import (
	"strings"
	"time"

	"github.com/shopspring/decimal"
)

var (
	RewardFulfilledValidated       = decimal.NewFromFloat(1.0)
	PenaltyCancelInsufficientFunds = decimal.NewFromFloat(-1.5)
	PenaltyCancelProviderFault     = decimal.NewFromFloat(-1.0)
	PenaltyValidationFailed        = decimal.NewFromFloat(-2.0)
	PenaltyOrderRequestExpired     = decimal.NewFromFloat(-0.5)
	RecentProcessedVolumeWindow    = 24 * time.Hour
	ProviderFaultCancelReasons     = []string{
		"out of stock",
		"declined",
		"rate expired",
		"unable to fulfill",
		"capacity limit",
	}
)

func isProviderFaultCancelReason(reason string) bool {
	normalized := strings.TrimSpace(strings.ToLower(reason))
	for _, allowed := range ProviderFaultCancelReasons {
		if normalized == allowed {
			return true
		}
	}
	return false
}
