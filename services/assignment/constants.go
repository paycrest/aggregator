package assignment

import (
	"time"

	"github.com/shopspring/decimal"
)

// Provider selection and scoring constants (hardcoded per product; not env-configured).

const (
	// Score deltas (applied via ProviderOrderTokenScoreHistory + score update).
	RewardFulfilledValidated       = 1.0
	PenaltyCancelInsufficientFunds = -1.5
	PenaltyCancelProviderFault     = -1.0
	PenaltyValidationFailed        = -2.0
	PenaltyOrderRequestExpired     = -0.5
)

// RecentVolumeWindow is the lookback for recent_successful_fiat_volume_24h ordering.
var RecentVolumeWindow = 24 * time.Hour

// assignPaymentOrderTimeout bounds DB/Redis work for one assignment invocation.
const assignPaymentOrderTimeout = 2 * time.Minute

// recordAssignmentRunTimeout bounds audit persistence so it is not cut off by assignPaymentOrderTimeout.
const recordAssignmentRunTimeout = 10 * time.Second

// orderAssignLockTTL is Redis TTL for order_assign_lock_{orderID} (exclusive assign / sendOrderRequest).
const orderAssignLockTTL = 5 * time.Minute

// assignmentMarketRateRelTol: refresh persisted assignment market snapshot when fiat rates drift beyond this relative delta.
var assignmentMarketRateRelTol = decimal.NewFromFloat(0.0005) // 0.05%

// ProviderFaultCancelReasons is the allow-list of cancel reasons that count as provider fault
// (-1.0). Each entry indicates the provider accepted an order their PSP or account configuration
// cannot process — i.e. the provider is responsible, not external infrastructure.
//
// Matching is case-insensitive prefix so PSPs can append context without breaking the match
// (e.g. "Amount exceeds maximum allowed (GHS 5000)" matches "Amount exceeds maximum allowed").
//
// Excluded intentionally (not provider fault):
//   - "Gateway timeout" — external infrastructure delay.
//   - "Transaction data not found", "transactionId is missing from the response",
//     "Invalid transfer response" — PSP response parsing bugs.
//   - "Disbursement failed", "Transaction failed", "Order processing incomplete" — catch-all
//     fallbacks too ambiguous to attribute to the provider.
var ProviderFaultCancelReasons = []string{
	"Amount exceeds maximum allowed",
	"Amount is less than minimum allowed",
	"Invalid amount",
	"Unsupported channel",
	"Payment failed",
}

// ScoreHistoryEventType values for idempotent score application (unique per payment_order_id + event_type).
const (
	ScoreEventFulfilledValidated      = "fulfilled_validated"
	ScoreEventCancelInsufficientFunds = "cancel_insufficient_funds"
	ScoreEventCancelProviderFault     = "cancel_provider_fault"
	ScoreEventValidationFailed        = "validation_failed"
	ScoreEventOrderRequestExpired     = "order_request_expired"
)

// AssignmentRunResult values for ProviderAssignmentRun.result.
const (
	AssignmentRunResultAssigned   = "assigned"
	AssignmentRunResultFallback   = "fallback"
	AssignmentRunResultNoProvider = "no_provider"
	AssignmentRunResultSkipped    = "skipped"
	AssignmentRunResultError      = "error"
)

// AssignmentRunTrigger values for ProviderAssignmentRun.trigger.
const (
	AssignmentTriggerInitial       = "initial"
	AssignmentTriggerReassignStale = "reassign_stale"
	AssignmentTriggerStaleOps      = "stale_ops"
)
