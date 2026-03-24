package assignment

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

// IsProviderFaultCancelReason returns true if reason starts with any entry in
// ProviderFaultCancelReasons (case-insensitive, trimmed). Prefix matching lets
// PSP-appended context like "(GHS 5000)" in "Amount exceeds maximum allowed (GHS 5000)"
// still match the base phrase "Amount exceeds maximum allowed".
func IsProviderFaultCancelReason(reason string) bool {
	r := strings.ToLower(strings.TrimSpace(reason))
	if r == "" {
		return false
	}
	for _, allowed := range ProviderFaultCancelReasons {
		if strings.HasPrefix(r, strings.ToLower(strings.TrimSpace(allowed))) {
			return true
		}
	}
	return false
}

// ApplyProviderScoreChange applies delta to the provider_order_token for this order's assigned
// provider, if score-eligible. Idempotent via unique (payment_order_id, event_type) on
// provider_order_token_score_histories.
func ApplyProviderScoreChange(ctx context.Context, orderID uuid.UUID, eventType string, delta decimal.Decimal) error {
	order, err := storage.Client.PaymentOrder.Query().
		Where(paymentorder.IDEQ(orderID)).
		WithProvider().
		WithToken(func(tq *ent.TokenQuery) { tq.WithNetwork() }).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("score: load order: %w", err)
	}
	if order.Edges.Provider == nil {
		return nil
	}
	return applyScoreForProvider(ctx, order, order.Edges.Provider, eventType, delta)
}

// ApplyProviderScoreChangeForProvider applies a score change for a specific provider
// (e.g. stale order_request meta) tied to orderID for idempotency.
func ApplyProviderScoreChangeForProvider(ctx context.Context, orderID uuid.UUID, providerID string, eventType string, delta decimal.Decimal) error {
	if providerID == "" {
		return nil
	}
	order, err := storage.Client.PaymentOrder.Query().
		Where(paymentorder.IDEQ(orderID)).
		WithToken(func(tq *ent.TokenQuery) { tq.WithNetwork() }).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("score: load order: %w", err)
	}
	prov, err := storage.Client.ProviderProfile.Get(ctx, providerID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("score: load provider: %w", err)
	}
	return applyScoreForProvider(ctx, order, prov, eventType, delta)
}

func applyScoreForProvider(ctx context.Context, order *ent.PaymentOrder, prov *ent.ProviderProfile, eventType string, delta decimal.Decimal) error {
	if prov == nil {
		return nil
	}
	providerID := prov.ID
	fb := config.OrderConfig().FallbackProviderID
	if fb != "" && providerID == fb {
		return nil
	}
	if prov.VisibilityMode != providerprofile.VisibilityModePublic {
		return nil
	}

	if order.Edges.Token == nil || order.Edges.Token.Edges.Network == nil {
		return fmt.Errorf("score: order token/network required")
	}
	inst, err := utils.GetInstitutionByCode(ctx, order.Institution, true)
	if err != nil || inst == nil || inst.Edges.FiatCurrency == nil {
		logger.WithFields(logger.Fields{"OrderID": order.ID.String()}).Warnf("score: skip — institution currency not resolved")
		return nil
	}
	fc := inst.Edges.FiatCurrency

	pot, err := storage.Client.ProviderOrderToken.Query().
		Where(
			providerordertoken.HasProviderWith(providerprofile.IDEQ(providerID)),
			providerordertoken.HasTokenWith(token.IDEQ(order.Edges.Token.ID)),
			providerordertoken.NetworkEQ(order.Edges.Token.Edges.Network.Identifier),
			providerordertoken.HasCurrencyWith(fiatcurrency.IDEQ(fc.ID)),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("score: resolve pot: %w", err)
	}

	_, err = storage.Client.ProviderOrderTokenScoreHistory.Create().
		SetPaymentOrderID(order.ID).
		SetProviderOrderTokenID(pot.ID).
		SetEventType(eventType).
		SetDelta(delta).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil
		}
		return fmt.Errorf("score: history insert: %w", err)
	}

	if err := storage.Client.ProviderOrderToken.UpdateOneID(pot.ID).AddScore(delta).Exec(ctx); err != nil {
		return fmt.Errorf("score: update pot: %w", err)
	}
	return nil
}
