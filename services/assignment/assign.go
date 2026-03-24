package assignment

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/paymentorderfulfillment"
	"github.com/paycrest/aggregator/ent/providerbalances"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

// AssignPaymentOrder assigns a payment order to a provider using DB-only selection.
func (s *Service) AssignPaymentOrder(ctx context.Context, order types.PaymentOrderFields) error {
	return s.AssignPaymentOrderWithTrigger(ctx, order, AssignmentTriggerInitial)
}

// TryFallbackAssignment attempts to assign the order to the configured fallback provider using only
// rate and balance checks. Returns a clear error if the fallback provider's rate is outside slippage.
func (s *Service) TryFallbackAssignment(ctx context.Context, order *ent.PaymentOrder) error {
	orderConf := config.OrderConfig()
	fallbackID := orderConf.FallbackProviderID
	if fallbackID == "" {
		return fmt.Errorf("fallback provider not configured")
	}
	if order.OrderType == paymentorder.OrderTypeOtc {
		return fmt.Errorf("fallback is only for regular orders, not OTC")
	}

	orderKey := fmt.Sprintf("order_request_%s", order.ID)
	exists, err := storage.RedisClient.Exists(ctx, orderKey).Result()
	if err != nil {
		return fmt.Errorf("fallback: failed to check order_request: %w", err)
	}
	if exists > 0 {
		return fmt.Errorf("fallback: order %s already has an active order_request", order.ID)
	}

	currentOrder, err := storage.Client.PaymentOrder.Query().
		Where(paymentorder.IDEQ(order.ID)).
		Only(ctx)
	if err != nil {
		return fmt.Errorf("fallback: failed to load order: %w", err)
	}
	if !currentOrder.FallbackTriedAt.IsZero() {
		return fmt.Errorf("fallback: order %s already had fallback assignment tried", order.ID)
	}
	assignable := currentOrder.Status == paymentorder.StatusPending || currentOrder.Status == paymentorder.StatusCancelled
	if currentOrder.Status == paymentorder.StatusFulfilled {
		tx, txErr := storage.Client.Tx(ctx)
		if txErr != nil {
			return fmt.Errorf("fallback: failed to start transaction for order %s: %w", order.ID, txErr)
		}
		deleted, delErr := tx.PaymentOrderFulfillment.Delete().
			Where(
				paymentorderfulfillment.HasOrderWith(paymentorder.IDEQ(order.ID)),
				paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusFailed),
			).Exec(ctx)
		if delErr != nil {
			_ = tx.Rollback()
			return fmt.Errorf("fallback: failed to delete fulfillments for order %s: %w", order.ID, delErr)
		}
		if deleted == 0 {
			_ = tx.Rollback()
			return fmt.Errorf("fallback: order %s is fulfilled with no failed fulfillments, not assignable", order.ID)
		}
		if _, updErr := tx.PaymentOrder.UpdateOneID(order.ID).
			ClearProvider().
			SetStatus(paymentorder.StatusPending).
			Save(ctx); updErr != nil {
			_ = tx.Rollback()
			return fmt.Errorf("fallback: failed to reset order %s to Pending after deleting fulfillments: %w", order.ID, updErr)
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return fmt.Errorf("fallback: failed to commit transaction for order %s: %w", order.ID, commitErr)
		}
		assignable = true
	}
	if !assignable {
		return fmt.Errorf("fallback: order %s is in state %s, not assignable", order.ID, currentOrder.Status)
	}

	if order.AccountIdentifier == "" || order.Institution == "" || order.AccountName == "" {
		return fmt.Errorf("fallback: order %s has no recipient information", order.ID.String())
	}
	fields := types.PaymentOrderFields{
		ID:                order.ID,
		OrderType:         order.OrderType.String(),
		Token:             order.Edges.Token,
		Network:           nil,
		GatewayID:         order.GatewayID,
		Amount:            order.Amount,
		Rate:              order.Rate,
		Institution:       order.Institution,
		AccountIdentifier: order.AccountIdentifier,
		AccountName:       order.AccountName,
		ProviderID:        "",
		MessageHash:       order.MessageHash,
		Memo:              order.Memo,
		UpdatedAt:         order.UpdatedAt,
		CreatedAt:         order.CreatedAt,
	}
	if order.Edges.Token != nil && order.Edges.Token.Edges.Network != nil {
		fields.Network = order.Edges.Token.Edges.Network
	}
	if fields.Token == nil {
		return fmt.Errorf("fallback: order %s has no token", order.ID.String())
	}

	institution, instErr := utils.GetInstitutionByCode(ctx, order.Institution, true)
	if instErr != nil {
		return fmt.Errorf("fallback: institution lookup failed for order %s: %w", fields.ID.String(), instErr)
	}
	if institution.Edges.FiatCurrency == nil {
		return fmt.Errorf("fallback: institution %s has no fiat currency for order %s", order.Institution, fields.ID.String())
	}
	bucketCurrency := institution.Edges.FiatCurrency

	if orderConf.ProviderStuckFulfillmentThreshold > 0 {
		stuckCount, errStuck := utils.GetProviderStuckOrderCount(ctx, fallbackID)
		if errStuck == nil && stuckCount >= orderConf.ProviderStuckFulfillmentThreshold {
			return &types.ErrNoProviderDueToStuck{CurrencyCode: bucketCurrency.Code}
		}
		if errStuck != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", errStuck),
				"FallbackID": fallbackID,
				"Currency":   bucketCurrency.Code,
			}).Errorf("fallback: failed to get stuck order count, proceeding with assignment (fail-open)")
		}
	}

	provider, err := storage.Client.ProviderProfile.Get(ctx, fallbackID)
	if err != nil {
		if ent.IsNotFound(err) {
			return fmt.Errorf("fallback provider %s not found", fallbackID)
		}
		return fmt.Errorf("failed to get fallback provider: %w", err)
	}

	network := fields.Token.Edges.Network
	if network == nil {
		var nErr error
		network, nErr = fields.Token.QueryNetwork().Only(ctx)
		if nErr != nil {
			return fmt.Errorf("fallback: token missing network: %w", nErr)
		}
	}

	providerToken, err := storage.Client.ProviderOrderToken.
		Query().
		Where(
			providerordertoken.NetworkEQ(network.Identifier),
			providerordertoken.HasProviderWith(
				providerprofile.IDEQ(fallbackID),
				providerprofile.HasProviderBalancesWith(
					providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(bucketCurrency.Code)),
					providerbalances.IsAvailableEQ(true),
				),
			),
			providerordertoken.HasTokenWith(token.IDEQ(fields.Token.ID)),
			providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(bucketCurrency.Code)),
			providerordertoken.SettlementAddressNEQ(""),
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return fmt.Errorf("fallback provider %s has no order token for %s/%s/%s", fallbackID, fields.Token.Symbol, network.Identifier, bucketCurrency.Code)
		}
		return fmt.Errorf("fallback: failed to get provider order token: %w", err)
	}

	providerRate, err := s.GetProviderRate(ctx, provider, fields.Token.Symbol, bucketCurrency.Code, RateSideSell)
	if err != nil {
		return fmt.Errorf("fallback: failed to get provider rate: %w", err)
	}
	allowedDeviation := fields.Rate.Mul(providerToken.RateSlippage.Div(decimal.NewFromInt(100)))
	if providerRate.Sub(fields.Rate).Abs().GreaterThan(allowedDeviation) {
		logger.WithFields(logger.Fields{
			"OrderID":      fields.ID.String(),
			"FallbackID":   fallbackID,
			"OrderRate":    fields.Rate.String(),
			"ProviderRate": providerRate.String(),
			"SlippagePct":  providerToken.RateSlippage.String(),
		}).Errorf("[FALLBACK_ASSIGNMENT] fallback assignment attempted but order rate is too far from what fallback node can fulfill")
		return fmt.Errorf("fallback assignment attempted for order %s but order rate is too far from what fallback provider %s can fulfill (provider rate %s, order rate %s, allowed slippage %s%%)",
			fields.ID.String(), fallbackID, providerRate.String(), fields.Rate.String(), providerToken.RateSlippage.String())
	}

	bal, err := s.balanceService.GetProviderFiatBalance(ctx, fallbackID, bucketCurrency.Code)
	if err != nil {
		return fmt.Errorf("fallback: failed to get provider balance: %w", err)
	}
	if !s.balanceService.CheckBalanceSufficiency(bal, fields.Amount.Mul(fields.Rate).RoundBank(0)) {
		return fmt.Errorf("fallback provider %s has insufficient balance for order %s", fallbackID, fields.ID.String())
	}

	fields.ProviderID = fallbackID
	if err := s.sendOrderRequest(ctx, fields); err != nil {
		return fmt.Errorf("fallback: send order request: %w", err)
	}
	if _, setErr := storage.Client.PaymentOrder.UpdateOneID(fields.ID).
		SetFallbackTriedAt(time.Now()).
		SetOrderPercent(decimal.NewFromInt(100)).
		Save(ctx); setErr != nil {
		logger.WithFields(logger.Fields{"OrderID": fields.ID.String(), "Error": setErr}).Errorf("[FALLBACK_ASSIGNMENT] failed to set fallback_tried_at on order")
		// Non-fatal: order request was sent; persistence can be reconciled later.
	}
	logger.WithFields(logger.Fields{"OrderID": fields.ID.String(), "FallbackID": fallbackID}).Infof("[FALLBACK_ASSIGNMENT] successful fallback assignment")
	return nil
}

// tryUsePreSetProvider fetches the provider by order.ProviderID, optionally refreshes the rate,
// then assigns via OTC or sendOrderRequest. Returns (true, provider, nil) on success.
func (s *Service) tryUsePreSetProvider(ctx context.Context, order types.PaymentOrderFields) (assigned bool, provider *ent.ProviderProfile, err error) {
	provider, err = storage.Client.ProviderProfile.
		Query().
		Where(providerprofile.IDEQ(order.ProviderID)).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
		}).Errorf("failed to get provider")
		return false, nil, err
	}

	if !order.UpdatedAt.IsZero() && order.UpdatedAt.Before(time.Now().Add(-10*time.Minute)) {
		currencyCode := ""
		if order.Institution != "" {
			institution, instErr := utils.GetInstitutionByCode(ctx, order.Institution, true)
			if instErr == nil && institution != nil && institution.Edges.FiatCurrency != nil {
				currencyCode = institution.Edges.FiatCurrency.Code
			}
		}
		if currencyCode != "" {
			order.Rate, err = s.GetProviderRate(ctx, provider, order.Token.Symbol, currencyCode, RateSideSell)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":      fmt.Sprintf("%v", err),
					"OrderID":    order.ID.String(),
					"ProviderID": order.ProviderID,
				}).Errorf("failed to get rate for provider")
			} else {
				_, err = storage.Client.PaymentOrder.
					Update().
					Where(paymentorder.MessageHashEQ(order.MessageHash)).
					SetRate(order.Rate).
					Save(ctx)
				if err != nil {
					logger.WithFields(logger.Fields{
						"Error":      fmt.Sprintf("%v", err),
						"OrderID":    order.ID.String(),
						"ProviderID": order.ProviderID,
					}).Errorf("failed to update rate for provider")
				}
			}
		}
	}

	if order.OrderType == "otc" {
		if err := s.assignOtcOrder(ctx, order); err != nil {
			return false, provider, err
		}
		return true, provider, nil
	}
	err = s.sendOrderRequest(ctx, order)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
		}).Errorf("failed to send order request to specific provider")
		return false, provider, err
	}
	return true, provider, nil
}

// assignOtcOrder assigns an OTC order to a provider in DB then creates a Redis key for reassignment.
func (s *Service) assignOtcOrder(ctx context.Context, order types.PaymentOrderFields) error {
	orderConf := config.OrderConfig()
	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
		}).Errorf("Failed to start transaction for OTC order assignment")
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if order.ProviderID != "" {
		provider, qErr := tx.ProviderProfile.Query().Where(providerprofile.IDEQ(order.ProviderID)).Only(ctx)
		if qErr != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", qErr),
				"OrderID":    order.ID.String(),
				"ProviderID": order.ProviderID,
			}).Errorf("failed to get provider for OTC order assignment")
			return fmt.Errorf("failed to get provider: %w", qErr)
		}
		if provider != nil {
			_, err = tx.PaymentOrder.
				Update().
				Where(paymentorder.IDEQ(order.ID)).
				SetProvider(provider).
				Save(ctx)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":      fmt.Sprintf("%v", err),
					"OrderID":    order.ID.String(),
					"ProviderID": order.ProviderID,
				}).Errorf("failed to assign OTC order to provider")
				return fmt.Errorf("failed to assign OTC order: %w", err)
			}
		}
	}

	if err = tx.Commit(); err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
		}).Errorf("Failed to commit OTC order assignment transaction")
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	orderKey := fmt.Sprintf("order_request_%s", order.ID)
	exists, err := storage.RedisClient.Exists(ctx, orderKey).Result()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"OrderKey":   orderKey,
		}).Errorf("Failed to check if OTC order request exists in Redis")
		return fmt.Errorf("failed to check order_request in Redis: %w", err)
	}
	if exists > 0 {
		existingProviderID, hgetErr := storage.RedisClient.HGet(ctx, orderKey, "providerId").Result()
		if hgetErr == nil && existingProviderID == order.ProviderID {
			logger.WithFields(logger.Fields{
				"OrderID":    order.ID.String(),
				"ProviderID": order.ProviderID,
				"OrderKey":   orderKey,
			}).Warnf("OTC order request already exists in Redis for same provider - skipping duplicate creation")
			return nil
		}
		if hgetErr == nil && existingProviderID != order.ProviderID {
			logger.WithFields(logger.Fields{
				"OrderID":            order.ID.String(),
				"ProviderID":         order.ProviderID,
				"ExistingProviderID": existingProviderID,
				"OrderKey":           orderKey,
			}).Errorf("OTC order request exists for different provider - DB/Redis consistency issue")
			return fmt.Errorf("order_request exists for different provider (redis=%s, current=%s)", existingProviderID, order.ProviderID)
		}
		verifyErr := hgetErr
		if verifyErr == nil {
			verifyErr = fmt.Errorf("providerId missing in Redis hash")
		}
		logger.WithFields(logger.Fields{
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"OrderKey":   orderKey,
			"Error":      verifyErr,
		}).Errorf("OTC order request exists but could not verify provider - skipping to avoid inconsistency")
		return fmt.Errorf("order_request exists but provider could not be verified: %w", verifyErr)
	}

	orderRequestData := map[string]interface{}{
		"type":       "otc",
		"providerId": order.ProviderID,
	}
	if err = storage.RedisClient.HSet(ctx, orderKey, orderRequestData).Err(); err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"OrderKey":   orderKey,
		}).Errorf("Failed to create Redis key for OTC order")
		return fmt.Errorf("failed to create order_request in Redis: %w", err)
	}
	if err = storage.RedisClient.ExpireAt(ctx, orderKey, time.Now().Add(orderConf.OrderRequestValidityOtc)).Err(); err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"OrderKey":   orderKey,
		}).Errorf("Failed to set TTL for OTC order request")
		_ = storage.RedisClient.Del(ctx, orderKey).Err()
		return fmt.Errorf("failed to set TTL for order_request: %w", err)
	}

	return nil
}

// countProviderInExcludeList counts how many times a provider appears in the exclude list.
func (s *Service) countProviderInExcludeList(excludeList []string, providerID string) int {
	count := 0
	for _, id := range excludeList {
		if id == providerID {
			count++
		}
	}
	return count
}

// getExcludePsps returns PSP names to exclude based on the global failure-rate threshold.
// PSPs that have a high failure rate in the last N minutes are excluded globally.
// Per-order exclusion is not used so the same order can retry a PSP after a transient failure.
func (s *Service) getExcludePsps(ctx context.Context) ([]string, error) {
	orderConf := config.OrderConfig()
	excluded := make(map[string]struct{})

	window := time.Duration(orderConf.PspExcludeWindowMinutes) * time.Minute
	if window <= 0 {
		window = 120 * time.Minute
	}
	since := time.Now().Add(-window)

	fulfillments, err := storage.Client.PaymentOrderFulfillment.Query().
		Where(paymentorderfulfillment.UpdatedAtGTE(since)).
		Select(
			paymentorderfulfillment.FieldPsp,
			paymentorderfulfillment.FieldValidationStatus,
		).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("global exclude PSPs: %w", err)
	}

	type stats struct{ attempts, failures int }
	byPsp := make(map[string]*stats)
	for _, f := range fulfillments {
		psp := strings.TrimSpace(f.Psp)
		if psp == "" {
			continue
		}
		if byPsp[psp] == nil {
			byPsp[psp] = &stats{}
		}
		byPsp[psp].attempts++
		if f.ValidationStatus == paymentorderfulfillment.ValidationStatusFailed {
			byPsp[psp].failures++
		}
	}

	minAttempts := orderConf.PspExcludeMinAttempts
	if minAttempts < 1 {
		minAttempts = 5
	}
	minFailures := orderConf.PspExcludeMinFailures
	if minFailures < 1 {
		minFailures = 3
	}
	minPercent := orderConf.PspExcludeMinFailurePercent
	if minPercent <= 0 {
		minPercent = 30
	}
	minRate := float64(minPercent) / 100

	for psp, st := range byPsp {
		if st.attempts < minAttempts || st.failures < minFailures {
			continue
		}
		rate := float64(st.failures) / float64(st.attempts)
		if rate >= minRate {
			excluded[psp] = struct{}{}
		}
	}

	out := make([]string, 0, len(excluded))
	for p := range excluded {
		out = append(out, p)
	}
	return out, nil
}

// sendOrderRequest reserves balance, writes the Redis order_request key, and notifies the provider.
func (s *Service) sendOrderRequest(ctx context.Context, order types.PaymentOrderFields) error {
	orderConf := config.OrderConfig()
	if order.Institution == "" {
		return fmt.Errorf("sendOrderRequest: order %s has no institution for currency resolution", order.ID.String())
	}
	inst, instErr := utils.GetInstitutionByCode(ctx, order.Institution, true)
	if instErr != nil || inst == nil || inst.Edges.FiatCurrency == nil {
		return fmt.Errorf("sendOrderRequest: institution or fiat currency for order %s: %w", order.ID.String(), instErr)
	}
	currency := inst.Edges.FiatCurrency.Code
	amount := order.Amount.Mul(order.Rate).RoundBank(0)

	orderKey := fmt.Sprintf("order_request_%s", order.ID)

	exists, err := storage.RedisClient.Exists(ctx, orderKey).Result()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"OrderKey":   orderKey,
		}).Errorf("Failed to check if order request exists in Redis")
		return err
	}
	if exists > 0 {
		existingProviderID, hErr := storage.RedisClient.HGet(ctx, orderKey, "providerId").Result()
		if hErr == nil && existingProviderID == order.ProviderID {
			logger.WithFields(logger.Fields{
				"OrderID":    order.ID.String(),
				"ProviderID": order.ProviderID,
				"OrderKey":   orderKey,
			}).Errorf("Order request already exists in Redis - skipping duplicate notification")
			return nil
		}
		if hErr == nil && existingProviderID != order.ProviderID {
			logger.WithFields(logger.Fields{
				"OrderID":            order.ID.String(),
				"ProviderID":         order.ProviderID,
				"ExistingProviderID": existingProviderID,
				"OrderKey":           orderKey,
			}).Errorf("Order request exists for different provider - potential race condition")
			return fmt.Errorf("order request exists for different provider")
		}
	}

	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"Currency":   currency,
			"Amount":     amount.String(),
		}).Errorf("Failed to start transaction for order processing")
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	txCommitted := false
	defer func() {
		if err != nil && !txCommitted {
			_ = tx.Rollback()
		}
	}()

	err = s.balanceService.ReserveFiatBalance(ctx, order.ProviderID, currency, amount, tx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"Currency":   currency,
			"Amount":     amount.String(),
		}).Errorf("Failed to reserve balance for order")
		return err
	}

	orderRequestData := map[string]interface{}{
		"amount":      order.Amount.Mul(order.Rate).RoundBank(0).String(),
		"institution": order.Institution,
		"currency":    currency,
		"providerId":  order.ProviderID,
	}

	err = storage.RedisClient.HSet(ctx, orderKey, orderRequestData).Err()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"OrderKey":   orderKey,
		}).Errorf("Failed to map order to a provider in Redis")
		return err
	}

	metaKey := fmt.Sprintf("order_request_meta_%s", order.ID)
	metaData := map[string]interface{}{
		"amount":     orderRequestData["amount"],
		"currency":   orderRequestData["currency"],
		"providerId": orderRequestData["providerId"],
	}
	err = storage.RedisClient.HSet(ctx, metaKey, metaData).Err()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"MetaKey":    metaKey,
		}).Errorf("Failed to persist order request metadata in Redis")
		_ = storage.RedisClient.Del(ctx, orderKey).Err()
		return err
	}

	err = storage.RedisClient.ExpireAt(ctx, orderKey, time.Now().Add(orderConf.OrderRequestValidity)).Err()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"OrderKey": orderKey,
		}).Errorf("Failed to set TTL for order request")
		cleanupErr := storage.RedisClient.Del(ctx, orderKey).Err()
		if cleanupErr != nil {
			logger.WithFields(logger.Fields{
				"Error":    fmt.Sprintf("%v", cleanupErr),
				"OrderKey": orderKey,
			}).Errorf("Failed to cleanup orderKey after ExpireAt failure")
		}
		_ = storage.RedisClient.Del(ctx, metaKey).Err()
		return err
	}

	err = storage.RedisClient.ExpireAt(ctx, metaKey, time.Now().Add(orderConf.OrderRequestValidity*2)).Err()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
			"MetaKey":    metaKey,
		}).Errorf("Failed to set TTL for order request metadata key")
		_ = storage.RedisClient.Del(ctx, orderKey).Err()
		_ = storage.RedisClient.Del(ctx, metaKey).Err()
		return err
	}

	if orderConf.FallbackProviderID == "" || order.ProviderID != orderConf.FallbackProviderID {
		excludePsps, excludeErr := s.getExcludePsps(ctx)
		if excludeErr != nil {
			logger.WithFields(logger.Fields{
				"OrderID": order.ID.String(),
				"Error":   excludeErr.Error(),
			}).Errorf("getExcludePsps failed, sending new_order without excludePsps")
		} else if len(excludePsps) > 0 {
			orderRequestData["excludePsps"] = excludePsps
		}
	}

	orderRequestData["orderId"] = order.ID.String()

	err = tx.Commit()
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
		}).Errorf("Failed to commit order processing transaction")
		_ = storage.RedisClient.Del(ctx, orderKey).Err()
		_ = storage.RedisClient.Del(ctx, metaKey).Err()
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	txCommitted = true

	err = s.notifyProvider(ctx, orderRequestData)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"OrderID":    order.ID.String(),
			"ProviderID": order.ProviderID,
		}).Errorf("Failed to notify provider")
		if relErr := s.balanceService.ReleaseFiatBalance(ctx, order.ProviderID, currency, amount, nil); relErr != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", relErr),
				"OrderID":    order.ID.String(),
				"ProviderID": order.ProviderID,
				"Currency":   currency,
				"Amount":     amount.String(),
			}).Errorf("Failed to release fiat balance after notifyProvider failure")
		}
		cleanupErr := storage.RedisClient.Del(ctx, orderKey).Err()
		if cleanupErr != nil {
			logger.WithFields(logger.Fields{
				"Error":    fmt.Sprintf("%v", cleanupErr),
				"OrderKey": orderKey,
			}).Errorf("Failed to cleanup orderKey after notifyProvider failure")
		}
		_ = storage.RedisClient.Del(ctx, metaKey).Err()
		return err
	}

	logger.WithFields(logger.Fields{
		"OrderID":    order.ID.String(),
		"ProviderID": order.ProviderID,
		"Currency":   currency,
		"Amount":     amount.String(),
	}).Infof("Order processed successfully with balance reserved")

	return nil
}

// notifyProvider sends an order request notification to a provider node via /new_order.
func (s *Service) notifyProvider(ctx context.Context, orderRequestData map[string]interface{}) error {
	providerID := orderRequestData["providerId"].(string)
	delete(orderRequestData, "providerId")

	data, err := utils.CallProviderWithHMAC(ctx, providerID, "POST", "/new_order", orderRequestData)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
		}).Errorf("failed to call provider /new_order endpoint")
		return err
	}

	logger.WithFields(logger.Fields{
		"ProviderID": providerID,
		"Data":       data,
	}).Infof("successfully called provider /new_order endpoint")

	return nil
}
