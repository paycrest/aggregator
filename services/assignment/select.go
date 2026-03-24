package assignment

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/paymentorder"
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

// AssignPaymentOrderWithTrigger assigns using DB-only candidate ranking
// (score DESC, 24h volume ASC, last_order_assigned_at ASC NULLS FIRST, id ASC).
func (s *Service) AssignPaymentOrderWithTrigger(ctx context.Context, order types.PaymentOrderFields, trigger string) error {
	if trigger == "" {
		trigger = AssignmentTriggerInitial
	}
	orderConf := config.OrderConfig()

	currentOrder, err := storage.Client.PaymentOrder.Get(ctx, order.ID)
	if err == nil {
		if currentOrder.Status != paymentorder.StatusPending {
			logger.WithFields(logger.Fields{"OrderID": order.ID.String(), "Status": currentOrder.Status}).Errorf("AssignPaymentOrder: Order is not in pending state, skipping assignment")
			return nil
		}
		orderKey := fmt.Sprintf("order_request_%s", order.ID)
		exists, rerr := storage.RedisClient.Exists(ctx, orderKey).Result()
		if rerr == nil && exists > 0 {
			logger.WithFields(logger.Fields{"OrderID": order.ID.String()}).Errorf("AssignPaymentOrder: Order request already exists, skipping duplicate assignment")
			return nil
		}
	} else if !ent.IsNotFound(err) {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "OrderID": order.ID.String()}).Errorf("AssignPaymentOrder: Failed to check order status")
	}

	excludeList, err := storage.RedisClient.LRange(ctx, fmt.Sprintf("order_exclude_list_%s", order.ID), 0, -1).Result()
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "OrderID": order.ID.String()}).Errorf("failed to get exclude list")
		return err
	}

	orderEnt, err := storage.Client.PaymentOrder.Query().
		Where(paymentorder.IDEQ(order.ID)).
		WithToken(func(tq *ent.TokenQuery) { tq.WithNetwork() }).
		Only(ctx)
	if err != nil {
		s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultError, nil, nil, false, nil, nil, fmt.Errorf("load order: %w", err))
		return fmt.Errorf("assign: load order: %w", err)
	}

	var rateSide RateSide
	switch orderEnt.Direction {
	case paymentorder.DirectionOnramp:
		rateSide = RateSideBuy
	default:
		rateSide = RateSideSell
	}

	if order.ProviderID != "" {
		excludeCount := s.countProviderInExcludeList(excludeList, order.ProviderID)
		shouldSkip := false
		if order.OrderType == "otc" {
			shouldSkip = excludeCount > 0
		} else {
			shouldSkip = excludeCount >= orderConf.ProviderMaxRetryAttempts
		}
		if !shouldSkip {
			if order.OrderType != "otc" && orderConf.ProviderStuckFulfillmentThreshold > 0 {
				stuckCount, errStuck := utils.GetProviderStuckOrderCount(ctx, order.ProviderID)
				if errStuck == nil && stuckCount >= orderConf.ProviderStuckFulfillmentThreshold {
					// fall through to DB selection
				} else {
					if errStuck != nil {
						logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", errStuck), "OrderID": order.ID.String()}).Errorf("failed to get stuck order count for pre-set provider")
					}
					assigned, provider, _ := s.tryUsePreSetProvider(ctx, order)
					if assigned {
						s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultAssigned, strPtr(order.ProviderID), nil, false, nil, nil, nil)
						return nil
					}
					if provider != nil && provider.VisibilityMode == providerprofile.VisibilityModePrivate {
						s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultSkipped, strPtr(order.ProviderID), nil, false, nil, nil, nil)
						return nil
					}
				}
			} else {
				assigned, provider, _ := s.tryUsePreSetProvider(ctx, order)
				if assigned {
					s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultAssigned, strPtr(order.ProviderID), nil, false, nil, nil, nil)
					return nil
				}
				if provider != nil && provider.VisibilityMode == providerprofile.VisibilityModePrivate {
					s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultSkipped, strPtr(order.ProviderID), nil, false, nil, nil, nil)
					return nil
				}
			}
		}
	}

	inst, err := utils.GetInstitutionByCode(ctx, order.Institution, true)
	if err != nil || inst == nil || inst.Edges.FiatCurrency == nil {
		s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultError, nil, nil, false, nil, nil, fmt.Errorf("resolve institution currency"))
		return fmt.Errorf("assign: institution or fiat currency not found for %q", order.Institution)
	}
	fiatCurrency := inst.Edges.FiatCurrency

	if order.Token == nil || order.Token.Edges.Network == nil {
		s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultError, nil, nil, false, nil, nil, fmt.Errorf("order token/network not loaded"))
		return fmt.Errorf("assign: token/network required on PaymentOrderFields")
	}
	networkID := order.Token.Edges.Network.Identifier

	buySnap, sellSnap, err := s.ensureAssignmentMarketSnapshot(ctx, orderEnt, fiatCurrency)
	if err != nil {
		s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultError, nil, nil, false, nil, nil, err)
		return fmt.Errorf("assign: market snapshot: %w", err)
	}

	isOTC := order.OrderType == "otc" || order.OrderType == string(paymentorder.OrderTypeOtc)
	fiatNeed := order.Amount.Mul(order.Rate).RoundBank(0)

	pq := storage.Client.ProviderOrderToken.Query().
		Where(
			providerordertoken.HasCurrencyWith(fiatcurrency.IDEQ(fiatCurrency.ID)),
			providerordertoken.HasTokenWith(token.IDEQ(order.Token.ID)),
			providerordertoken.NetworkEQ(networkID),
			providerordertoken.SettlementAddressNEQ(""),
			providerordertoken.HasProviderWith(
				providerprofile.IsActive(true),
				providerprofile.VisibilityModeEQ(providerprofile.VisibilityModePublic),
				providerprofile.HasProviderBalancesWith(
					providerbalances.HasFiatCurrencyWith(fiatcurrency.IDEQ(fiatCurrency.ID)),
					providerbalances.IsAvailableEQ(true),
					providerbalances.AvailableBalanceGTE(fiatNeed),
				),
			),
		)
	if orderConf.FallbackProviderID != "" {
		pq = pq.Where(providerordertoken.HasProviderWith(providerprofile.IDNEQ(orderConf.FallbackProviderID)))
	}
	pots, err := pq.WithProvider().WithCurrency().All(ctx)
	if err != nil {
		s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultError, nil, nil, false, &buySnap, &sellSnap, err)
		return fmt.Errorf("assign: query candidates: %w", err)
	}

	var candidates []*ent.ProviderOrderToken
	for _, pot := range pots {
		if !amountInRangeForOrder(pot, order.Amount, isOTC) {
			continue
		}
		candidates = append(candidates, pot)
	}

	if len(candidates) == 0 {
		if !isOTC {
			if fbErr := s.TryFallbackAssignment(ctx, orderEnt); fbErr == nil {
				s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultFallback, strPtr(orderConf.FallbackProviderID), nil, true, &buySnap, &sellSnap, nil)
				return nil
			}
		}
		s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultNoProvider, nil, nil, false, &buySnap, &sellSnap, nil)
		return fmt.Errorf("no provider matched for order")
	}

	provIDs := make([]string, 0, len(candidates))
	seen := map[string]struct{}{}
	for _, pot := range candidates {
		pid := pot.Edges.Provider.ID
		if _, ok := seen[pid]; ok {
			continue
		}
		seen[pid] = struct{}{}
		provIDs = append(provIDs, pid)
	}
	volMap, err := recentFiatVolumeByProvider(ctx, provIDs)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": err.Error()}).Warnf("assign: recent volume query failed; using zero volume")
		volMap = map[string]decimal.Decimal{}
	}

	slices.SortStableFunc(candidates, func(a, b *ent.ProviderOrderToken) int {
		if c := b.Score.Cmp(a.Score); c != 0 {
			return c
		}
		va := volMap[a.Edges.Provider.ID]
		vb := volMap[b.Edges.Provider.ID]
		if c := va.Cmp(vb); c != 0 {
			return c
		}
		if c := cmpLastAssigned(a, b); c != 0 {
			return c
		}
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})

	for _, pot := range candidates {
		pid := pot.Edges.Provider.ID
		if orderConf.FallbackProviderID != "" && pid == orderConf.FallbackProviderID {
			continue
		}
		exc := s.countProviderInExcludeList(excludeList, pid)
		if isOTC {
			if exc > 0 {
				continue
			}
		} else {
			if exc >= orderConf.ProviderMaxRetryAttempts {
				continue
			}
		}
		if !isOTC && orderConf.ProviderStuckFulfillmentThreshold > 0 {
			stuck, se := utils.GetProviderStuckOrderCount(ctx, pid)
			if se == nil && stuck >= orderConf.ProviderStuckFulfillmentThreshold {
				continue
			}
		}

		provRate := providerRateForAssignment(pot, rateSide, buySnap, sellSnap)
		if provRate.IsZero() {
			continue
		}
		allowed := order.Rate.Mul(pot.RateSlippage.Div(decimal.NewFromInt(100)))
		if provRate.Sub(order.Rate).Abs().GreaterThan(allowed) {
			continue
		}

		bal, berr := s.balanceService.GetProviderFiatBalance(ctx, pid, fiatCurrency.Code)
		if berr != nil || !s.balanceService.CheckBalanceSufficiency(bal, fiatNeed) {
			continue
		}

		assignOrder := order
		assignOrder.ProviderID = pid
		var assignErr error
		if isOTC {
			assignErr = s.assignOtcOrder(ctx, assignOrder)
		} else {
			assignErr = s.sendOrderRequest(ctx, assignOrder)
		}
		if assignErr != nil {
			logger.WithFields(logger.Fields{"OrderID": order.ID.String(), "ProviderID": pid, "Error": assignErr.Error()}).Errorf("assign: failed to assign to candidate")
			continue
		}

		now := time.Now()
		_, _ = storage.Client.ProviderOrderToken.UpdateOneID(pot.ID).SetLastOrderAssignedAt(now).Save(ctx)

		s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultAssigned, &pid, &pot.ID, false, &buySnap, &sellSnap, nil)
		return nil
	}

	if !isOTC {
		if fbErr := s.TryFallbackAssignment(ctx, orderEnt); fbErr == nil {
			s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultFallback, strPtr(orderConf.FallbackProviderID), nil, true, &buySnap, &sellSnap, nil)
			return nil
		}
	}
	s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultNoProvider, nil, nil, false, &buySnap, &sellSnap, nil)
	return fmt.Errorf("no provider matched for order")
}

func strPtr(s string) *string { return &s }

func cmpLastAssigned(a, b *ent.ProviderOrderToken) int {
	la, lb := a.LastOrderAssignedAt, b.LastOrderAssignedAt
	switch {
	case la == nil && lb == nil:
		return 0
	case la == nil:
		return -1
	case lb == nil:
		return 1
	default:
		return la.Compare(*lb)
	}
}

func amountInRangeForOrder(pot *ent.ProviderOrderToken, amount decimal.Decimal, isOTC bool) bool {
	if isOTC {
		return !amount.LessThan(pot.MinOrderAmountOtc) && !amount.GreaterThan(pot.MaxOrderAmountOtc)
	}
	if amount.GreaterThan(pot.MaxOrderAmount) {
		if pot.MinOrderAmountOtc.IsZero() || pot.MaxOrderAmountOtc.IsZero() {
			return false
		}
		return !amount.LessThan(pot.MinOrderAmountOtc) && !amount.GreaterThan(pot.MaxOrderAmountOtc)
	}
	return !amount.LessThan(pot.MinOrderAmount) && !amount.GreaterThan(pot.MaxOrderAmount)
}

func providerRateForAssignment(pot *ent.ProviderOrderToken, side RateSide, buySnap, sellSnap decimal.Decimal) decimal.Decimal {
	switch side {
	case RateSideBuy:
		if !pot.FixedBuyRate.IsZero() {
			return pot.FixedBuyRate
		}
		if !buySnap.IsZero() {
			return buySnap.Add(pot.FloatingBuyDelta).RoundBank(2)
		}
	case RateSideSell:
		if !pot.FixedSellRate.IsZero() {
			return pot.FixedSellRate
		}
		if !sellSnap.IsZero() {
			return sellSnap.Add(pot.FloatingSellDelta).RoundBank(2)
		}
	}
	return decimal.Zero
}

func (s *Service) ensureAssignmentMarketSnapshot(ctx context.Context, po *ent.PaymentOrder, fc *ent.FiatCurrency) (buy, sell decimal.Decimal, err error) {
	if po.AssignmentMarketBuyRate != nil && po.AssignmentMarketSellRate != nil {
		return *po.AssignmentMarketBuyRate, *po.AssignmentMarketSellRate, nil
	}
	buy = fc.MarketBuyRate
	sell = fc.MarketSellRate
	_, err = storage.Client.PaymentOrder.UpdateOneID(po.ID).
		SetAssignmentMarketBuyRate(buy).
		SetAssignmentMarketSellRate(sell).
		Save(ctx)
	if err != nil {
		return decimal.Zero, decimal.Zero, err
	}
	return buy, sell, nil
}

func recentFiatVolumeByProvider(ctx context.Context, providerIDs []string) (map[string]decimal.Decimal, error) {
	out := make(map[string]decimal.Decimal)
	if len(providerIDs) == 0 {
		return out, nil
	}
	since := time.Now().Add(-RecentVolumeWindow)
	for _, pid := range providerIDs {
		var sum float64
		row := storage.DB.QueryRowContext(ctx, `
SELECT COALESCE(SUM(amount * rate), 0)
FROM payment_orders
WHERE provider_profile_assigned_orders = $1
  AND status IN ('validated', 'settled')
  AND updated_at >= $2`, pid, since)
		if err := row.Scan(&sum); err != nil {
			return nil, err
		}
		out[pid] = decimal.NewFromFloat(sum)
	}
	return out, nil
}

func (s *Service) recordAssignmentRun(ctx context.Context, orderID uuid.UUID, trigger, result string, provID *string, potID *int, usedFallback bool, buy, sell *decimal.Decimal, runErr error) {
	b := storage.Client.ProviderAssignmentRun.Create().SetPaymentOrderID(orderID).SetTrigger(trigger).SetResult(result).SetUsedFallback(usedFallback)
	if provID != nil {
		b.SetAssignedProviderID(*provID)
	}
	if potID != nil {
		b.SetProviderOrderTokenID(*potID)
	}
	if buy != nil {
		b.SetMarketBuyRateSnapshot(*buy)
	}
	if sell != nil {
		b.SetMarketSellRateSnapshot(*sell)
	}
	if runErr != nil {
		b.SetErrorMessage(runErr.Error())
	}
	if _, err := b.Save(ctx); err != nil {
		logger.WithFields(logger.Fields{"OrderID": orderID.String(), "Error": err.Error()}).Errorf("recordAssignmentRun: failed to persist")
	}
}
