package assignment

import (
	"context"
	"errors"
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
// (direction-specific score DESC — score_onramp for onramp, score_offramp for offramp —
// then 24h volume ASC, last_order_assigned_at ASC NULLS FIRST, id ASC).
func (s *Service) AssignPaymentOrderWithTrigger(ctx context.Context, order types.PaymentOrderFields, trigger string) error {
	ctx, cancel := context.WithTimeout(ctx, assignPaymentOrderTimeout)
	defer cancel()

	if trigger == "" {
		trigger = AssignmentTriggerInitial
	}
	orderConf := config.OrderConfig()
	maxRetryAttempts := orderConf.ProviderMaxRetryAttempts
	if maxRetryAttempts < 1 {
		maxRetryAttempts = 1
	}

	var assignmentLockHeld bool
	currentOrder, err := storage.Client.PaymentOrder.Get(ctx, order.ID)
	if err == nil {
		if currentOrder.Status != paymentorder.StatusPending {
			logger.WithFields(logger.Fields{"OrderID": order.ID.String(), "Status": currentOrder.Status}).Errorf("AssignPaymentOrder: Order is not in pending state, skipping assignment")
			s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultSkipped, nil, nil, false, nil, nil, fmt.Errorf("AssignPaymentOrder: Order is not in pending state (status=%s)", currentOrder.Status))
			return nil
		}
		orderKey := fmt.Sprintf("order_request_%s", order.ID)
		releaseAssignLock, lockErr := acquireOrderAssignmentLock(ctx, order.ID)
		if lockErr != nil {
			if errors.Is(lockErr, ErrAssignmentLockHeld) {
				rerr := resolveConcurrentAssignmentStart(ctx, order, orderKey)
				if rerr != nil {
					s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultError, nil, nil, false, nil, nil, rerr)
				} else {
					s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultSkipped, nil, nil, false, nil, nil, fmt.Errorf("AssignPaymentOrder: skipped concurrent assignment (order_request present or resolved)"))
				}
				return rerr
			}
			s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultError, nil, nil, false, nil, nil, fmt.Errorf("redis assignment lock: %w", lockErr))
			return lockErr
		}
		defer releaseAssignLock()
		assignmentLockHeld = true
		exists, rerr := storage.RedisClient.Exists(ctx, orderKey).Result()
		if rerr == nil && exists > 0 {
			logger.WithFields(logger.Fields{"OrderID": order.ID.String()}).Errorf("AssignPaymentOrder: Order request already exists, skipping duplicate assignment")
			s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultSkipped, nil, nil, false, nil, nil, fmt.Errorf("AssignPaymentOrder: Order request already exists in Redis; skipping duplicate assignment"))
			return nil
		}
	} else if !ent.IsNotFound(err) {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "OrderID": order.ID.String()}).Errorf("AssignPaymentOrder: Failed to check order status")
		s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultError, nil, nil, false, nil, nil, fmt.Errorf("AssignPaymentOrder: failed to check order status: %w", err))
		return err
	}

	excludeList, err := storage.RedisClient.LRange(ctx, fmt.Sprintf("order_exclude_list_%s", order.ID), 0, -1).Result()
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "OrderID": order.ID.String()}).Errorf("failed to get exclude list")
		s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultError, nil, nil, false, nil, nil, fmt.Errorf("failed to get exclude list: %w", err))
		return err
	}

	orderEnt, err := storage.Client.PaymentOrder.Query().
		Where(paymentorder.IDEQ(order.ID)).
		WithToken(func(tq *ent.TokenQuery) { tq.WithNetwork() }).
		WithProvider().
		Only(ctx)
	if err != nil {
		s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultError, nil, nil, false, nil, nil, fmt.Errorf("load order: %w", err))
		return fmt.Errorf("assign: load order: %w", err)
	}

	workOrder, err := paymentOrderFieldsFromEnt(orderEnt)
	if err != nil {
		s.recordAssignmentRun(ctx, order.ID, trigger, AssignmentRunResultError, nil, nil, false, nil, nil, err)
		return fmt.Errorf("assign: build order fields: %w", err)
	}

	var rateSide RateSide
	switch orderEnt.Direction {
	case paymentorder.DirectionOnramp:
		rateSide = RateSideBuy
	default:
		rateSide = RateSideSell
	}

	if workOrder.ProviderID != "" {
		excludeCount := s.countProviderInExcludeList(excludeList, workOrder.ProviderID)
		shouldSkip := false
		if workOrder.OrderType == "otc" {
			shouldSkip = excludeCount > 0
		} else {
			shouldSkip = excludeCount >= maxRetryAttempts
		}
		if !shouldSkip {
			if workOrder.OrderType != "otc" && orderConf.ProviderStuckFulfillmentThreshold > 0 {
				stuckCount, errStuck := utils.GetProviderStuckOrderCount(ctx, workOrder.ProviderID)
				if errStuck == nil && stuckCount >= orderConf.ProviderStuckFulfillmentThreshold {
					logger.WithFields(logger.Fields{
						"OrderID":    workOrder.ID.String(),
						"ProviderID": workOrder.ProviderID,
						"StuckCount": stuckCount,
						"Threshold":  orderConf.ProviderStuckFulfillmentThreshold,
					}).Warnf("assign: pre-set provider skipped (stuck threshold); using public selection")
					exclKey := fmt.Sprintf("order_exclude_list_%s", workOrder.ID)
					if pushErr := storage.RedisClient.RPush(ctx, exclKey, workOrder.ProviderID).Err(); pushErr != nil {
						logger.WithFields(logger.Fields{"OrderID": workOrder.ID.String(), "Error": pushErr.Error()}).Warnf("assign: failed to push pre-set provider to exclude list after stuck skip")
					} else {
						excludeList = append(excludeList, workOrder.ProviderID)
					}
				} else {
					if errStuck != nil {
						logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", errStuck), "OrderID": workOrder.ID.String()}).Errorf("failed to get stuck order count for pre-set provider")
					}
					assigned, provider, presetErr := s.tryUsePreSetProvider(ctx, workOrder, assignmentLockHeld)
					if presetErr != nil {
						s.recordAssignmentRun(ctx, workOrder.ID, trigger, AssignmentRunResultError, strPtr(workOrder.ProviderID), nil, false, nil, nil, presetErr)
						return fmt.Errorf("assign: pre-set provider: %w", presetErr)
					}
					if assigned {
						s.recordAssignmentRun(ctx, workOrder.ID, trigger, AssignmentRunResultAssigned, strPtr(workOrder.ProviderID), nil, false, nil, nil, nil)
						return nil
					}
					if provider != nil && provider.VisibilityMode == providerprofile.VisibilityModePrivate {
						s.recordAssignmentRun(ctx, workOrder.ID, trigger, AssignmentRunResultSkipped, strPtr(workOrder.ProviderID), nil, false, nil, nil, nil)
						return nil
					}
				}
			} else {
				assigned, provider, presetErr := s.tryUsePreSetProvider(ctx, workOrder, assignmentLockHeld)
				if presetErr != nil {
					s.recordAssignmentRun(ctx, workOrder.ID, trigger, AssignmentRunResultError, strPtr(workOrder.ProviderID), nil, false, nil, nil, presetErr)
					return fmt.Errorf("assign: pre-set provider: %w", presetErr)
				}
				if assigned {
					s.recordAssignmentRun(ctx, workOrder.ID, trigger, AssignmentRunResultAssigned, strPtr(workOrder.ProviderID), nil, false, nil, nil, nil)
					return nil
				}
				if provider != nil && provider.VisibilityMode == providerprofile.VisibilityModePrivate {
					s.recordAssignmentRun(ctx, workOrder.ID, trigger, AssignmentRunResultSkipped, strPtr(workOrder.ProviderID), nil, false, nil, nil, nil)
					return nil
				}
			}
		}
	}

	inst, err := utils.GetInstitutionByCode(ctx, workOrder.Institution, true)
	if err != nil || inst == nil || inst.Edges.FiatCurrency == nil {
		s.recordAssignmentRun(ctx, workOrder.ID, trigger, AssignmentRunResultError, nil, nil, false, nil, nil, fmt.Errorf("resolve institution currency"))
		return fmt.Errorf("assign: institution or fiat currency not found for %q", workOrder.Institution)
	}
	fiatCurrency := inst.Edges.FiatCurrency

	orderNet := resolveOrderNetwork(workOrder)
	if workOrder.Token == nil || orderNet == nil {
		s.recordAssignmentRun(ctx, workOrder.ID, trigger, AssignmentRunResultError, nil, nil, false, nil, nil, fmt.Errorf("order token/network not loaded from DB"))
		return fmt.Errorf("assign: token/network required on payment order")
	}
	networkID := orderNet.Identifier

	buySnap, sellSnap, err := s.ensureAssignmentMarketSnapshot(ctx, orderEnt, fiatCurrency)
	if err != nil {
		s.recordAssignmentRun(ctx, workOrder.ID, trigger, AssignmentRunResultError, nil, nil, false, nil, nil, err)
		return fmt.Errorf("assign: market snapshot: %w", err)
	}

	isOTC := orderEnt.OrderType == paymentorder.OrderTypeOtc
	fiatNeed := workOrder.Amount.Mul(workOrder.Rate).RoundBank(0)

	pq := storage.Client.ProviderOrderToken.Query().
		Where(
			providerordertoken.HasCurrencyWith(fiatcurrency.IDEQ(fiatCurrency.ID)),
			providerordertoken.HasTokenWith(token.IDEQ(workOrder.Token.ID)),
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
		s.recordAssignmentRun(ctx, workOrder.ID, trigger, AssignmentRunResultError, nil, nil, false, &buySnap, &sellSnap, err)
		return fmt.Errorf("assign: query candidates: %w", err)
	}

	var candidates []*ent.ProviderOrderToken
	for _, pot := range pots {
		if !amountInRangeForOrder(pot, workOrder.Amount, isOTC) {
			continue
		}
		candidates = append(candidates, pot)
	}

	if len(candidates) == 0 {
		if !isOTC {
			if fbErr := s.TryFallbackAssignment(ctx, orderEnt, assignmentLockHeld); fbErr == nil {
				s.recordAssignmentRun(ctx, workOrder.ID, trigger, AssignmentRunResultFallback, strPtr(orderConf.FallbackProviderID), nil, true, &buySnap, &sellSnap, nil)
				return nil
			}
		}
		s.recordAssignmentRun(ctx, workOrder.ID, trigger, AssignmentRunResultNoProvider, nil, nil, false, &buySnap, &sellSnap, nil)
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

	var stuckCountByProvider map[string]int
	if !isOTC && orderConf.ProviderStuckFulfillmentThreshold > 0 && len(provIDs) > 0 {
		stuckCountByProvider, err = utils.StuckOrderCountsByProviderIDs(ctx, provIDs)
		if err != nil {
			logger.WithFields(logger.Fields{"Error": err.Error()}).Warnf("assign: stuck-order count query failed; treating stuck count as zero")
			stuckCountByProvider = map[string]int{}
		}
	}

	slices.SortStableFunc(candidates, func(a, b *ent.ProviderOrderToken) int {
		if c := cmpAssignmentScore(a, b, orderEnt.Direction); c != 0 {
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
			if exc >= maxRetryAttempts {
				continue
			}
		}
		if !isOTC && orderConf.ProviderStuckFulfillmentThreshold > 0 {
			stuck := stuckCountByProvider[pid]
			if stuck >= orderConf.ProviderStuckFulfillmentThreshold {
				continue
			}
		}

		provRate := providerRateForAssignment(pot, rateSide, buySnap, sellSnap)
		if provRate.IsZero() {
			continue
		}
		allowed := workOrder.Rate.Mul(pot.RateSlippage.Div(decimal.NewFromInt(100)))
		if provRate.Sub(workOrder.Rate).Abs().GreaterThan(allowed) {
			continue
		}

		bal, berr := s.balanceService.GetProviderFiatBalance(ctx, pid, fiatCurrency.Code)
		if berr != nil || !s.balanceService.CheckBalanceSufficiency(bal, fiatNeed) {
			continue
		}

		assignOrder := workOrder
		assignOrder.ProviderID = pid
		var assignErr error
		if isOTC {
			assignErr = s.assignOtcOrder(ctx, assignOrder, assignmentLockHeld)
		} else {
			assignErr = s.sendOrderRequest(ctx, assignOrder, assignmentLockHeld)
		}
		if assignErr != nil {
			if errors.Is(assignErr, ErrAssignmentLockHeld) {
				logger.WithFields(logger.Fields{"OrderID": workOrder.ID.String(), "ProviderID": pid}).Warnf("assign: concurrent assignment for order; stopping candidate loop")
				s.recordAssignmentRun(ctx, workOrder.ID, trigger, AssignmentRunResultError, &pid, &pot.ID, false, &buySnap, &sellSnap, assignErr)
				return assignErr
			}
			logger.WithFields(logger.Fields{"OrderID": workOrder.ID.String(), "ProviderID": pid, "Error": assignErr.Error()}).Errorf("assign: failed to assign to candidate")
			continue
		}

		now := time.Now()
		if _, uerr := storage.Client.ProviderOrderToken.UpdateOneID(pot.ID).SetLastOrderAssignedAt(now).Save(ctx); uerr != nil {
			logger.WithFields(logger.Fields{
				"OrderID":              workOrder.ID.String(),
				"ProviderID":           pid,
				"ProviderOrderTokenID": pot.ID,
				"Error":                uerr.Error(),
			}).Warnf("assign: failed to update last_order_assigned_at")
		}

		s.recordAssignmentRun(ctx, workOrder.ID, trigger, AssignmentRunResultAssigned, &pid, &pot.ID, false, &buySnap, &sellSnap, nil)
		return nil
	}

	if !isOTC {
		if fbErr := s.TryFallbackAssignment(ctx, orderEnt, assignmentLockHeld); fbErr == nil {
			s.recordAssignmentRun(ctx, workOrder.ID, trigger, AssignmentRunResultFallback, strPtr(orderConf.FallbackProviderID), nil, true, &buySnap, &sellSnap, nil)
			return nil
		}
	}
	s.recordAssignmentRun(ctx, workOrder.ID, trigger, AssignmentRunResultNoProvider, nil, nil, false, &buySnap, &sellSnap, nil)
	return fmt.Errorf("no provider matched for order")
}

func strPtr(s string) *string { return &s }

// resolveOrderNetwork returns the network for assignment using PaymentOrderFields.Network when set,
// otherwise Token.Edges.Network (kept in sync by paymentOrderFieldsFromEnt).
func resolveOrderNetwork(f types.PaymentOrderFields) *ent.Network {
	if f.Network != nil {
		return f.Network
	}
	if f.Token != nil {
		return f.Token.Edges.Network
	}
	return nil
}

// paymentOrderFieldsFromEnt builds assignment input from the persisted order and loaded edges (token+network+provider).
func paymentOrderFieldsFromEnt(po *ent.PaymentOrder) (types.PaymentOrderFields, error) {
	if po.Edges.Token == nil {
		return types.PaymentOrderFields{}, fmt.Errorf("payment order %s has no token loaded", po.ID)
	}
	tok := po.Edges.Token
	var net *ent.Network
	if tok.Edges.Network != nil {
		net = tok.Edges.Network
	}
	fields := types.PaymentOrderFields{
		ID:                po.ID,
		OrderType:         po.OrderType.String(),
		Token:             tok,
		Network:           net,
		GatewayID:         po.GatewayID,
		Amount:            po.Amount,
		Rate:              po.Rate,
		ProtocolFee:       po.ProtocolFee,
		AmountInUSD:       po.AmountInUsd,
		BlockNumber:       po.BlockNumber,
		TxHash:            po.TxHash,
		Institution:       po.Institution,
		AccountIdentifier: po.AccountIdentifier,
		AccountName:       po.AccountName,
		Sender:            po.Sender,
		MessageHash:       po.MessageHash,
		Memo:              po.Memo,
		Metadata:          po.Metadata,
		UpdatedAt:         po.UpdatedAt,
		CreatedAt:         po.CreatedAt,
	}
	if po.Edges.Provider != nil {
		fields.ProviderID = po.Edges.Provider.ID
	}
	// Keep top-level Network and Token.Edges.Network aligned for downstream checks and future loaders.
	if fields.Network != nil && fields.Token != nil && fields.Token.Edges.Network == nil {
		fields.Token.Edges.Network = fields.Network
	} else if fields.Token != nil && fields.Token.Edges.Network != nil && fields.Network == nil {
		fields.Network = fields.Token.Edges.Network
	}
	return fields, nil
}

func scoreForAssignment(pot *ent.ProviderOrderToken, dir paymentorder.Direction) decimal.Decimal {
	if dir == paymentorder.DirectionOnramp {
		return pot.ScoreOnramp
	}
	return pot.ScoreOfframp
}

// cmpAssignmentScore orders by higher direction-specific score first (same ordering as b.Score.Cmp(a.Score)).
func cmpAssignmentScore(a, b *ent.ProviderOrderToken, dir paymentorder.Direction) int {
	return scoreForAssignment(b, dir).Cmp(scoreForAssignment(a, dir))
}

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
	// Regular orders: only regular min/max; do not admit via OTC bounds (would mismatch assignOtcOrder vs sendOrderRequest).
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

func assignmentMarketRatesMatchFiat(storedBuy, storedSell, fcBuy, fcSell decimal.Decimal) bool {
	return rateCloseEnoughForAssignment(storedBuy, fcBuy) && rateCloseEnoughForAssignment(storedSell, fcSell)
}

func rateCloseEnoughForAssignment(a, b decimal.Decimal) bool {
	if a.IsZero() && b.IsZero() {
		return true
	}
	diff := a.Sub(b).Abs()
	maxAbs := a.Abs()
	if b.Abs().GreaterThan(maxAbs) {
		maxAbs = b.Abs()
	}
	if maxAbs.IsZero() {
		return diff.IsZero()
	}
	return diff.Div(maxAbs).LessThan(assignmentMarketRateRelTol)
}

func (s *Service) ensureAssignmentMarketSnapshot(ctx context.Context, po *ent.PaymentOrder, fc *ent.FiatCurrency) (buy, sell decimal.Decimal, err error) {
	if po.AssignmentMarketBuyRate != nil && po.AssignmentMarketSellRate != nil {
		stBuy, stSell := *po.AssignmentMarketBuyRate, *po.AssignmentMarketSellRate
		if assignmentMarketRatesMatchFiat(stBuy, stSell, fc.MarketBuyRate, fc.MarketSellRate) {
			return stBuy, stSell, nil
		}
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
	since := time.Now().Add(-RecentVolumeWindow)
	return utils.RecentFiatVolumeByProvider(ctx, since, providerIDs)
}

func (s *Service) recordAssignmentRun(ctx context.Context, orderID uuid.UUID, trigger, result string, provID *string, potID *int, usedFallback bool, buy, sell *decimal.Decimal, runErr error) {
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordAssignmentRunTimeout)
	defer cancel()

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
	if _, err := b.Save(auditCtx); err != nil {
		logger.WithFields(logger.Fields{"OrderID": orderID.String(), "Error": err.Error()}).Errorf("recordAssignmentRun: failed to persist")
	}
}
