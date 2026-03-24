package assignment

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerassignmentrun"
	"github.com/paycrest/aggregator/ent/providerbalances"
	"github.com/paycrest/aggregator/ent/providerprofile"
	tokenEnt "github.com/paycrest/aggregator/ent/token"
	userEnt "github.com/paycrest/aggregator/ent/user"
	svc "github.com/paycrest/aggregator/services"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils/test"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assignCtx holds only the shared (across all subtests) fixtures: network, token, mock HTTP server.
type assignCtx struct {
	ctx     context.Context
	client  *ent.Client
	tok     *ent.Token // loaded with WithNetwork()
	mockURL string     // mock HTTP server URL every provider will use
}

// subEnv provides per-subtest isolation: a unique FiatCurrency + Institution pair.
// The DB candidate query filters by currency ID, so providers from other subtests
// are invisible to a subtest using a different subEnv.
type subEnv struct {
	cur      *ent.FiatCurrency
	instCode string
}

// newAssignCtx creates the shared network/token/mock-server fixtures.
func newAssignCtx(t *testing.T) assignCtx {
	t.Helper()
	ctx := context.Background()
	client := db.Client

	netw, err := client.Network.Create().
		SetIdentifier("assign-net").
		SetChainID(56).
		SetRPCEndpoint("ws://localhost:8545").
		SetBlockTime(decimal.NewFromFloat(3)).
		SetFee(decimal.NewFromFloat(0.1)).
		SetIsTestnet(true).
		Save(ctx)
	require.NoError(t, err)

	tok, err := client.Token.Create().
		SetSymbol("ASNTOK").
		SetContractAddress("0x2222222222222222222222222222222222222222").
		SetDecimals(6).
		SetNetworkID(netw.ID).
		SetIsEnabled(true).
		SetBaseCurrency("A01").
		Save(ctx)
	require.NoError(t, err)
	tok, err = client.Token.Query().Where(tokenEnt.IDEQ(tok.ID)).WithNetwork().Only(ctx)
	require.NoError(t, err)

	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","message":"ok"}`))
	}))
	t.Cleanup(mockSrv.Close)

	return assignCtx{ctx: ctx, client: client, tok: tok, mockURL: mockSrv.URL}
}

// newSubEnv creates a unique FiatCurrency + Institution for a single subtest.
// code must be unique across all subtests (e.g. "A01", "A02", …).
func newSubEnv(t *testing.T, ac assignCtx, code string) subEnv {
	t.Helper()
	cur, err := ac.client.FiatCurrency.Create().
		SetCode(code).
		SetShortName(code).
		SetSymbol(code).
		SetName(code + " Test Currency").
		SetDecimals(2).
		SetIsEnabled(true).
		SetMarketBuyRate(decimal.NewFromFloat(1500)).
		SetMarketSellRate(decimal.NewFromFloat(1500)).
		Save(ac.ctx)
	require.NoError(t, err)

	instCode := code + "BNK"
	_, err = ac.client.Institution.Create().
		SetCode(instCode).
		SetName(instCode + " Institution").
		SetFiatCurrencyID(cur.ID).
		Save(ac.ctx)
	require.NoError(t, err)

	return subEnv{cur: cur, instCode: instCode}
}

// makeAssignProvider creates a fully eligible public provider scoped to se's currency.
func makeAssignProvider(t *testing.T, ac assignCtx, se subEnv, email string, rate, score, balance float64) *ent.ProviderProfile {
	t.Helper()
	ctx := ac.ctx
	client := ac.client

	u, err := test.CreateTestUser(map[string]interface{}{"scope": "provider", "email": email})
	require.NoError(t, err)

	prov, err := test.CreateTestProviderProfile(map[string]interface{}{
		"user_id":         u.ID,
		"currency_id":     se.cur.ID,
		"visibility_mode": "public",
	})
	require.NoError(t, err)

	_, err = client.ProviderProfile.UpdateOneID(prov.ID).
		SetIsActive(true).
		SetHostIdentifier(ac.mockURL).
		Save(ctx)
	require.NoError(t, err)

	_, err = client.User.UpdateOneID(u.ID).
		SetKybVerificationStatus(userEnt.KybVerificationStatusApproved).
		Save(ctx)
	require.NoError(t, err)

	apiKeySvc := svc.NewAPIKeyService()
	_, _, err = apiKeySvc.GenerateAPIKey(ctx, nil, nil, prov)
	require.NoError(t, err)

	pot, err := test.AddProviderOrderTokenToProvider(map[string]interface{}{
		"provider":             prov,
		"currency_id":          se.cur.ID,
		"token_id":             ac.tok.ID,
		"network":              ac.tok.Edges.Network.Identifier,
		"fixed_sell_rate":      decimal.NewFromFloat(rate),
		"max_order_amount":     decimal.NewFromFloat(10_000),
		"min_order_amount":     decimal.NewFromFloat(1),
		"max_order_amount_otc": decimal.NewFromFloat(10_000),
		"min_order_amount_otc": decimal.NewFromFloat(100),
	})
	require.NoError(t, err)

	if score != 0 {
		_, err = client.ProviderOrderToken.UpdateOneID(pot.ID).
			SetScore(decimal.NewFromFloat(score)).
			Save(ctx)
		require.NoError(t, err)
	}

	_, err = client.ProviderBalances.Update().
		Where(providerbalances.HasProviderWith(providerprofile.IDEQ(prov.ID))).
		Where(providerbalances.HasFiatCurrencyWith(fiatcurrency.IDEQ(se.cur.ID))).
		SetAvailableBalance(decimal.NewFromFloat(balance)).
		SetTotalBalance(decimal.NewFromFloat(balance)).
		SetIsAvailable(true).
		Save(ctx)
	require.NoError(t, err)

	return prov
}

// makeAssignOrder creates a pending payment order referencing se's institution.
func makeAssignOrder(t *testing.T, ac assignCtx, se subEnv, amount, rate float64) *ent.PaymentOrder {
	t.Helper()
	order, err := ac.client.PaymentOrder.Create().
		SetAmount(decimal.NewFromFloat(amount)).
		SetAmountInUsd(decimal.NewFromFloat(amount)).
		SetRate(decimal.NewFromFloat(rate)).
		SetStatus(paymentorder.StatusPending).
		SetInstitution(se.instCode).
		SetAccountIdentifier("9876543210").
		SetAccountName("Assign Test Account").
		SetMemo("assignment test").
		SetToken(ac.tok).
		SetGatewayID(uuid.New().String()).
		SetBlockNumber(1).
		Save(ac.ctx)
	require.NoError(t, err)
	return order
}

// orderFields converts a PaymentOrder into the types.PaymentOrderFields the assignment service expects.
func orderFields(order *ent.PaymentOrder, tok *ent.Token, orderType string) types.PaymentOrderFields {
	if orderType == "" {
		orderType = string(paymentorder.OrderTypeRegular)
	}
	return types.PaymentOrderFields{
		ID:                order.ID,
		OrderType:         orderType,
		GatewayID:         order.GatewayID,
		Amount:            order.Amount,
		Rate:              order.Rate,
		BlockNumber:       order.BlockNumber,
		Institution:       order.Institution,
		AccountIdentifier: order.AccountIdentifier,
		AccountName:       order.AccountName,
		Memo:              order.Memo,
		Token:             tok,
		Network:           tok.Edges.Network,
	}
}

// assignedProviderID reads the providerId stored in the Redis order_request hash.
func assignedProviderID(t *testing.T, orderID uuid.UUID) string {
	t.Helper()
	key := fmt.Sprintf("order_request_%s", orderID)
	pid, err := db.RedisClient.HGet(context.Background(), key, "providerId").Result()
	require.NoError(t, err, "order_request key should exist after successful assignment")
	return pid
}

// TestAssignment exercises the DB-only provider selection engine.
// Each subtest creates its own FiatCurrency (via newSubEnv) so that the
// candidate DB query only sees that subtest's providers.
func TestAssignment(t *testing.T) {
	newTestDB(t, "assign_tests")
	ac := newAssignCtx(t)
	s := New()

	t.Run("score_ordering_higher_score_wins", func(t *testing.T) {
		se := newSubEnv(t, ac, "A01")
		pLow := makeAssignProvider(t, ac, se, "a01_low@t.com", 1500, 1.0, 1_000_000)
		pHigh := makeAssignProvider(t, ac, se, "a01_high@t.com", 1500, 5.0, 1_000_000)
		order := makeAssignOrder(t, ac, se, 10, 1500)

		require.NoError(t, s.AssignPaymentOrder(ac.ctx, orderFields(order, ac.tok, "")))

		assert.Equal(t, pHigh.ID, assignedProviderID(t, order.ID),
			"provider with higher score should be assigned first")
		_ = pLow
	})

	t.Run("last_assigned_at_tiebreak_nil_wins", func(t *testing.T) {
		se := newSubEnv(t, ac, "A02")
		pRecent := makeAssignProvider(t, ac, se, "a02_recent@t.com", 1500, 0, 1_000_000)
		pNever := makeAssignProvider(t, ac, se, "a02_never@t.com", 1500, 0, 1_000_000)

		recentPot := getProviderPOT(t, ac.ctx, pRecent.ID)
		_, err := ac.client.ProviderOrderToken.UpdateOneID(recentPot.ID).
			SetLastOrderAssignedAt(time.Now().Add(-10 * time.Second)).
			Save(ac.ctx)
		require.NoError(t, err)

		order := makeAssignOrder(t, ac, se, 10, 1500)
		require.NoError(t, s.AssignPaymentOrder(ac.ctx, orderFields(order, ac.tok, "")))

		assert.Equal(t, pNever.ID, assignedProviderID(t, order.ID),
			"provider with nil last_order_assigned_at should win over recently assigned one")
		_ = pRecent
	})

	t.Run("insufficient_balance_skipped", func(t *testing.T) {
		se := newSubEnv(t, ac, "A03")
		pPoor := makeAssignProvider(t, ac, se, "a03_poor@t.com", 1500, 0, 100)
		pRich := makeAssignProvider(t, ac, se, "a03_rich@t.com", 1500, 0, 1_000_000)

		_, err := ac.client.ProviderOrderToken.UpdateOneID(
			getProviderPOT(t, ac.ctx, pPoor.ID).ID,
		).SetScore(decimal.NewFromFloat(10)).Save(ac.ctx)
		require.NoError(t, err)

		order := makeAssignOrder(t, ac, se, 100, 1500)
		require.NoError(t, s.AssignPaymentOrder(ac.ctx, orderFields(order, ac.tok, "")))

		assert.Equal(t, pRich.ID, assignedProviderID(t, order.ID),
			"provider with insufficient balance must be skipped")
		_ = pPoor
	})

	t.Run("amount_out_of_range_skipped", func(t *testing.T) {
		se := newSubEnv(t, ac, "A04")
		pSmall := makeAssignProvider(t, ac, se, "a04_small@t.com", 1500, 10, 1_000_000)
		pAny := makeAssignProvider(t, ac, se, "a04_any@t.com", 1500, 0, 1_000_000)

		_, err := ac.client.ProviderOrderToken.UpdateOneID(
			getProviderPOT(t, ac.ctx, pSmall.ID).ID,
		).SetMaxOrderAmount(decimal.NewFromFloat(5)).
			SetMinOrderAmount(decimal.NewFromFloat(1)).
			Save(ac.ctx)
		require.NoError(t, err)

		order := makeAssignOrder(t, ac, se, 50, 1500)
		require.NoError(t, s.AssignPaymentOrder(ac.ctx, orderFields(order, ac.tok, "")))

		assert.Equal(t, pAny.ID, assignedProviderID(t, order.ID),
			"provider with amount outside their min/max range must be skipped")
		_ = pSmall
	})

	t.Run("rate_mismatch_skipped", func(t *testing.T) {
		se := newSubEnv(t, ac, "A05")
		pBad := makeAssignProvider(t, ac, se, "a05_bad@t.com", 2000, 10, 1_000_000)
		pGood := makeAssignProvider(t, ac, se, "a05_good@t.com", 1500, 0, 1_000_000)

		order := makeAssignOrder(t, ac, se, 10, 1500)
		require.NoError(t, s.AssignPaymentOrder(ac.ctx, orderFields(order, ac.tok, "")))

		assert.Equal(t, pGood.ID, assignedProviderID(t, order.ID),
			"provider with rate outside slippage tolerance must be skipped")
		_ = pBad
	})

	t.Run("exclude_list_regular_skips_after_max_retries", func(t *testing.T) {
		se := newSubEnv(t, ac, "A06")
		pExcl := makeAssignProvider(t, ac, se, "a06_excl@t.com", 1500, 10, 1_000_000)
		pFall := makeAssignProvider(t, ac, se, "a06_fall@t.com", 1500, 0, 1_000_000)

		order := makeAssignOrder(t, ac, se, 10, 1500)

		excludeKey := fmt.Sprintf("order_exclude_list_%s", order.ID)
		for i := 0; i < 3; i++ {
			require.NoError(t, db.RedisClient.RPush(ac.ctx, excludeKey, pExcl.ID).Err())
		}

		require.NoError(t, s.AssignPaymentOrder(ac.ctx, orderFields(order, ac.tok, "")))

		assert.Equal(t, pFall.ID, assignedProviderID(t, order.ID),
			"provider appearing 3× in exclude list must be skipped for regular order")
		_ = pExcl
	})

	t.Run("exclude_list_otc_skips_after_one_appearance", func(t *testing.T) {
		se := newSubEnv(t, ac, "A07")
		pExcl := makeAssignProvider(t, ac, se, "a07_excl@t.com", 1500, 10, 1_000_000)
		pFall := makeAssignProvider(t, ac, se, "a07_fall@t.com", 1500, 0, 1_000_000)

		order, err := ac.client.PaymentOrder.Create().
			SetAmount(decimal.NewFromFloat(200)).
			SetAmountInUsd(decimal.NewFromFloat(200)).
			SetRate(decimal.NewFromFloat(1500)).
			SetStatus(paymentorder.StatusPending).
			SetInstitution(se.instCode).
			SetAccountIdentifier("1111111111").
			SetAccountName("OTC Account").
			SetMemo("otc test").
			SetToken(ac.tok).
			SetOrderType(paymentorder.OrderTypeOtc).
			SetGatewayID(uuid.New().String()).
			SetBlockNumber(1).
			Save(ac.ctx)
		require.NoError(t, err)

		excludeKey := fmt.Sprintf("order_exclude_list_%s", order.ID)
		require.NoError(t, db.RedisClient.RPush(ac.ctx, excludeKey, pExcl.ID).Err())

		fields := orderFields(order, ac.tok, "otc")
		require.NoError(t, s.AssignPaymentOrder(ac.ctx, fields))

		got := assignedProviderID(t, order.ID)
		assert.Equal(t, pFall.ID, got,
			"OTC provider appearing once in exclude list must be skipped")
		_ = pExcl
	})

	t.Run("market_rate_snapshot_persisted_on_first_run", func(t *testing.T) {
		se := newSubEnv(t, ac, "A08")
		makeAssignProvider(t, ac, se, "a08_prov@t.com", 1500, 0, 1_000_000)
		order := makeAssignOrder(t, ac, se, 10, 1500)

		require.NoError(t, s.AssignPaymentOrder(ac.ctx, orderFields(order, ac.tok, "")))

		updated, err := ac.client.PaymentOrder.Get(ac.ctx, order.ID)
		require.NoError(t, err)
		require.NotNil(t, updated.AssignmentMarketBuyRate)
		require.NotNil(t, updated.AssignmentMarketSellRate)
		assert.Equal(t, decimal.NewFromFloat(1500).String(), updated.AssignmentMarketBuyRate.String())
		assert.Equal(t, decimal.NewFromFloat(1500).String(), updated.AssignmentMarketSellRate.String())
	})

	t.Run("market_rate_snapshot_reused_on_retry", func(t *testing.T) {
		se := newSubEnv(t, ac, "A09")
		makeAssignProvider(t, ac, se, "a09_prov@t.com", 1500, 0, 1_000_000)
		order := makeAssignOrder(t, ac, se, 10, 1500)

		require.NoError(t, s.AssignPaymentOrder(ac.ctx, orderFields(order, ac.tok, "")))

		_, err := ac.client.FiatCurrency.UpdateOneID(se.cur.ID).
			SetMarketBuyRate(decimal.NewFromFloat(9999)).
			SetMarketSellRate(decimal.NewFromFloat(9999)).
			Save(ac.ctx)
		require.NoError(t, err)

		_ = db.RedisClient.Del(ac.ctx, fmt.Sprintf("order_request_%s", order.ID))
		_, err = ac.client.PaymentOrder.UpdateOneID(order.ID).
			SetStatus(paymentorder.StatusPending).
			Save(ac.ctx)
		require.NoError(t, err)

		require.NoError(t, s.AssignPaymentOrder(ac.ctx, orderFields(order, ac.tok, "")))

		reloaded, err := ac.client.PaymentOrder.Get(ac.ctx, order.ID)
		require.NoError(t, err)
		assert.Equal(t, decimal.NewFromFloat(1500).String(),
			reloaded.AssignmentMarketBuyRate.String(),
			"snapshot must be reused from first run, not overwritten with new market rate")
	})

	t.Run("audit_run_recorded_on_successful_assignment", func(t *testing.T) {
		se := newSubEnv(t, ac, "A10")
		prov := makeAssignProvider(t, ac, se, "a10_prov@t.com", 1500, 0, 1_000_000)
		order := makeAssignOrder(t, ac, se, 10, 1500)

		require.NoError(t, s.AssignPaymentOrder(ac.ctx, orderFields(order, ac.tok, "")))

		runs, err := ac.client.ProviderAssignmentRun.Query().
			Where(providerassignmentrun.HasPaymentOrderWith(paymentorder.IDEQ(order.ID))).
			All(ac.ctx)
		require.NoError(t, err)
		require.Len(t, runs, 1, "one ProviderAssignmentRun should be created")

		run := runs[0]
		assert.Equal(t, AssignmentRunResultAssigned, run.Result)
		assert.Equal(t, AssignmentTriggerInitial, run.Trigger)
		require.NotNil(t, run.AssignedProviderID)
		assert.Equal(t, prov.ID, *run.AssignedProviderID)
	})

	t.Run("audit_run_recorded_when_no_provider_matches", func(t *testing.T) {
		se := newSubEnv(t, ac, "A11")
		prov := makeAssignProvider(t, ac, se, "a11_noprov@t.com", 1500, 0, 0)
		_, err := ac.client.ProviderBalances.Update().
			Where(providerbalances.HasProviderWith(providerprofile.IDEQ(prov.ID))).
			Where(providerbalances.HasFiatCurrencyWith(fiatcurrency.IDEQ(se.cur.ID))).
			SetAvailableBalance(decimal.Zero).
			SetIsAvailable(false).
			Save(ac.ctx)
		require.NoError(t, err)

		order := makeAssignOrder(t, ac, se, 10, 1500)
		err = s.AssignPaymentOrder(ac.ctx, orderFields(order, ac.tok, ""))
		require.Error(t, err, "should return error when no provider matches")
		assert.Contains(t, err.Error(), "no provider matched")

		runs, err := ac.client.ProviderAssignmentRun.Query().
			Where(providerassignmentrun.HasPaymentOrderWith(paymentorder.IDEQ(order.ID))).
			All(ac.ctx)
		require.NoError(t, err)
		require.Len(t, runs, 1)
		assert.Equal(t, AssignmentRunResultNoProvider, runs[0].Result)
	})

	t.Run("duplicate_assignment_skipped_when_redis_key_exists", func(t *testing.T) {
		se := newSubEnv(t, ac, "A12")
		makeAssignProvider(t, ac, se, "a12_prov@t.com", 1500, 0, 1_000_000)
		order := makeAssignOrder(t, ac, se, 10, 1500)

		orderKey := fmt.Sprintf("order_request_%s", order.ID)
		require.NoError(t, db.RedisClient.HSet(ac.ctx, orderKey, map[string]interface{}{
			"providerId":  "pre-existing-provider",
			"institution": se.instCode,
		}).Err())

		assert.NoError(t, s.AssignPaymentOrder(ac.ctx, orderFields(order, ac.tok, "")),
			"duplicate assignment must return nil, not an error")

		pid, _ := db.RedisClient.HGet(ac.ctx, orderKey, "providerId").Result()
		assert.Equal(t, "pre-existing-provider", pid,
			"pre-seeded provider must not be overwritten by duplicate assignment")
	})

	t.Run("non_pending_order_is_skipped", func(t *testing.T) {
		se := newSubEnv(t, ac, "A13")
		makeAssignProvider(t, ac, se, "a13_prov@t.com", 1500, 0, 1_000_000)

		order, err := ac.client.PaymentOrder.Create().
			SetAmount(decimal.NewFromFloat(10)).
			SetAmountInUsd(decimal.NewFromFloat(10)).
			SetRate(decimal.NewFromFloat(1500)).
			SetStatus(paymentorder.StatusFulfilled).
			SetInstitution(se.instCode).
			SetAccountIdentifier("5555555555").
			SetAccountName("Fulfilled Account").
			SetMemo("fulfilled test").
			SetToken(ac.tok).
			SetGatewayID(uuid.New().String()).
			SetBlockNumber(1).
			Save(ac.ctx)
		require.NoError(t, err)

		assert.NoError(t, s.AssignPaymentOrder(ac.ctx, orderFields(order, ac.tok, "")),
			"assignment of non-pending order must return nil")

		orderKey := fmt.Sprintf("order_request_%s", order.ID)
		exists, _ := db.RedisClient.Exists(ac.ctx, orderKey).Result()
		assert.Equal(t, int64(0), exists,
			"no order_request key must be created for a non-pending order")
	})

	t.Run("last_order_assigned_at_updated_after_assignment", func(t *testing.T) {
		se := newSubEnv(t, ac, "A14")
		prov := makeAssignProvider(t, ac, se, "a14_prov@t.com", 1500, 0, 1_000_000)
		pot := getProviderPOT(t, ac.ctx, prov.ID)
		assert.Nil(t, pot.LastOrderAssignedAt,
			"last_order_assigned_at must be nil before any assignment")

		beforeAssign := time.Now()
		order := makeAssignOrder(t, ac, se, 10, 1500)
		require.NoError(t, s.AssignPaymentOrder(ac.ctx, orderFields(order, ac.tok, "")))

		pot2, err := ac.client.ProviderOrderToken.Get(ac.ctx, pot.ID)
		require.NoError(t, err)
		require.NotNil(t, pot2.LastOrderAssignedAt)
		assert.True(t, !pot2.LastOrderAssignedAt.Before(beforeAssign))
	})

	t.Run("round_robin_via_last_assigned_at", func(t *testing.T) {
		se := newSubEnv(t, ac, "A15")
		pOld := makeAssignProvider(t, ac, se, "a15_old@t.com", 1500, 0, 1_000_000)
		pNew := makeAssignProvider(t, ac, se, "a15_new@t.com", 1500, 0, 1_000_000)

		oldPot := getProviderPOT(t, ac.ctx, pOld.ID)
		newPot := getProviderPOT(t, ac.ctx, pNew.ID)

		_, err := ac.client.ProviderOrderToken.UpdateOneID(oldPot.ID).
			SetLastOrderAssignedAt(time.Now().Add(-2 * time.Hour)).
			Save(ac.ctx)
		require.NoError(t, err)
		_, err = ac.client.ProviderOrderToken.UpdateOneID(newPot.ID).
			SetLastOrderAssignedAt(time.Now().Add(-1 * time.Second)).
			Save(ac.ctx)
		require.NoError(t, err)

		order := makeAssignOrder(t, ac, se, 10, 1500)
		require.NoError(t, s.AssignPaymentOrder(ac.ctx, orderFields(order, ac.tok, "")))

		assert.Equal(t, pOld.ID, assignedProviderID(t, order.ID),
			"provider with the oldest last_order_assigned_at should be selected (round-robin)")
		_ = pNew
	})
}
