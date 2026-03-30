package assignment

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	tokenEnt "github.com/paycrest/aggregator/ent/token"
	userEnt "github.com/paycrest/aggregator/ent/user"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils/test"
	"github.com/redis/go-redis/v9"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/mattn/go-sqlite3"
)

// newTestDB opens a fresh named in-memory SQLite database, wires it into the
// global storage singletons, and registers cleanup via t.Cleanup. Each call
// must use a unique name to avoid cross-test contamination.
func newTestDB(t *testing.T, name string) {
	t.Helper()

	prevClient := db.Client
	prevDB := db.DB
	prevRedis := db.RedisClient

	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared&_fk=1&_busy_timeout=5000", name)
	dbConn, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	dbConn.SetMaxOpenConns(2)

	drv := entsql.OpenDB(dialect.SQLite, dbConn)
	client := ent.NewClient(ent.Driver(drv))
	require.NoError(t, client.Schema.Create(context.Background()))

	mr, err := miniredis.Run()
	require.NoError(t, err)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	db.Client = client
	db.DB = dbConn
	db.RedisClient = rdb

	t.Cleanup(func() {
		_ = rdb.Close()
		mr.Close()
		_ = client.Close()
		_ = dbConn.Close()
		db.Client = prevClient
		db.DB = prevDB
		db.RedisClient = prevRedis
	})
}

// TestIsProviderFaultCancelReason validates the prefix-based allow-list check.
func TestIsProviderFaultCancelReason(t *testing.T) {
	cases := []struct {
		reason string
		want   bool
		desc   string
	}{
		// ── PSP-generated: exact base string ───────────────────────────────────
		{"Amount exceeds maximum allowed", true, "PSP: exact base phrase"},
		{"Amount is less than minimum allowed", true, "PSP: exact base phrase"},
		{"Invalid amount", true, "PSP: exact base phrase"},
		{"Unsupported channel", true, "PSP: exact base phrase"},
		{"Payment failed", true, "PSP: Transfero exact phrase"},

		// ── PSP-generated: base phrase with appended context (prefix match) ────
		{"Amount exceeds maximum allowed (GHS 5000)", true, "PSP: BoltPay with currency suffix"},
		{"Amount exceeds maximum allowed (NGN 10000)", true, "PSP: hypothetical currency suffix"},
		{"Amount is less than minimum allowed (GHS 10)", true, "PSP: BoltPay min with suffix"},
		{"Unsupported channel type", true, "PSP: BoltPay 'unsupported channel type' starts with 'Unsupported channel'"},

		// ── Case-insensitive variants ───────────────────────────────────────────
		{"amount exceeds maximum allowed", true, "lowercase PSP phrase"},
		{"PAYMENT FAILED", true, "uppercase PSP phrase"},

		// ── Whitespace tolerance ────────────────────────────────────────────────
		{"  Amount exceeds maximum allowed  ", true, "PSP phrase with whitespace"},

		// ── NOT provider fault: should NOT match ───────────────────────────────
		{"Insufficient funds", false, "handled by separate penalty, not in this list"},
		{"Gateway timeout", false, "external infrastructure, not provider fault"},
		{"Transaction failed", false, "ambiguous catch-all, not provider fault"},
		{"Disbursement failed", false, "generic catch-all, not provider fault"},
		{"Order processing incomplete", false, "system error, not provider fault"},
		{"Transaction data not found", false, "PSP response bug, not provider fault"},
		{"Invalid transfer response", false, "PSP response bug, not provider fault"},
		{"Invalid recipient bank details", false, "customer data issue, handled separately"},
		{"Network error", false, "external infrastructure"},

		// ── Empty / blank ───────────────────────────────────────────────────────
		{"", false, "empty string"},
		{"   ", false, "whitespace-only string"},
	}

	for _, tc := range cases {
		got := IsProviderFaultCancelReason(tc.reason)
		assert.Equal(t, tc.want, got, "[%s] reason=%q", tc.desc, tc.reason)
	}
}

// scoringCtx holds the shared DB fixtures used across TestProviderScoring subtests.
type scoringCtx struct {
	ctx      context.Context
	client   *ent.Client
	currency *ent.FiatCurrency
	tok      *ent.Token // loaded with WithNetwork()
}

// newScoringCtx creates the shared network/token/currency fixtures for scoring tests.
func newScoringCtx(t *testing.T) scoringCtx {
	t.Helper()
	ctx := context.Background()
	client := db.Client

	netw, err := client.Network.Create().
		SetIdentifier("score-net").
		SetChainID(56).
		SetRPCEndpoint("ws://localhost:8545").
		SetBlockTime(decimal.NewFromFloat(3)).
		SetFee(decimal.NewFromFloat(0.1)).
		SetIsTestnet(true).
		Save(ctx)
	require.NoError(t, err)

	tok, err := client.Token.Create().
		SetSymbol("SCRTOK").
		SetContractAddress("0x1111111111111111111111111111111111111111").
		SetDecimals(6).
		SetNetworkID(netw.ID).
		SetIsEnabled(true).
		SetBaseCurrency("NGN").
		Save(ctx)
	require.NoError(t, err)
	tok, err = client.Token.Query().Where(tokenEnt.IDEQ(tok.ID)).WithNetwork().Only(ctx)
	require.NoError(t, err)

	cur, err := test.CreateTestFiatCurrency(map[string]interface{}{
		"code": "NGN", "short_name": "Naira", "decimals": 2,
		"symbol": "₦", "name": "Nigerian Naira", "market_rate": 1500.0,
	})
	require.NoError(t, err)
	_, err = client.FiatCurrency.UpdateOneID(cur.ID).
		SetMarketBuyRate(decimal.NewFromFloat(1500)).
		SetMarketSellRate(decimal.NewFromFloat(1500)).
		Save(ctx)
	require.NoError(t, err)

	return scoringCtx{ctx: ctx, client: client, currency: cur, tok: tok}
}

// makeScoringProvider creates a public+active provider and a matching POT.
func makeScoringProvider(t *testing.T, sc scoringCtx, email, visibility string) (*ent.ProviderProfile, *ent.ProviderOrderToken) {
	t.Helper()
	ctx := sc.ctx
	client := sc.client

	u, err := test.CreateTestUser(map[string]interface{}{"scope": "provider", "email": email})
	require.NoError(t, err)

	prov, err := test.CreateTestProviderProfile(map[string]interface{}{
		"user_id":         u.ID,
		"currency_id":     sc.currency.ID,
		"visibility_mode": visibility,
	})
	require.NoError(t, err)

	_, err = client.ProviderProfile.UpdateOneID(prov.ID).SetIsActive(true).Save(ctx)
	require.NoError(t, err)
	_, err = client.User.UpdateOneID(u.ID).
		SetKybVerificationStatus(userEnt.KybVerificationStatusApproved).
		Save(ctx)
	require.NoError(t, err)

	pot, err := test.AddProviderOrderTokenToProvider(map[string]interface{}{
		"provider":         prov,
		"currency_id":      sc.currency.ID,
		"token_id":         sc.tok.ID,
		"network":          sc.tok.Edges.Network.Identifier,
		"fixed_sell_rate":  decimal.NewFromFloat(1500),
		"max_order_amount": decimal.NewFromFloat(10000),
		"min_order_amount": decimal.NewFromFloat(1),
	})
	require.NoError(t, err)

	return prov, pot
}

// makeScoringOrder creates a payment order assigned to the given provider.
func makeScoringOrder(t *testing.T, sc scoringCtx, prov *ent.ProviderProfile) *ent.PaymentOrder {
	t.Helper()
	order, err := sc.client.PaymentOrder.Create().
		SetAmount(decimal.NewFromFloat(10)).
		SetAmountInUsd(decimal.NewFromFloat(10)).
		SetRate(decimal.NewFromFloat(1500)).
		SetStatus(paymentorder.StatusFulfilled).
		SetInstitution("ABNGNGLA").
		SetAccountIdentifier("0000000001").
		SetAccountName("Scorer Account").
		SetMemo("scoring test").
		SetToken(sc.tok).
		SetGatewayID(uuid.New().String()).
		SetBlockNumber(1).
		SetProvider(prov).
		Save(sc.ctx)
	require.NoError(t, err)
	return order
}

// TestProviderScoring tests the ApplyProviderScoreChange logic end-to-end.
func TestProviderScoring(t *testing.T) {
	newTestDB(t, "scoring_tests")
	sc := newScoringCtx(t)

	t.Run("applies_delta_and_creates_history", func(t *testing.T) {
		prov, pot := makeScoringProvider(t, sc, "score_apply@test.com", "public")
		order := makeScoringOrder(t, sc, prov)

		err := ApplyProviderScoreChange(sc.ctx, order.ID, ScoreEventFulfilledValidated, decimal.NewFromFloat(RewardFulfilledValidated))
		require.NoError(t, err)

		updated, err := sc.client.ProviderOrderToken.Get(sc.ctx, pot.ID)
		require.NoError(t, err)
		assert.Equal(t, decimal.NewFromFloat(1.0).String(), updated.ScoreOfframp.String())

		count, err := sc.client.ProviderOrderTokenScoreHistory.Query().Count(sc.ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, count, "one history row should be created")
	})

	t.Run("onramp_updates_score_onramp_not_offramp", func(t *testing.T) {
		prov, pot := makeScoringProvider(t, sc, "score_onramp_only@test.com", "public")
		order, err := sc.client.PaymentOrder.Create().
			SetAmount(decimal.NewFromFloat(10)).
			SetAmountInUsd(decimal.NewFromFloat(10)).
			SetRate(decimal.NewFromFloat(1500)).
			SetStatus(paymentorder.StatusFulfilled).
			SetInstitution("ABNGNGLA").
			SetAccountIdentifier("0000000001").
			SetAccountName("Scorer Account").
			SetMemo("scoring test").
			SetToken(sc.tok).
			SetGatewayID(uuid.New().String()).
			SetBlockNumber(1).
			SetProvider(prov).
			SetDirection(paymentorder.DirectionOnramp).
			Save(sc.ctx)
		require.NoError(t, err)

		err = ApplyProviderScoreChange(sc.ctx, order.ID, ScoreEventFulfilledValidated, decimal.NewFromFloat(RewardFulfilledValidated))
		require.NoError(t, err)

		updated, err := sc.client.ProviderOrderToken.Get(sc.ctx, pot.ID)
		require.NoError(t, err)
		assert.Equal(t, decimal.NewFromFloat(1.0).String(), updated.ScoreOnramp.String())
		assert.Equal(t, decimal.Zero.String(), updated.ScoreOfframp.String())
	})

	t.Run("idempotent_same_event", func(t *testing.T) {
		prov, pot := makeScoringProvider(t, sc, "score_idem@test.com", "public")
		order := makeScoringOrder(t, sc, prov)

		delta := decimal.NewFromFloat(1.0)
		event := ScoreEventFulfilledValidated

		require.NoError(t, ApplyProviderScoreChange(sc.ctx, order.ID, event, delta))

		updated1, err := sc.client.ProviderOrderToken.Get(sc.ctx, pot.ID)
		require.NoError(t, err)
		scoreAfterFirst := updated1.ScoreOfframp

		require.NoError(t, ApplyProviderScoreChange(sc.ctx, order.ID, event, delta))

		updated2, err := sc.client.ProviderOrderToken.Get(sc.ctx, pot.ID)
		require.NoError(t, err)
		assert.Equal(t, scoreAfterFirst.String(), updated2.ScoreOfframp.String(),
			"score must not change on duplicate event")
	})

	t.Run("different_event_types_both_applied", func(t *testing.T) {
		prov, pot := makeScoringProvider(t, sc, "score_multi@test.com", "public")
		order := makeScoringOrder(t, sc, prov)

		require.NoError(t, ApplyProviderScoreChange(sc.ctx, order.ID, ScoreEventFulfilledValidated, decimal.NewFromFloat(1.0)))
		require.NoError(t, ApplyProviderScoreChange(sc.ctx, order.ID, ScoreEventValidationFailed, decimal.NewFromFloat(-2.0)))

		pot2, err := sc.client.ProviderOrderToken.Get(sc.ctx, pot.ID)
		require.NoError(t, err)
		assert.Equal(t, decimal.NewFromFloat(-1.0).String(), pot2.ScoreOfframp.String())
	})

	t.Run("skips_private_provider", func(t *testing.T) {
		prov, pot := makeScoringProvider(t, sc, "score_priv@test.com", "private")
		order := makeScoringOrder(t, sc, prov)

		err := ApplyProviderScoreChange(sc.ctx, order.ID, ScoreEventFulfilledValidated, decimal.NewFromFloat(1.0))
		require.NoError(t, err)

		unchanged, err := sc.client.ProviderOrderToken.Get(sc.ctx, pot.ID)
		require.NoError(t, err)
		assert.Equal(t, decimal.Zero.String(), unchanged.ScoreOnramp.String(),
			"private provider score_onramp must not change")
		assert.Equal(t, decimal.Zero.String(), unchanged.ScoreOfframp.String(),
			"private provider score_offramp must not change")
	})

	t.Run("skips_order_with_no_assigned_provider", func(t *testing.T) {
		order, err := sc.client.PaymentOrder.Create().
			SetAmount(decimal.NewFromFloat(5)).
			SetAmountInUsd(decimal.NewFromFloat(5)).
			SetRate(decimal.NewFromFloat(1500)).
			SetStatus(paymentorder.StatusPending).
			SetInstitution("ABNGNGLA").
			SetAccountIdentifier("0000000002").
			SetAccountName("No Provider").
			SetMemo("no provider test").
			SetToken(sc.tok).
			SetGatewayID(uuid.New().String()).
			SetBlockNumber(1).
			Save(sc.ctx)
		require.NoError(t, err)

		err = ApplyProviderScoreChange(sc.ctx, order.ID, ScoreEventFulfilledValidated, decimal.NewFromFloat(1.0))
		assert.NoError(t, err)
	})

	t.Run("skips_nonexistent_order", func(t *testing.T) {
		fakeID := uuid.New()
		err := ApplyProviderScoreChange(sc.ctx, fakeID, ScoreEventFulfilledValidated, decimal.NewFromFloat(1.0))
		assert.NoError(t, err, "missing order must return nil, not an error")
	})

	t.Run("penalty_cancel_insufficient_funds", func(t *testing.T) {
		prov, pot := makeScoringProvider(t, sc, "score_insuf@test.com", "public")
		order := makeScoringOrder(t, sc, prov)

		err := ApplyProviderScoreChange(sc.ctx, order.ID,
			ScoreEventCancelInsufficientFunds,
			decimal.NewFromFloat(PenaltyCancelInsufficientFunds))
		require.NoError(t, err)

		updated, err := sc.client.ProviderOrderToken.Get(sc.ctx, pot.ID)
		require.NoError(t, err)
		assert.Equal(t, decimal.NewFromFloat(PenaltyCancelInsufficientFunds).String(), updated.ScoreOfframp.String())
	})

	t.Run("penalty_provider_fault_cancel", func(t *testing.T) {
		prov, pot := makeScoringProvider(t, sc, "score_fault@test.com", "public")
		order := makeScoringOrder(t, sc, prov)

		err := ApplyProviderScoreChange(sc.ctx, order.ID,
			ScoreEventCancelProviderFault,
			decimal.NewFromFloat(PenaltyCancelProviderFault))
		require.NoError(t, err)

		updated, err := sc.client.ProviderOrderToken.Get(sc.ctx, pot.ID)
		require.NoError(t, err)
		assert.Equal(t, decimal.NewFromFloat(PenaltyCancelProviderFault).String(), updated.ScoreOfframp.String())
	})

	t.Run("apply_for_specific_provider_by_id", func(t *testing.T) {
		prov, pot := makeScoringProvider(t, sc, "score_byprovid@test.com", "public")
		order := makeScoringOrder(t, sc, prov)

		err := ApplyProviderScoreChangeForProvider(sc.ctx, order.ID, prov.ID,
			ScoreEventOrderRequestExpired,
			decimal.NewFromFloat(PenaltyOrderRequestExpired))
		require.NoError(t, err)

		updated, err := sc.client.ProviderOrderToken.Get(sc.ctx, pot.ID)
		require.NoError(t, err)
		assert.Equal(t, decimal.NewFromFloat(PenaltyOrderRequestExpired).String(), updated.ScoreOfframp.String())
	})

	t.Run("apply_for_specific_provider_idempotent", func(t *testing.T) {
		prov, pot := makeScoringProvider(t, sc, "score_byprovid_idem@test.com", "public")
		order := makeScoringOrder(t, sc, prov)

		require.NoError(t, ApplyProviderScoreChangeForProvider(sc.ctx, order.ID, prov.ID,
			ScoreEventOrderRequestExpired, decimal.NewFromFloat(-0.5)))
		require.NoError(t, ApplyProviderScoreChangeForProvider(sc.ctx, order.ID, prov.ID,
			ScoreEventOrderRequestExpired, decimal.NewFromFloat(-0.5)))

		updated, err := sc.client.ProviderOrderToken.Get(sc.ctx, pot.ID)
		require.NoError(t, err)
		assert.Equal(t, decimal.NewFromFloat(-0.5).String(), updated.ScoreOfframp.String())
	})

	t.Run("skips_empty_provider_id_for_specific_provider", func(t *testing.T) {
		order := makeScoringOrder(t, sc, func() *ent.ProviderProfile {
			prov, _ := makeScoringProvider(t, sc, "score_emptyid@test.com", "public")
			return prov
		}())
		err := ApplyProviderScoreChangeForProvider(sc.ctx, order.ID, "", ScoreEventFulfilledValidated, decimal.NewFromFloat(1.0))
		assert.NoError(t, err)
	})
}

func getProviderPOT(t *testing.T, ctx context.Context, provID string) *ent.ProviderOrderToken {
	t.Helper()
	pot, err := db.Client.ProviderOrderToken.Query().
		Where(providerordertoken.HasProviderWith(providerprofile.IDEQ(provID))).
		Only(ctx)
	require.NoError(t, err)
	return pot
}
