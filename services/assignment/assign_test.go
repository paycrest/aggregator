package assignment

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/alicebob/miniredis/v2"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerbalances"
	"github.com/paycrest/aggregator/ent/providerprofile"
	tokenEnt "github.com/paycrest/aggregator/ent/token"
	userEnt "github.com/paycrest/aggregator/ent/user"
	svc "github.com/paycrest/aggregator/services"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils/test"
	"github.com/redis/go-redis/v9"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssignPaymentOrder_DBOnlyPublicProvider(t *testing.T) {
	dbConn, err := sql.Open("sqlite3", "file:ent_pq?mode=memory&cache=shared&_fk=1&_busy_timeout=5000")
	require.NoError(t, err)
	dbConn.SetMaxOpenConns(2)
	t.Cleanup(func() { _ = dbConn.Close() })

	drv := entsql.OpenDB(dialect.SQLite, dbConn)
	client := ent.NewClient(ent.Driver(drv))
	t.Cleanup(func() { _ = client.Close() })

	db.Client = client
	db.DB = dbConn
	require.NoError(t, client.Schema.Create(context.Background()))

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	db.RedisClient = rdb

	ctx := context.Background()

	netw, err := client.Network.Create().
		SetIdentifier("localhost").
		SetChainID(56).
		SetRPCEndpoint("ws://localhost:8545").
		SetBlockTime(decimal.NewFromFloat(3)).
		SetFee(decimal.NewFromFloat(0.1)).
		SetIsTestnet(true).
		Save(ctx)
	require.NoError(t, err)
	networkID := netw.ID

	tok, err := client.Token.Create().
		SetSymbol("TST").
		SetContractAddress("0xd4E96eF8eee8678dBFf4d535E033Ed1a4F7605b7").
		SetDecimals(6).
		SetNetworkID(networkID).
		SetIsEnabled(true).
		SetBaseCurrency("KES").
		Save(ctx)
	require.NoError(t, err)
	tok, err = client.Token.Query().Where(tokenEnt.IDEQ(tok.ID)).WithNetwork().Only(ctx)
	require.NoError(t, err)

	cur, err := test.CreateTestFiatCurrency(map[string]interface{}{
		"code": "KES", "short_name": "Shilling", "decimals": 2, "symbol": "KSh",
		"name": "Kenyan Shilling", "market_rate": 550.0,
	})
	require.NoError(t, err)

	_, err = client.FiatCurrency.UpdateOneID(cur.ID).
		SetMarketBuyRate(decimal.NewFromFloat(550)).
		SetMarketSellRate(decimal.NewFromFloat(550)).
		Save(ctx)
	require.NoError(t, err)

	_, err = client.Institution.Create().
		SetCode("PQTESTBANK").
		SetName("PQ Test Bank").
		SetFiatCurrencyID(cur.ID).
		Save(ctx)
	require.NoError(t, err)

	u, err := test.CreateTestUser(map[string]interface{}{"scope": "provider", "email": "pqpub@test.com"})
	require.NoError(t, err)
	prov, err := test.CreateTestProviderProfile(map[string]interface{}{
		"user_id": u.ID, "currency_id": cur.ID, "host_identifier": "https://example.com",
	})
	require.NoError(t, err)
	_, err = client.ProviderProfile.UpdateOneID(prov.ID).SetIsActive(true).Save(ctx)
	require.NoError(t, err)
	_, err = client.User.UpdateOneID(u.ID).SetKybVerificationStatus(userEnt.KybVerificationStatusApproved).Save(ctx)
	require.NoError(t, err)

	apiKeySvc := svc.NewAPIKeyService()
	_, _, err = apiKeySvc.GenerateAPIKey(ctx, nil, nil, prov)
	require.NoError(t, err)

	_, err = test.AddProviderOrderTokenToProvider(map[string]interface{}{
		"provider":         prov,
		"currency_id":      cur.ID,
		"token_id":         tok.ID,
		"network":          tok.Edges.Network.Identifier,
		"fixed_buy_rate":   decimal.NewFromFloat(100),
		"fixed_sell_rate":  decimal.NewFromFloat(100),
		"max_order_amount": decimal.NewFromFloat(10000),
		"min_order_amount": decimal.NewFromFloat(1),
	})
	require.NoError(t, err)

	_, err = client.ProviderBalances.Update().
		Where(providerbalances.HasProviderWith(providerprofile.IDEQ(prov.ID))).
		Where(providerbalances.HasFiatCurrencyWith(fiatcurrency.IDEQ(cur.ID))).
		SetAvailableBalance(decimal.NewFromFloat(1_000_000)).
		SetTotalBalance(decimal.NewFromFloat(1_000_000)).
		SetIsAvailable(true).
		Save(ctx)
	require.NoError(t, err)

	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","message":"ok"}`))
	}))
	t.Cleanup(mockSrv.Close)
	_, err = client.ProviderProfile.Update().SetHostIdentifier(mockSrv.URL).Save(ctx)
	require.NoError(t, err)

	order, err := client.PaymentOrder.Create().
		SetAmount(decimal.NewFromFloat(100.5)).
		SetAmountInUsd(decimal.NewFromFloat(100.5)).
		SetRate(decimal.NewFromFloat(100)).
		SetStatus(paymentorder.StatusPending).
		SetInstitution("PQTESTBANK").
		SetAccountIdentifier("1234567890").
		SetAccountName("Test Account").
		SetMemo("pq test").
		SetToken(tok).
		SetGatewayID("gw-pq-dbonly-1").
		SetBlockNumber(1).
		Save(ctx)
	require.NoError(t, err)

	s := New()

	fields := types.PaymentOrderFields{
		ID:                order.ID,
		OrderType:         string(paymentorder.OrderTypeRegular),
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

	require.NoError(t, s.AssignPaymentOrder(ctx, fields))

	key := "order_request_" + order.ID.String()
	n, err := rdb.Exists(ctx, key).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
	pid, err := rdb.HGet(ctx, key, "providerId").Result()
	require.NoError(t, err)
	assert.Equal(t, prov.ID, pid)
}
