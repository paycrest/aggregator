package services

import (
	"context"
	"testing"

	"database/sql"
	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/mattn/go-sqlite3"
	"github.com/paycrest/aggregator/ent"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

func setupCurrencyResolutionTestDB(t *testing.T) context.Context {
	t.Helper()

	dbConn, err := sql.Open("sqlite3", "file:currency_resolution?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	t.Cleanup(func() { _ = dbConn.Close() })

	drv := entsql.OpenDB(dialect.SQLite, dbConn)
	client := ent.NewClient(ent.Driver(drv))
	t.Cleanup(func() { _ = client.Close() })

	db.Client = client
	require.NoError(t, client.Schema.Create(context.Background()))

	ctx := context.Background()

	kes, err := client.FiatCurrency.Create().
		SetCode("KES").
		SetShortName("Kenyan Shilling").
		SetDecimals(2).
		SetSymbol("KSh").
		SetName("Kenyan Shilling").
		SetIsEnabled(true).
		Save(ctx)
	require.NoError(t, err)

	ngn, err := client.FiatCurrency.Create().
		SetCode("NGN").
		SetShortName("Naira").
		SetDecimals(2).
		SetSymbol("₦").
		SetName("Nigerian Naira").
		SetIsEnabled(true).
		Save(ctx)
	require.NoError(t, err)

	_, err = client.Institution.Create().
		SetCode("MPESAKES").
		SetName("M-Pesa Kenya").
		SetType("mobile_money").
		SetFiatCurrency(kes).
		Save(ctx)
	require.NoError(t, err)

	bucket, err := client.ProvisionBucket.Create().
		SetMinAmount(decimal.NewFromInt(1)).
		SetMaxAmount(decimal.NewFromInt(1000)).
		SetCurrency(ngn).
		Save(ctx)
	require.NoError(t, err)

	return ctx
}

func getTestBucket(t *testing.T, ctx context.Context) *ent.ProvisionBucket {
	t.Helper()
	bucket, err := db.Client.ProvisionBucket.Query().WithCurrency().Only(ctx)
	require.NoError(t, err)
	return bucket
}

func TestResolveOrderCurrencyPrefersInstitutionCurrency(t *testing.T) {
	ctx := setupCurrencyResolutionTestDB(t)
	bucket := getTestBucket(t, ctx)

	currency, err := resolveOrderCurrency(ctx, &ent.PaymentOrder{
		Institution: "MPESAKES",
		Edges: ent.PaymentOrderEdges{
			ProvisionBucket: bucket,
		},
	})
	require.NoError(t, err)
	require.Equal(t, "KES", currency.Code)
}

func TestResolveOrderFieldsCurrencyPrefersInstitutionCurrency(t *testing.T) {
	ctx := setupCurrencyResolutionTestDB(t)
	bucket := getTestBucket(t, ctx)

	currency, err := resolveOrderFieldsCurrency(ctx, types.PaymentOrderFields{
		Institution:     "MPESAKES",
		ProvisionBucket: bucket,
	})
	require.NoError(t, err)
	require.Equal(t, "KES", currency.Code)
}
