package services

import (
	"context"
	"fmt"
	"time"

	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/shopspring/decimal"
)

func resolveInstitutionCurrency(ctx context.Context, institutionCode string) (*ent.FiatCurrency, error) {
	institution, err := utils.GetInstitutionByCode(ctx, institutionCode, true)
	if err != nil {
		return nil, err
	}
	if institution == nil || institution.Edges.FiatCurrency == nil {
		return nil, fmt.Errorf("institution %s has no fiat currency", institutionCode)
	}
	return institution.Edges.FiatCurrency, nil
}

func resolveOrderCurrency(ctx context.Context, order *ent.PaymentOrder) (*ent.FiatCurrency, error) {
	if order == nil {
		return nil, fmt.Errorf("payment order is nil")
	}
	return resolveInstitutionCurrency(ctx, order.Institution)
}

func resolveOrderFieldsCurrency(ctx context.Context, order types.PaymentOrderFields) (*ent.FiatCurrency, error) {
	return resolveInstitutionCurrency(ctx, order.Institution)
}

func getRecentSuccessfulFiatVolumeByProvider(ctx context.Context, providerIDs []string) (map[string]decimal.Decimal, error) {
	volumes := make(map[string]decimal.Decimal, len(providerIDs))
	if len(providerIDs) == 0 {
		return volumes, nil
	}
	since := time.Now().Add(-RecentProcessedVolumeWindow)
	orders, err := storage.Client.PaymentOrder.Query().
		Where(
			paymentorder.HasProviderWith(providerprofile.IDIn(providerIDs...)),
			paymentorder.UpdatedAtGTE(since),
			paymentorder.StatusIn(paymentorder.StatusValidated, paymentorder.StatusSettled),
		).
		WithProvider().
		All(ctx)
	if err != nil {
		return nil, err
	}
	for _, order := range orders {
		if order.Edges.Provider == nil {
			continue
		}
		volumes[order.Edges.Provider.ID] = volumes[order.Edges.Provider.ID].Add(order.Amount.Mul(order.Rate))
	}
	return volumes, nil
}
