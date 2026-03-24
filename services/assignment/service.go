package assignment

import (
	"context"

	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/services/balance"
	"github.com/shopspring/decimal"
)

// RateSide represents the direction of the rate (buy for onramp, sell for offramp).
type RateSide string

const (
	RateSideBuy  RateSide = "buy"  // Onramp: fiat per 1 token the sender pays to buy crypto
	RateSideSell RateSide = "sell" // Offramp: fiat per 1 token the sender receives when selling crypto
)

// Service coordinates provider assignment, selection, and scoring.
type Service struct {
	balanceService *balance.Service
}

// New creates a new assignment Service.
func New() *Service {
	return &Service{
		balanceService: balance.New(),
	}
}

// GetProviderRate returns the effective rate for a provider based on side (buy or sell).
func (s *Service) GetProviderRate(ctx context.Context, provider *ent.ProviderProfile, tokenSymbol string, currency string, side RateSide) (decimal.Decimal, error) {
	tokenConfig, err := provider.QueryOrderTokens().
		Where(
			providerordertoken.HasProviderWith(providerprofile.IDEQ(provider.ID)),
			providerordertoken.HasTokenWith(token.SymbolEQ(tokenSymbol)),
			providerordertoken.HasCurrencyWith(fiatcurrency.CodeEQ(currency)),
		).
		WithProvider().
		WithCurrency().
		First(ctx)
	if err != nil {
		return decimal.Decimal{}, err
	}

	var rate decimal.Decimal
	switch side {
	case RateSideBuy:
		if !tokenConfig.FixedBuyRate.IsZero() {
			rate = tokenConfig.FixedBuyRate
		} else if !tokenConfig.Edges.Currency.MarketBuyRate.IsZero() {
			rate = tokenConfig.Edges.Currency.MarketBuyRate.Add(tokenConfig.FloatingBuyDelta).RoundBank(2)
		}
	case RateSideSell:
		if !tokenConfig.FixedSellRate.IsZero() {
			rate = tokenConfig.FixedSellRate
		} else if !tokenConfig.Edges.Currency.MarketSellRate.IsZero() {
			rate = tokenConfig.Edges.Currency.MarketSellRate.Add(tokenConfig.FloatingSellDelta).RoundBank(2)
		}
	}

	return rate, nil
}
