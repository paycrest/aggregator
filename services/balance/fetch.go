package balance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	blockchainUtils "github.com/paycrest/aggregator/utils/blockchain"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

// FetchProviderFiatBalances fetches fiat balances from the provider /info endpoint.
// It returns currencyCode -> ProviderBalance (ReservedBalance is always 0 in provider reports).
//
// NOTE: This method also best-effort syncs ProviderOrderToken.payout_address from the provider's
// ServiceInfo.walletAddress (if present), matching existing behavior in the cron task.
func (svc *Service) FetchProviderFiatBalances(ctx context.Context, providerID string) (map[string]*types.ProviderBalance, error) {
	// Get provider with host identifier
	provider, err := svc.client.ProviderProfile.
		Query().
		Where(providerprofile.IDEQ(providerID)).
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	// Check if provider has host identifier
	if provider.HostIdentifier == "" {
		return nil, fmt.Errorf("provider %s has no host identifier", providerID)
	}

	// Call provider /info endpoint without HMAC (endpoint doesn't require authentication)
	res, err := fastshot.NewClient(provider.HostIdentifier).
		Config().SetTimeout(30 * time.Second).
		Build().GET("/info").
		Send()
	if err != nil {
		return nil, fmt.Errorf("failed to call provider /info endpoint: %v", err)
	}

	// Parse JSON response
	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Parse the response data into ProviderInfoResponse using proper JSON unmarshaling
	responseBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %v", err)
	}

	var response types.ProviderInfoResponse
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response data: %v", err)
	}

	// Convert response to ProviderBalance map
	balances := make(map[string]*types.ProviderBalance)

	// Use totalBalances from response
	for currency, balanceData := range response.Data.TotalBalances {
		availableBalance, err := decimal.NewFromString(balanceData.AvailableBalance)
		if err != nil {
			logger.Warnf("Failed to parse available balance for %s: %v", currency, err)
			continue
		}
		if availableBalance.IsNegative() {
			logger.Errorf("Negative available balance for %s: %v", currency, availableBalance)
			continue
		}

		totalBalance, err := decimal.NewFromString(balanceData.TotalBalance)
		if err != nil {
			logger.Warnf("Failed to parse total balance for %s: %v", currency, err)
			continue
		}
		if totalBalance.IsNegative() {
			logger.Errorf("Negative total balance for %s: %v", currency, totalBalance)
			continue
		}

		balances[currency] = &types.ProviderBalance{
			AvailableBalance: availableBalance,
			TotalBalance:     totalBalance,
			ReservedBalance:  decimal.Zero, // Provider doesn't track reserved balance
			LastUpdated:      time.Now(),
		}
	}

	// Sync payout_address from provider's walletAddress to all ProviderOrderToken records (best effort)
	if walletAddress := response.Data.ServiceInfo.WalletAddress; walletAddress != "" {
		_, err := svc.client.ProviderOrderToken.
			Update().
			Where(providerordertoken.HasProviderWith(providerprofile.IDEQ(providerID))).
			SetPayoutAddress(walletAddress).
			Save(ctx)
		if err != nil {
			logger.Warnf("Failed to sync payout_address for provider %s: %v", providerID, err)
			// Don't return error - non-critical update
		} else {
			logger.Debugf("Synced payout_address for provider %s: %s", providerID, walletAddress)
		}
	}

	return balances, nil
}

// FetchProviderTokenBalances fetches on-chain token balances for a provider's ProviderOrderToken payout addresses.
// It aggregates balances by token ID (summing across multiple payout addresses for the same token).
func (svc *Service) FetchProviderTokenBalances(ctx context.Context, providerID string) (map[int]*types.ProviderBalance, error) {
	pots, err := svc.client.ProviderOrderToken.Query().
		Where(
			providerordertoken.HasProviderWith(providerprofile.IDEQ(providerID)),
			providerordertoken.PayoutAddressNEQ(""),
		).
		WithToken(func(q *ent.TokenQuery) { q.WithNetwork() }).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query provider order tokens: %w", err)
	}

	balances := make(map[int]*types.ProviderBalance)
	for _, pot := range pots {
		tok := pot.Edges.Token
		if tok == nil || tok.Edges.Network == nil {
			continue
		}
		rpcEndpoint := tok.Edges.Network.RPCEndpoint
		if rpcEndpoint == "" {
			continue
		}
		raw, err := blockchainUtils.GetTokenBalance(rpcEndpoint, tok.ContractAddress, pot.PayoutAddress)
		if err != nil {
			logger.Warnf("Failed to fetch token balance for provider %s token %d: %v", providerID, tok.ID, err)
			continue
		}

		// raw is in smallest units; convert using token decimals
		dec := int32(tok.Decimals)
		bal := decimal.NewFromBigInt(raw, -dec)
		now := time.Now()

		// Aggregate balances by token ID - multiple payout addresses for same token should be summed
		if existing, exists := balances[tok.ID]; exists {
			existing.TotalBalance = existing.TotalBalance.Add(bal)
			existing.AvailableBalance = existing.AvailableBalance.Add(bal)
			existing.ReservedBalance = existing.ReservedBalance.Add(decimal.Zero)
			if now.After(existing.LastUpdated) {
				existing.LastUpdated = now
			}
		} else {
			balances[tok.ID] = &types.ProviderBalance{
				TotalBalance:     bal,
				AvailableBalance: bal,
				ReservedBalance:  decimal.Zero,
				LastUpdated:      now,
			}
		}
	}

	return balances, nil
}

// FetchAndUpdateProviderTokenBalances fetches on-chain token balances for a provider and updates them in the database.
// This is called asynchronously when a provider updates their fiat balance, ensuring token balances stay current.
func (svc *Service) FetchAndUpdateProviderTokenBalances(ctx context.Context, providerID string) error {
	balances, err := svc.FetchProviderTokenBalances(ctx, providerID)
	if err != nil {
		return err
	}

	// Update all token balances in the database
	for tokenID, balance := range balances {
		err := svc.UpsertProviderTokenBalance(ctx, providerID, tokenID, balance)
		if err != nil {
			logger.Warnf("Failed to update token balance for provider %s token %d: %v", providerID, tokenID, err)
			continue
		}
	}

	logger.Debugf("Successfully fetched and updated token balances for provider %s", providerID)
	return nil
}
