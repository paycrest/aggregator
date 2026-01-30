package balance

import (
	"context"
	"fmt"
	"time"

	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/providerbalances"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

// FailedOrderInfo represents information about a failed order for cleanup.
type FailedOrderInfo struct {
	OrderID      string          `json:"orderId"`
	ProviderID   string          `json:"providerId"`
	CurrencyCode string          `json:"currencyCode"`
	Amount       decimal.Decimal `json:"amount"`
	FailureTime  time.Time       `json:"failureTime"`
}

// BulkCleanupReport represents the result of bulk cleanup operations.
type BulkCleanupReport struct {
	TotalOrders    int             `json:"totalOrders"`
	SuccessCount   int             `json:"successCount"`
	FailureCount   int             `json:"failureCount"`
	TotalAmount    decimal.Decimal `json:"totalAmount"`
	Errors         []string        `json:"errors"`
	SuccessDetails []string        `json:"successDetails"`
	FailureDetails []string        `json:"failureDetails"`
}

// BalanceHealthReport represents the result of a balance health check.
type BalanceHealthReport struct {
	ProviderID       string          `json:"providerId"`
	CurrencyCode     string          `json:"currencyCode"`
	AvailableBalance decimal.Decimal `json:"availableBalance"`
	ReservedBalance  decimal.Decimal `json:"reservedBalance"`
	TotalBalance     decimal.Decimal `json:"totalBalance"`
	LastUpdated      time.Time       `json:"lastUpdated"`
	Status           string          `json:"status"`
	Severity         string          `json:"severity"`
	Issues           []string        `json:"issues"`
	Recommendations  []string        `json:"recommendations"`
}

// GetProviderBalances retrieves all balances (fiat + token) for a specific provider.
func (svc *Service) GetProviderBalances(ctx context.Context, providerID string) ([]*ent.ProviderBalances, error) {
	list, err := svc.client.ProviderBalances.Query().
		Where(providerbalances.HasProviderWith(providerprofile.IDEQ(providerID))).
		WithProvider().
		WithFiatCurrency().
		WithToken().
		All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{"Error": fmt.Sprintf("%v", err), "ProviderID": providerID}).Errorf("Failed to get provider balances")
		return nil, fmt.Errorf("failed to get provider balances: %w", err)
	}
	return list, nil
}

// CheckBalanceSufficiency checks if the given balance has sufficient available amount.
// The caller loads the balance first (e.g. via GetProviderFiatBalance or GetProviderTokenBalance).
func (svc *Service) CheckBalanceSufficiency(balance *ent.ProviderBalances, amount decimal.Decimal) bool {
	return balance.AvailableBalance.GreaterThanOrEqual(amount)
}

// ValidateBalanceConsistency validates that the given balance is logically consistent.
// The caller loads the balance first.
func (svc *Service) ValidateBalanceConsistency(balance *ent.ProviderBalances) error {
	if balance.AvailableBalance.Add(balance.ReservedBalance).GreaterThan(balance.TotalBalance) {
		return fmt.Errorf("balance inconsistency: available + reserved > total for balance %s", balance.ID)
	}
	if balance.AvailableBalance.LessThan(decimal.Zero) {
		return fmt.Errorf("negative available balance for balance %s: %s", balance.ID, balance.AvailableBalance.String())
	}
	if balance.ReservedBalance.LessThan(decimal.Zero) {
		return fmt.Errorf("negative reserved balance for balance %s: %s", balance.ID, balance.ReservedBalance.String())
	}
	if balance.TotalBalance.LessThan(decimal.Zero) {
		return fmt.Errorf("negative total balance for balance %s: %s", balance.ID, balance.TotalBalance.String())
	}
	return nil
}

// FixBalanceInconsistencies fixes common inconsistencies on the given balance within the transaction.
// The caller loads the balance and provides the transaction.
func (svc *Service) FixBalanceInconsistencies(ctx context.Context, balance *ent.ProviderBalances, tx *ent.Tx) error {
	var needsUpdate bool
	av, rv, tv := balance.AvailableBalance, balance.ReservedBalance, balance.TotalBalance
	if av.LessThan(decimal.Zero) {
		av = decimal.Zero
		needsUpdate = true
		logger.WithFields(logger.Fields{"BalanceID": balance.ID}).Warnf("Fixed negative available balance")
	}
	if rv.LessThan(decimal.Zero) {
		rv = decimal.Zero
		needsUpdate = true
		logger.WithFields(logger.Fields{"BalanceID": balance.ID}).Warnf("Fixed negative reserved balance")
	}
	if tv.LessThan(decimal.Zero) {
		tv = decimal.Zero
		needsUpdate = true
		logger.WithFields(logger.Fields{"BalanceID": balance.ID}).Warnf("Fixed negative total balance")
	}
	if av.Add(rv).GreaterThan(tv) {
		tv = av.Add(rv)
		needsUpdate = true
		logger.WithFields(logger.Fields{"BalanceID": balance.ID}).Warnf("Fixed balance inconsistency by adjusting total")
	}
	if needsUpdate {
		_, err := balance.Update().
			SetAvailableBalance(av).
			SetTotalBalance(tv).
			SetReservedBalance(rv).
			SetUpdatedAt(time.Now()).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to update balance after fixing inconsistencies: %w", err)
		}
		logger.WithFields(logger.Fields{"BalanceID": balance.ID, "AvailableBalance": av.String(), "TotalBalance": tv.String(), "ReservedBalance": rv.String()}).Infof("Fixed balance inconsistencies")
	}
	return nil
}

// ValidateAndFixBalances validates and fixes fiat balance inconsistencies for the given provider and currency.
func (svc *Service) ValidateAndFixBalances(ctx context.Context, providerID string, currencyCode string) error {
	tx, err := svc.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction for balance validation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	bal, err := tx.ProviderBalances.Query().
		Where(
			providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)),
			providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currencyCode)),
		).
		Only(ctx)
	if err != nil {
		return fmt.Errorf("failed to get provider fiat balance for validation: %w", err)
	}

	if validationErr := svc.ValidateBalanceConsistency(bal); validationErr != nil {
		logger.WithFields(logger.Fields{"ProviderID": providerID, "Currency": currencyCode, "Error": validationErr.Error()}).Warnf("Balance validation failed, attempting to fix")
		if fixErr := svc.FixBalanceInconsistencies(ctx, bal, tx); fixErr != nil {
			return fmt.Errorf("failed to validate or fix balances: validation: %w, fix: %w", validationErr, fixErr)
		}
		bal, err = tx.ProviderBalances.Query().
			Where(providerbalances.HasProviderWith(providerprofile.IDEQ(providerID)), providerbalances.HasFiatCurrencyWith(fiatcurrency.CodeEQ(currencyCode))).
			Only(ctx)
		if err != nil {
			return fmt.Errorf("failed to reload provider balance after fix: %w", err)
		}
		if validationErr = svc.ValidateBalanceConsistency(bal); validationErr != nil {
			return fmt.Errorf("balance validation still failed after fixing: %w", validationErr)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit balance validation transaction: %w", err)
	}
	return nil
}

// CheckBalanceHealth performs a health check on the given balance (loaded with WithProvider/WithFiatCurrency/WithToken for full labels).
func (svc *Service) CheckBalanceHealth(balance *ent.ProviderBalances) *BalanceHealthReport {
	providerID := ""
	if balance.Edges.Provider != nil {
		providerID = balance.Edges.Provider.ID
	}
	currencyCode := ""
	if balance.Edges.FiatCurrency != nil {
		currencyCode = balance.Edges.FiatCurrency.Code
	}

	report := &BalanceHealthReport{
		ProviderID:       providerID,
		CurrencyCode:     currencyCode,
		AvailableBalance: balance.AvailableBalance,
		ReservedBalance:  balance.ReservedBalance,
		TotalBalance:     balance.TotalBalance,
		LastUpdated:      balance.UpdatedAt,
		Issues:           []string{},
		Recommendations:  []string{},
	}

	if balance.AvailableBalance.LessThan(decimal.Zero) {
		report.Issues = append(report.Issues, fmt.Sprintf("Negative available balance: %s", balance.AvailableBalance.String()))
		report.Recommendations = append(report.Recommendations, "Reset available balance to zero")
		report.Severity = "HIGH"
	}
	if balance.ReservedBalance.LessThan(decimal.Zero) {
		report.Issues = append(report.Issues, fmt.Sprintf("Negative reserved balance: %s", balance.ReservedBalance.String()))
		report.Recommendations = append(report.Recommendations, "Reset reserved balance to zero")
		report.Severity = "HIGH"
	}
	if balance.TotalBalance.LessThan(decimal.Zero) {
		report.Issues = append(report.Issues, fmt.Sprintf("Negative total balance: %s", balance.TotalBalance.String()))
		report.Recommendations = append(report.Recommendations, "Reset total balance to zero")
		report.Severity = "HIGH"
	}
	calculatedTotal := balance.AvailableBalance.Add(balance.ReservedBalance)
	if calculatedTotal.GreaterThan(balance.TotalBalance) {
		report.Issues = append(report.Issues, fmt.Sprintf("Logical inconsistency: available + reserved (%s) > total (%s)", calculatedTotal.String(), balance.TotalBalance.String()))
		report.Recommendations = append(report.Recommendations, "Adjust total balance to match available + reserved")
		report.Severity = "MEDIUM"
	}
	if balance.AvailableBalance.Equal(decimal.Zero) && balance.ReservedBalance.Equal(decimal.Zero) && balance.TotalBalance.Equal(decimal.Zero) {
		report.Issues = append(report.Issues, "All balance fields are zero - may indicate uninitialized provider")
		report.Recommendations = append(report.Recommendations, "Verify provider balance initialization")
		report.Severity = "LOW"
	}
	if balance.ReservedBalance.GreaterThan(balance.TotalBalance) {
		report.Issues = append(report.Issues, fmt.Sprintf("Reserved balance (%s) exceeds total balance (%s)", balance.ReservedBalance.String(), balance.TotalBalance.String()))
		report.Recommendations = append(report.Recommendations, "Investigate order assignment logic")
		report.Severity = "HIGH"
	}

	if len(report.Issues) == 0 {
		report.Status = "HEALTHY"
		report.Severity = "NONE"
	} else if report.Severity == "HIGH" {
		report.Status = "CRITICAL"
	} else if report.Severity == "MEDIUM" {
		report.Status = "WARNING"
	} else {
		report.Status = "INFO"
	}
	return report
}

// SafeReleaseBalance safely releases reserved balance with comprehensive error handling.
// This method is designed to be called from cleanup operations and should not fail the main flow.
func (svc *Service) SafeReleaseBalance(ctx context.Context, providerID string, currencyCode string, amount decimal.Decimal) error {
	// Use a separate context with timeout to prevent hanging
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Attempt to release the balance
	err := svc.ReleaseFiatBalance(ctx, providerID, currencyCode, amount, nil)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":      fmt.Sprintf("%v", err),
			"ProviderID": providerID,
			"Currency":   currencyCode,
			"Amount":     amount.String(),
		}).Errorf("Failed to safely release reserved balance for provider %s - this may require manual intervention", providerID)

		// Log additional context for debugging
		logger.WithFields(logger.Fields{
			"ProviderID": providerID,
			"Currency":   currencyCode,
			"Amount":     amount.String(),
		}).Warnf("Balance release failed - provider %s may have inconsistent balance state", providerID)

		return err
	}

	logger.WithFields(logger.Fields{
		"ProviderID": providerID,
		"Currency":   currencyCode,
		"Amount":     amount.String(),
	}).Infof("Successfully released reserved balance for provider %s", providerID)

	return nil
}

// BulkCleanupFailedOrders performs bulk cleanup of failed orders and releases associated balances.
// This method is designed to be called from cleanup jobs or admin interfaces.
func (svc *Service) BulkCleanupFailedOrders(ctx context.Context, failedOrders []FailedOrderInfo) (*BulkCleanupReport, error) {
	report := &BulkCleanupReport{
		TotalOrders:    len(failedOrders),
		SuccessCount:   0,
		FailureCount:   0,
		TotalAmount:    decimal.Zero,
		Errors:         []string{},
		SuccessDetails: []string{},
		FailureDetails: []string{},
	}

	// Process each failed order
	for _, order := range failedOrders {
		// Use a separate context with timeout for each order
		orderCtx, cancel := context.WithTimeout(ctx, 30*time.Second)

		// Attempt to release balance for this order
		err := svc.SafeReleaseBalance(orderCtx, order.ProviderID, order.CurrencyCode, order.Amount)
		cancel()

		if err != nil {
			report.FailureCount++
			errorMsg := fmt.Sprintf("Order %s: %v", order.OrderID, err)
			report.Errors = append(report.Errors, errorMsg)
			report.FailureDetails = append(report.FailureDetails,
				fmt.Sprintf("Order %s (Provider: %s, Currency: %s, Amount: %s) - %v",
					order.OrderID, order.ProviderID, order.CurrencyCode, order.Amount.String(), err))
		} else {
			report.SuccessCount++
			report.TotalAmount = report.TotalAmount.Add(order.Amount)
			report.SuccessDetails = append(report.SuccessDetails,
				fmt.Sprintf("Order %s (Provider: %s, Currency: %s, Amount: %s) - Balance released successfully",
					order.OrderID, order.ProviderID, order.CurrencyCode, order.Amount.String()))
		}
	}

	// Log summary
	logger.WithFields(logger.Fields{
		"TotalOrders":  report.TotalOrders,
		"SuccessCount": report.SuccessCount,
		"FailureCount": report.FailureCount,
		"TotalAmount":  report.TotalAmount.String(),
	}).Infof("Bulk cleanup completed: %d successful, %d failed", report.SuccessCount, report.FailureCount)

	return report, nil
}
