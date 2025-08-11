package services

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/go-co-op/gocron"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/shopspring/decimal"
)

// BalanceMonitoringService handles balance monitoring and alerting
type BalanceMonitoringService struct {
	client     *ent.Client
	config     *config.BalanceConfiguration
	scheduler  *gocron.Scheduler
	emailService *EmailService
}

// NewBalanceMonitoringService creates a new balance monitoring service
func NewBalanceMonitoringService(client *ent.Client, balanceConfig *config.BalanceConfiguration, emailService *EmailService) *BalanceMonitoringService {
	return &BalanceMonitoringService{
		client:        client,
		config:        balanceConfig,
		scheduler:     gocron.NewScheduler(time.UTC),
		emailService:  emailService,
	}
}

// Start begins the balance monitoring service
func (bms *BalanceMonitoringService) Start() error {
	if !bms.config.MonitoringEnabled {
		log.Println("Balance monitoring is disabled")
		return nil
	}

	log.Printf("Starting balance monitoring service with check interval: %v", bms.config.MonitoringCheckInterval)
	
	// Schedule periodic balance checks
	_, err := bms.scheduler.Every(bms.config.MonitoringCheckInterval).Do(bms.CheckAllProviderBalances)
	if err != nil {
		return fmt.Errorf("failed to schedule balance monitoring: %w", err)
	}

	// Start the scheduler
	bms.scheduler.StartAsync()
	
	// Run initial check
	go bms.CheckAllProviderBalances()
	
	return nil
}

// Stop stops the balance monitoring service
func (bms *BalanceMonitoringService) Stop() {
	if bms.scheduler != nil {
		bms.scheduler.Stop()
	}
}

// CheckAllProviderBalances checks balances for all providers and currencies
func (bms *BalanceMonitoringService) CheckAllProviderBalances() {
	log.Println("Starting balance health check for all providers...")
	
	ctx := context.Background()
	
	// Get all provider currencies
	providerCurrencies, err := bms.client.ProviderCurrencies.Query().
		WithProvider().
		WithCurrency().
		All(ctx)
	
	if err != nil {
		log.Printf("Error fetching provider currencies: %v", err)
		return
	}

	for _, pc := range providerCurrencies {
		if err := bms.CheckProviderBalance(ctx, pc); err != nil {
			log.Printf("Error checking balance for provider %s, currency %s: %v", 
				pc.Edges.Provider.ID, pc.Edges.Currency.Code, err)
		}
	}
	
	log.Printf("Completed balance health check for %d provider currencies", len(providerCurrencies))
}

// CheckProviderBalance checks the balance for a specific provider currency
func (bms *BalanceMonitoringService) CheckProviderBalance(ctx context.Context, pc *ent.ProviderCurrencies) error {
	currencyCode := pc.Edges.Currency.Code
	availableBalance := pc.AvailableBalance
	
	// Get balance status
	status := bms.config.GetBalanceStatus(currencyCode, availableBalance)
	
	// Check if balance is sufficient for orders
	isSufficient := bms.config.IsBalanceSufficient(currencyCode, availableBalance)
	
	log.Printf("Provider %s, Currency %s: Balance=%.8f, Status=%s, Sufficient=%v", 
		pc.Edges.Provider.ID, currencyCode, availableBalance, status, isSufficient)
	
	// Handle different balance statuses
	switch status {
	case config.BalanceStatusCritical:
		return bms.handleCriticalBalance(ctx, pc, availableBalance)
	case config.BalanceStatusAlert:
		return bms.handleAlertBalance(ctx, pc, availableBalance)
	case config.BalanceStatusHealthy:
		return bms.handleHealthyBalance(ctx, pc, availableBalance)
	}
	
	return nil
}

// handleCriticalBalance handles critical balance situations
func (bms *BalanceMonitoringService) handleCriticalBalance(ctx context.Context, pc *ent.ProviderCurrencies, availableBalance decimal.Decimal) error {
	currencyCode := pc.Edges.Currency.Code
	criticalThreshold := bms.config.GetCriticalThreshold(currencyCode)
	
	log.Printf("CRITICAL: Provider %s has insufficient balance for %s. Available: %.8f, Critical Threshold: %.8f", 
		pc.Edges.Provider.ID, currencyCode, availableBalance, criticalThreshold)
	
	// Send critical alert email
	if bms.config.MonitoringEmailEnabled && bms.emailService != nil {
		// Get user email from provider profile
		user, err := pc.Edges.Provider.QueryUser().Only(ctx)
		if err == nil && user.Email != "" {
			// TODO: Implement balance alert email sending
			log.Printf("Would send critical balance alert to: %s", user.Email)
		}
	}
	
	// TODO: Potentially disable provider for this currency
	// This could be implemented by updating a provider status field
	
	return nil
}

// handleAlertBalance handles alert balance situations
func (bms *BalanceMonitoringService) handleAlertBalance(ctx context.Context, pc *ent.ProviderCurrencies, availableBalance decimal.Decimal) error {
	currencyCode := pc.Edges.Currency.Code
	alertThreshold := bms.config.GetAlertThreshold(currencyCode)
	
	log.Printf("ALERT: Provider %s balance is low for %s. Available: %.8f, Alert Threshold: %.8f", 
		pc.Edges.Provider.ID, currencyCode, availableBalance, alertThreshold)
	
	// Send alert email
	if bms.config.MonitoringEmailEnabled && bms.emailService != nil {
		// Get user email from provider profile
		user, err := pc.Edges.Provider.QueryUser().Only(ctx)
		if err == nil && user.Email != "" {
			// TODO: Implement balance alert email sending
			log.Printf("Would send balance alert to: %s", user.Email)
		}
	}
	
	return nil
}

// handleHealthyBalance handles healthy balance situations
func (bms *BalanceMonitoringService) handleHealthyBalance(ctx context.Context, pc *ent.ProviderCurrencies, availableBalance decimal.Decimal) error {
	// Log healthy balance (optional, can be removed for production)
	currencyCode := pc.Edges.Currency.Code
	log.Printf("HEALTHY: Provider %s balance is healthy for %s. Available: %.8f", 
		pc.Edges.Provider.ID, currencyCode, availableBalance)
	
	return nil
}

// GetProviderBalanceStatus returns the current balance status for a provider currency
func (bms *BalanceMonitoringService) GetProviderBalanceStatus(providerID string, currencyCode string) (*config.BalanceStatus, error) {
	ctx := context.Background()
	
	// Get provider currency using a simpler query approach
	providerCurrencies, err := bms.client.ProviderCurrencies.Query().
		WithProvider().
		WithCurrency().
		All(ctx)
	
	if err != nil {
		return nil, fmt.Errorf("failed to fetch provider currencies: %w", err)
	}
	
	// Find the specific provider currency
	for _, pc := range providerCurrencies {
		if pc.Edges.Provider.ID == providerID && pc.Edges.Currency.Code == currencyCode {
			status := bms.config.GetBalanceStatus(currencyCode, pc.AvailableBalance)
			return &status, nil
		}
	}
	
	return nil, fmt.Errorf("provider currency not found")
}

// IsProviderBalanceSufficient checks if a provider has sufficient balance for orders
func (bms *BalanceMonitoringService) IsProviderBalanceSufficient(providerID string, currencyCode string) (bool, error) {
	ctx := context.Background()
	
	// Get provider currency using a simpler query approach
	providerCurrencies, err := bms.client.ProviderCurrencies.Query().
		WithProvider().
		WithCurrency().
		All(ctx)
	
	if err != nil {
		return false, fmt.Errorf("failed to fetch provider currencies: %w", err)
	}
	
	// Find the specific provider currency
	for _, pc := range providerCurrencies {
		if pc.Edges.Provider.ID == providerID && pc.Edges.Currency.Code == currencyCode {
			return bms.config.IsBalanceSufficient(currencyCode, pc.AvailableBalance), nil
		}
	}
	
	return false, fmt.Errorf("provider currency not found")
} 