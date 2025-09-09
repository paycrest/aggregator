package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/services/email"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

type BalanceMonitoringService struct {
	config         *config.BalanceConfiguration
	balanceService *BalanceManagementService
	emailService   *email.EmailService
}

type BalanceAlert struct {
	ProviderId     string
	CurrencyCode   string
	CurrentBalance decimal.Decimal
	Threshold      decimal.Decimal
	AlertType      AlertType
	Timestamp      time.Time
}

type AlertType string

type CurrencyThresholds struct {
	MinAvailable      decimal.Decimal
	AlertThreshold    decimal.Decimal
	CriticalThreshold decimal.Decimal
}

const (
	AlertTypeLow      AlertType = "low_balance"
	AlertTypeCritical AlertType = "critical_balance"
)

func NewBalanceMonitoringService() *BalanceMonitoringService {
	return &BalanceMonitoringService{
		config:         config.BalanceConfig(),
		balanceService: NewBalanceManagementService(),
		emailService:   email.NewEmailService(),
	}
}

func (s *BalanceMonitoringService) StartMonitoring(ctx context.Context) {
	if !s.config.MonitoringEnabled {
		logger.Infof("Balance monitoring is disabled")
		return
	}

	ticker := time.NewTicker(s.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.CheckAllProviderBalances(ctx)
		}
	}
}

func (s *BalanceMonitoringService) CheckAllProviderBalances(ctx context.Context) {
	providers, err := s.getAllActiveProviders(ctx)

	if err != nil {
		logger.Errorf("Failed to get active providers: %v", err)
		return
	}

	for _, provider := range providers {
		s.checkProviderBalances(ctx, provider)
	}
}

func (s *BalanceMonitoringService) getAllActiveProviders(ctx context.Context) ([]*ent.ProviderProfile, error) {
	providers, err := storage.Client.ProviderProfile.Query().Where(providerprofile.IsActiveEQ(true)).WithProviderCurrencies(func(pcq *ent.ProviderCurrenciesQuery) {
		pcq.WithCurrency()
	}).
		All(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to get active providers: %w", err)
	}

	return providers, nil
}

func (s *BalanceMonitoringService) checkProviderBalances(ctx context.Context, provider *ent.ProviderProfile) {
	currencies, err := s.balanceService.GetProviderBalances(ctx, provider.ID)

	if err != nil {
		logger.Errorf("Failed to get provider balances: %v", err)
		return
	}

	for _, currency := range currencies {
		s.checkCurrencyBalance(ctx, provider, currency)
	}
}

func (s *BalanceMonitoringService) checkCurrencyBalance(ctx context.Context, provider *ent.ProviderProfile, currency *ent.ProviderCurrencies) {
	thresholds, err := s.getCurrencyThresholds(ctx, currency.Edges.Currency.Code)

	if err != nil {
		logger.Errorf("Failed to get thresholds for currency %s: %v", currency.Edges.Currency.Code, err)
		return
	}

	currentBalance := currency.AvailableBalance

	if currentBalance.LessThan(thresholds.CriticalThreshold) {
		alert := &BalanceAlert{
			ProviderId:     provider.ID,
			CurrencyCode:   currency.Edges.Currency.Code,
			CurrentBalance: currentBalance,
			Threshold:      thresholds.CriticalThreshold,
			AlertType:      AlertTypeCritical,
			Timestamp:      time.Now(),
		}

		s.sendAlert(ctx, alert)

		s.handleCriticalAlert(ctx, provider, currency)
	} else if currentBalance.LessThan(thresholds.AlertThreshold) {
		alert := &BalanceAlert{
			ProviderId:     provider.ID,
			CurrencyCode:   currency.Edges.Currency.Code,
			CurrentBalance: currentBalance,
			Threshold:      thresholds.AlertThreshold,
			AlertType:      AlertTypeLow,
			Timestamp:      time.Now(),
		}

		s.sendAlert(ctx, alert)
	}
}

func (s *BalanceMonitoringService) handleCriticalAlert(ctx context.Context, provider *ent.ProviderProfile, currency *ent.ProviderCurrencies) {
	logger.WithFields(logger.Fields{
		"ProviderID":      provider.ID,
		"CurrencyCode":    currency.Edges.Currency.Code,
		"CurrencyBalance": currency.AvailableBalance.String(),
	}).Errorf("Provider has critical balance - consider disabling")

	// Update provider health status to unhealthy
	err := s.UpdateProviderHealthStatus(ctx, provider.ID, currency.Edges.Currency.Code, false)
	if err != nil {
		logger.Errorf("Failed to update provider health status: %v", err)
	}

	// mark provider as unavailable
	if err := s.disableProvider(ctx, provider, currency); err != nil {
		logger.Errorf("Failed to disable provider: %v", err)
	}

	if err := s.sendCriticalAlert(ctx, provider, currency); err != nil {
		logger.Errorf("Failed to send critical alert: %v", err)
	}

	if err := s.pauseProviderOrders(ctx, provider, currency); err != nil {
		logger.Errorf("Failed to pause providers orders: %v", err)
	}

	if err := s.creditAuditLog(ctx, provider, currency, "critical_balance"); err != nil {
		logger.Errorf("Failed to create audit log: %v", err)
	}
}

func (s *BalanceMonitoringService) getCurrencyThresholds(ctx context.Context, currencyCode string) (*CurrencyThresholds, error) {
	if s.config.RedisEnabled {
		if cached, err := s.getCachedThresholds(currencyCode); err == nil {
			return cached, nil
		}
	}

	currency, err := storage.Client.FiatCurrency.
		Query().
		Where(fiatcurrency.CodeEQ(currencyCode)).
		Only(ctx)

	if err != nil {
		return nil, err
	}

	thresholds := &CurrencyThresholds{
		MinAvailable:      currency.MinimumAvailableBalance,
		AlertThreshold:    currency.AlertThreshold,
		CriticalThreshold: currency.CriticalThreshold,
	}

	if s.config.RedisEnabled {
		s.cacheThresholds(currencyCode, thresholds)
	}

	return thresholds, nil
}
func (s *BalanceMonitoringService) getCachedThresholds(currencyCode string) (*CurrencyThresholds, error) {
	if !s.config.RedisEnabled {
		return nil, fmt.Errorf("redis is not enabled")
	}

	key := fmt.Sprintf("balance_thresholds:%s", currencyCode)

	data, err := storage.RedisClient.Get(context.Background(), key).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to get cached thresholds: %w", err)
	}

	var thresholds CurrencyThresholds

	if err := json.Unmarshal([]byte(data), &thresholds); err != nil {
		return nil, fmt.Errorf("failed to unmarshal thresholds: %w", err)
	}

	return &thresholds, nil
}

func (s *BalanceMonitoringService) cacheThresholds(currencyCode string, thresholds *CurrencyThresholds) {
	if !s.config.RedisEnabled {
		logger.Infof("Redis is not enabled, skipping cache for thresholds")
		return
	}

	key := fmt.Sprintf("balance_thresholds:%s", currencyCode)

	data, err := json.Marshal(thresholds)

	if err != nil {
		logger.Errorf("Failed to marshal thresholds: %v", err)
		return
	}

	if err := storage.RedisClient.Set(context.Background(), key, data, s.config.RedisTTL).Err(); err != nil {
		logger.Errorf("Failed to cache thresholds: %v", err)
	}
}

func (s *BalanceMonitoringService) sendAlert(ctx context.Context, alert *BalanceAlert) {
	if !s.config.EmailEnabled {
		logger.Infof("Email notifications are disabled, skipping alert for %s", alert.CurrencyCode)
		return
	}

	provider, err := s.getProviderDetails(ctx, alert.ProviderId)

	if err != nil {
		logger.Errorf("Failed to get provider details: %v", err)
		return
	}

	response, err := s.emailService.SendBalanceAlertEmail(ctx, provider.Edges.User.Email, provider.Edges.User.FirstName)

	if err != nil {
		logger.Errorf("Failed to send alert email: %v", err)
	}

	logger.WithFields(logger.Fields{
		"ProviderID":      alert.ProviderId,
		"CurrencyCode":    alert.CurrencyCode,
		"CurrencyBalance": alert.CurrentBalance.String(),
		"Threshold":       alert.Threshold.String(),
		"AlertType":       alert.AlertType,
		"EmailResponse":   response.Id,
	}).Warnf("Balance alert triggered")
}

func (s *BalanceMonitoringService) getProviderDetails(ctx context.Context, providerId string) (*ent.ProviderProfile, error) {
	provider, err := storage.Client.ProviderProfile.Query().Where(providerprofile.IDEQ(providerId)).Only(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to get provider details: %w", err)
	}

	return provider, nil
}

// func (s *BalanceMonitoringService) handleCriticalBalance(ctx context.Context, provider *ent.ProviderProfile, currency *ent.ProviderCurrencies) {
// 	logger.WithFields(logger.Fields{
// 		"ProviderID":      provider.ID,
// 		"CurrencyCode":    currency.Edges.Currency.Code,
// 		"CurrencyBalance": currency.AvailableBalance.String(),
// 	}).Errorf("Provider has critical balance - consider disabling")
// }

func (s *BalanceMonitoringService) disableProvider(ctx context.Context, provider *ent.ProviderProfile, currency *ent.ProviderCurrencies) error {
	_, err := storage.Client.ProviderProfile.
		UpdateOneID(provider.ID).
		SetIsActive(false).
		SetUpdatedAt(time.Now()).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("failed to disable provider: %w", err)
	}

	logger.WithFields(logger.Fields{
		"ProviderID":   provider.ID,
		"CurrencyCode": currency.Edges.Currency.Code,
		"Action":       "provider_disabled",
		"Reason":       "critical_balance",
	}).Warnf("Provider disabled due to critical balance")

	return nil
}

func (s *BalanceMonitoringService) sendCriticalAlert(ctx context.Context, provider *ent.ProviderProfile, currency *ent.ProviderCurrencies) error {
	additionalData := map[string]interface{}{
		"currency_code":      currency.Edges.Currency.Code,
		"currency_balance":   currency.AvailableBalance.String(),
		"critical_threshold": currency.Edges.Currency.CriticalThreshold.String(),
		"alert_type":         "critical",
		"timestamp":          time.Now().Format("2006-01-02 15:04:05 UTC"),
		"severity":           "CRITICAL",
		"action_taken":       "Provider has been automatically disabled due to critical balance",
		"next_steps":         "Please top up your balance and contact support to reactivate your account",
	}

	response, err := s.emailService.SendCriticalBalanceAlertEmail(ctx, provider.Edges.User.Email, provider.Edges.User.FirstName, additionalData)

	if err != nil {
		return fmt.Errorf("failed to send critical alert: %w", err)
	}

	logger.WithFields(logger.Fields{
		"ProviderID":    provider.ID,
		"EmailResponse": response.Id,
		"Action":        "critical_alert_sent",
	})

	return nil
}

func (s *BalanceMonitoringService) pauseProviderOrders(ctx context.Context, provider *ent.ProviderProfile, currency *ent.ProviderCurrencies) error {
	updatedCount, err := storage.Client.LockPaymentOrder.
		Update().
		Where(lockpaymentorder.HasProviderWith(providerprofile.IDEQ(provider.ID)),
			lockpaymentorder.StatusEQ(lockpaymentorder.StatusValidated),
		).
		SetStatus(lockpaymentorder.StatusPaused).
		SetUpdatedAt(time.Now()).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("failed to pause provider orders: %w", err)
	}

	logger.WithFields(logger.Fields{
		"ProviderID":   provider.ID,
		"CurrencyCode": currency.Edges.Currency.Code,
		"PausedOrders": updatedCount,
		"Action":       "orders_paused",
	}).Warnf("Paused %d orders for provider due to critical balance", updatedCount)

	return nil
}

func (s *BalanceMonitoringService) creditAuditLog(_ctx context.Context, provider *ent.ProviderProfile, currency *ent.ProviderCurrencies, action string) error {
	auditLog := map[string]interface{}{
		"action":           action,
		"provider_id":      provider.ID,
		"provider_name":    provider.TradingName,
		"currency_code":    currency.Edges.Currency.Code,
		"currency_balance": currency.AvailableBalance.String(),
		"threshold":        currency.Edges.Currency.CriticalThreshold.String(),
		"timestamp":        time.Now(),
		"severity":         "critical",
		"auto_action":      true,
	}

	logger.WithFields(logger.Fields{
		"AuditLog": auditLog,
	}).Errorf("Critical balance audit log: %s", action)

	return nil
}

func (s *BalanceMonitoringService) IsProviderHealthyForOrders(ctx context.Context, providerID string, currencyCode string) (bool, error) {
	// Check if provider is in critical state (cached check)
	if s.config.RedisEnabled && storage.RedisClient != nil {
		key := fmt.Sprintf("provider_health:%s:%s", providerID, currencyCode)
		status, err := storage.RedisClient.Get(ctx, key).Result()
		if err == nil {
			return status == "healthy", nil
		}
	}

	// Fallback to balance service health check
	balanceService := NewBalanceManagementService()
	isHealthy, err := balanceService.IsProviderHealthyForCurrency(ctx, providerID, currencyCode)
	if err != nil {
		return false, err
	}

	// Cache the result if Redis is available
	if s.config.RedisEnabled && storage.RedisClient != nil {
		key := fmt.Sprintf("provider_health:%s:%s", providerID, currencyCode)
		status := "unhealthy"
		if isHealthy {
			status = "healthy"
		}
		storage.RedisClient.Set(ctx, key, status, 5*time.Minute)
	}

	return isHealthy, nil
}

func (s *BalanceMonitoringService) UpdateProviderHealthStatus(ctx context.Context, providerID string, currencyCode string, isHealthy bool) error {
	if s.config.RedisEnabled && storage.RedisClient != nil {
		key := fmt.Sprintf("provider_health:%s:%s", providerID, currencyCode)
		status := "unhealthy"
		if isHealthy {
			status = "healthy"
		}
		return storage.RedisClient.Set(ctx, key, status, 5*time.Minute).Err()
	}

	key := fmt.Sprintf("provider_health:%s:%s", providerID, currencyCode)
	status := "unhealthy"
	if isHealthy {
		status = "healthy"
	}

	return storage.RedisClient.Set(ctx, key, status, 5*time.Minute).Err()
}

func (s *BalanceMonitoringService) GetProviderHealthStatus(ctx context.Context, providerID string, currencyCode string) (string, error) {
	if s.config.RedisEnabled && storage.RedisClient != nil {
		key := fmt.Sprintf("provider_health:%s:%s", providerID, currencyCode)
		status, err := storage.RedisClient.Get(ctx, key).Result()
		if err == nil {
			return status, nil
		}
	}

	// Fallback to balance service check
	balanceService := NewBalanceManagementService()
	isHealthy, err := balanceService.IsProviderHealthyForCurrency(ctx, providerID, currencyCode)
	if err != nil {
		return "unknown", err
	}
	if isHealthy {
		return "healthy", nil
	}
	return "unhealthy", nil
}
