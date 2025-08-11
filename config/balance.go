package config

import (
	"time"

	"github.com/shopspring/decimal"
)

// BalanceConfiguration holds all balance-related configuration settings
type BalanceConfiguration struct {
	// Redis caching settings
	RedisEnabled   bool          `env:"BALANCE_REDIS_ENABLED" envDefault:"true"`
	RedisTTL       time.Duration `env:"BALANCE_REDIS_TTL" envDefault:"5m"`
	RedisMaxRetries int          `env:"BALANCE_REDIS_MAX_RETRIES" envDefault:"3"`

	// Monitoring settings
	MonitoringEnabled      bool          `env:"BALANCE_MONITORING_ENABLED" envDefault:"true"`
	MonitoringCheckInterval time.Duration `env:"BALANCE_MONITORING_CHECK_INTERVAL" envDefault:"10m"`
	MonitoringEmailEnabled  bool          `env:"BALANCE_MONITORING_EMAIL_ENABLED" envDefault:"true"`

	// Default thresholds (can be overridden per currency)
	DefaultMinimumBalance decimal.Decimal `env:"BALANCE_DEFAULT_MINIMUM" envDefault:"100.0"`
	DefaultAlertThreshold decimal.Decimal `env:"BALANCE_DEFAULT_ALERT" envDefault:"500.0"`
	DefaultCriticalThreshold decimal.Decimal `env:"BALANCE_DEFAULT_CRITICAL" envDefault:"100.0"`

	// Currency-specific threshold overrides
	CurrencyThresholds map[string]CurrencyThresholds
}

// CurrencyThresholds defines balance thresholds for a specific currency
type CurrencyThresholds struct {
	MinimumAvailableBalance decimal.Decimal
	AlertThreshold         decimal.Decimal
	CriticalThreshold      decimal.Decimal
}

// NewBalanceConfiguration creates a new balance configuration with defaults
func NewBalanceConfiguration() *BalanceConfiguration {
	return &BalanceConfiguration{
		RedisEnabled:           true,
		RedisTTL:              5 * time.Minute,
		RedisMaxRetries:       3,
		MonitoringEnabled:     true,
		MonitoringCheckInterval: 10 * time.Minute,
		MonitoringEmailEnabled:  true,
		DefaultMinimumBalance: decimal.NewFromFloat(100.0),
		DefaultAlertThreshold: decimal.NewFromFloat(500.0),
		DefaultCriticalThreshold: decimal.NewFromFloat(100.0),
		CurrencyThresholds:    make(map[string]CurrencyThresholds),
	}
}

// GetMinimumBalance returns the minimum balance threshold for a currency
func (bc *BalanceConfiguration) GetMinimumBalance(currencyCode string) decimal.Decimal {
	if thresholds, exists := bc.CurrencyThresholds[currencyCode]; exists {
		return thresholds.MinimumAvailableBalance
	}
	return bc.DefaultMinimumBalance
}

// GetAlertThreshold returns the alert threshold for a currency
func (bc *BalanceConfiguration) GetAlertThreshold(currencyCode string) decimal.Decimal {
	if thresholds, exists := bc.CurrencyThresholds[currencyCode]; exists {
		return thresholds.AlertThreshold
	}
	return bc.DefaultAlertThreshold
}

// GetCriticalThreshold returns the critical threshold for a currency
func (bc *BalanceConfiguration) GetCriticalThreshold(currencyCode string) decimal.Decimal {
	if thresholds, exists := bc.CurrencyThresholds[currencyCode]; exists {
		return thresholds.CriticalThreshold
	}
	return bc.DefaultCriticalThreshold
}

// SetCurrencyThresholds sets thresholds for a specific currency
func (bc *BalanceConfiguration) SetCurrencyThresholds(currencyCode string, thresholds CurrencyThresholds) {
	bc.CurrencyThresholds[currencyCode] = thresholds
}

// IsBalanceSufficient checks if a balance is sufficient for orders
func (bc *BalanceConfiguration) IsBalanceSufficient(currencyCode string, availableBalance decimal.Decimal) bool {
	minimumBalance := bc.GetMinimumBalance(currencyCode)
	return availableBalance.GreaterThanOrEqual(minimumBalance)
}

// GetBalanceStatus returns the current balance status for monitoring
func (bc *BalanceConfiguration) GetBalanceStatus(currencyCode string, availableBalance decimal.Decimal) BalanceStatus {
	alertThreshold := bc.GetAlertThreshold(currencyCode)
	criticalThreshold := bc.GetCriticalThreshold(currencyCode)

	if availableBalance.LessThan(criticalThreshold) {
		return BalanceStatusCritical
	} else if availableBalance.LessThan(alertThreshold) {
		return BalanceStatusAlert
	}
	return BalanceStatusHealthy
}

// BalanceStatus represents the current balance health status
type BalanceStatus string

const (
	BalanceStatusHealthy  BalanceStatus = "healthy"
	BalanceStatusAlert    BalanceStatus = "alert"
	BalanceStatusCritical BalanceStatus = "critical"
) 