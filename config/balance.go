package config

import (
	"time"

	"github.com/shopspring/decimal"
)

type BalanceConfiguration struct {
	RedisEnabled   bool          `env:"BALANCE_REDIS_ENABLED" envDefault:"true"`
	RedisTTL       time.Duration `env:"BALANCE_REDIS_TTL" envDefault:"5m"`
	RedisMaxRetries int          `env:"BALANCE_REDIS_MAX_RETRIES" envDefault:"3"`

	MonitoringEnabled      bool          `env:"BALANCE_MONITORING_ENABLED" envDefault:"true"`
	MonitoringCheckInterval time.Duration `env:"BALANCE_MONITORING_CHECK_INTERVAL" envDefault:"10m"`
	MonitoringEmailEnabled  bool          `env:"BALANCE_MONITORING_EMAIL_ENABLED" envDefault:"true"`

	DefaultMinimumBalance decimal.Decimal `env:"BALANCE_DEFAULT_MINIMUM" envDefault:"100.0"`
	DefaultAlertThreshold decimal.Decimal `env:"BALANCE_DEFAULT_ALERT" envDefault:"500.0"`
	DefaultCriticalThreshold decimal.Decimal `env:"BALANCE_DEFAULT_CRITICAL" envDefault:"100.0"`

	CurrencyThresholds map[string]CurrencyThresholds
}

type CurrencyThresholds struct {
	MinimumAvailableBalance decimal.Decimal
	AlertThreshold         decimal.Decimal
	CriticalThreshold      decimal.Decimal
}

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

func (bc *BalanceConfiguration) GetMinimumBalance(currencyCode string) decimal.Decimal {
	if thresholds, exists := bc.CurrencyThresholds[currencyCode]; exists {
		return thresholds.MinimumAvailableBalance
	}
	return bc.DefaultMinimumBalance
}

func (bc *BalanceConfiguration) GetAlertThreshold(currencyCode string) decimal.Decimal {
	if thresholds, exists := bc.CurrencyThresholds[currencyCode]; exists {
		return thresholds.AlertThreshold
	}
	return bc.DefaultAlertThreshold
}

func (bc *BalanceConfiguration) GetCriticalThreshold(currencyCode string) decimal.Decimal {
	if thresholds, exists := bc.CurrencyThresholds[currencyCode]; exists {
		return thresholds.CriticalThreshold
	}
	return bc.DefaultCriticalThreshold
}

func (bc *BalanceConfiguration) SetCurrencyThresholds(currencyCode string, thresholds CurrencyThresholds) {
	bc.CurrencyThresholds[currencyCode] = thresholds
}

func (bc *BalanceConfiguration) IsBalanceSufficient(currencyCode string, availableBalance decimal.Decimal) bool {
	minimumBalance := bc.GetMinimumBalance(currencyCode)
	return availableBalance.GreaterThanOrEqual(minimumBalance)
}

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

type BalanceStatus string

const (
	BalanceStatusHealthy  BalanceStatus = "healthy"
	BalanceStatusAlert    BalanceStatus = "alert"
	BalanceStatusCritical BalanceStatus = "critical"
) 