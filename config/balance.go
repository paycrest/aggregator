package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

type BalanceConfiguration struct {
	RedisEnabled    bool
	RedisTTL        time.Duration
	RedisMaxRetries int

	MonitoringEnabled bool
	CheckInterval     time.Duration
	EmailEnabled      bool
}

func BalanceConfig() *BalanceConfiguration {
	viper.SetDefault("REDIS_ENABLED", true)
	viper.SetDefault("REDIS_TTL", 10*time.Minute)
	viper.SetDefault("REDIS_MAX_RETRIES", 3)

	viper.SetDefault("MONITORING_ENABLED", true)
	viper.SetDefault("CHECK_INTERVAL", 10*time.Minute)
	viper.SetDefault("EMAIL_ENABLED", true)

	return &BalanceConfiguration{
		RedisEnabled:      viper.GetBool("REDIS_ENABLED"),
		RedisTTL:          time.Duration(viper.GetInt("REDIS_TTL")) * time.Minute,
		RedisMaxRetries:   viper.GetInt("REDIS_MAX_RETRIES"),
		MonitoringEnabled: viper.GetBool("MONITORING_ENABLED"),
		CheckInterval:     time.Duration(viper.GetInt("CHECK_INTERVAL")) * time.Minute,
		EmailEnabled:      viper.GetBool("EMAIL_ENABLED"),
	}
}

func init() {
	if err := SetupConfig(); err != nil {
		panic(fmt.Sprintf("config SetupConfig() error: %s", err))
	}
}