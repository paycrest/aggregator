package config

import (
	"github.com/spf13/viper"
)

// EtherscanConfiguration holds the configuration for Etherscan API integration
type EtherscanConfiguration struct {
	ApiKey     string
	RateLimit  int // Requests per second per worker (default: 3 for Free tier)
	DailyLimit int // Maximum API calls per day (default: 100000 for Free tier)
}

// EtherscanConfig returns the Etherscan configuration
func EtherscanConfig() *EtherscanConfiguration {
	viper.SetDefault("ETHERSCAN_RATE_LIMIT", 3)
	viper.SetDefault("ETHERSCAN_DAILY_LIMIT", 100000) // Default: 100k for Free tier

	return &EtherscanConfiguration{
		ApiKey:     viper.GetString("ETHERSCAN_API_KEY"),
		RateLimit:  viper.GetInt("ETHERSCAN_RATE_LIMIT"),
		DailyLimit: viper.GetInt("ETHERSCAN_DAILY_LIMIT"),
	}
}
