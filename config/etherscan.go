package config

import (
	"github.com/spf13/viper"
)

// EtherscanConfiguration holds the configuration for Etherscan API integration
type EtherscanConfiguration struct {
	ApiKey string
}

// EtherscanConfig returns the Etherscan configuration
func EtherscanConfig() *EtherscanConfiguration {
	return &EtherscanConfiguration{
		ApiKey: viper.GetString("ETHERSCAN_API_KEY"),
	}
}
