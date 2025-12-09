package config

import (
	"github.com/spf13/viper"
)

// StarknetConfiguration holds the configuration for Starknet integration
type StarknetConfiguration struct {
	AccountClassHash        string
	StarknetPaymasterURL    string
	StarknetClientURL       string
	StarknetPaymasterAPIKey string
	StarknetAggregatorSalt  string
}

// StarknetConfig returns the Starknet configuration
func StarknetConfig() *StarknetConfiguration {
	return &StarknetConfiguration{
		AccountClassHash:        viper.GetString("STARKNET_ACCOUNT_CLASS_HASH"),
		StarknetPaymasterURL:    viper.GetString("STARKNET_PAYMASTER_URL"),
		StarknetClientURL:       viper.GetString("STARKNET_CLIENT_URL"),
		StarknetPaymasterAPIKey: viper.GetString("STARKNET_PAYMASTER_API_KEY"),
		StarknetAggregatorSalt:  viper.GetString("STARKNET_AGGREGATOR_SALT"),
	}
}
