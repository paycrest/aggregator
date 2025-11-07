// Package config provides configuration management for the aggregator service
package config

import "github.com/spf13/viper"

// HederaConfiguration type defines Hedera-specific configurations
type HederaConfiguration struct {
	PrivateKey     string
	ReceiveAddress string
}

// HederaConfig returns the Hedera configuration
func HederaConfig() *HederaConfiguration {
	return &HederaConfiguration{
		PrivateKey:     viper.GetString("HEDERA_PRIVATE_KEY"),
		ReceiveAddress: viper.GetString("HEDERA_RECEIVE_ADDRESS"),
	}
}
