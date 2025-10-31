// Package config provides configuration management for the aggregator service
package config

import "github.com/spf13/viper"

// HederaConfiguration type defines Hedera-specific configurations
type HederaConfiguration struct {
	PrivateKey      string
	GatewayContract string
	RPCURL          string
	MirrorNodeURL   string
}

// HederaConfig returns the Hedera configuration
func HederaConfig() *HederaConfiguration {
	return &HederaConfiguration{
		PrivateKey:      viper.GetString("HEDERA_PRIVATE_KEY"),
		GatewayContract: viper.GetString("HEDERA_GATEWAY_CONTRACT"),
		RPCURL:          viper.GetString("HEDERA_RPC_URL"),
		MirrorNodeURL:   viper.GetString("HEDERA_MIRROR_NODE_URL"),
	}
}
