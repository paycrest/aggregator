package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// CryptoConfiguration type defines crypto configurations
type CryptoConfiguration struct {
	HDWalletMnemonic       string
	AggregatorPublicKey    string
	AggregatorPrivateKey   string
	AggregatorSmartAccount string
}

// CryptoConfig sets the crypto configuration
func CryptoConfig() *CryptoConfiguration {

	return &CryptoConfiguration{
		HDWalletMnemonic:       viper.GetString("HD_WALLET_MNEMONIC"),
		AggregatorPublicKey:    viper.GetString("AGGREGATOR_PUBLIC_KEY"),
		AggregatorPrivateKey:   viper.GetString("AGGREGATOR_PRIVATE_KEY"),
		AggregatorSmartAccount: viper.GetString("AGGREGATOR_SMART_ACCOUNT"),
	}
}

func init() {
	if err := SetupConfig(); err != nil {
		panic(fmt.Sprintf("config SetupConfig() error: %s", err))
	}
}
