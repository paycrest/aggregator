package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// CryptoConfiguration type defines crypto configurations
type CryptoConfiguration struct {
	HDWalletMnemonic          string
	AggregatorPublicKey       string
	AggregatorPrivateKey      string
	AggregatorAccountEVM      string
	AggregatorAccountStarknet string
}

// CryptoConfig sets the crypto configuration
func CryptoConfig() *CryptoConfiguration {

	return &CryptoConfiguration{
		HDWalletMnemonic:          viper.GetString("HD_WALLET_MNEMONIC"),
		AggregatorPublicKey:       viper.GetString("AGGREGATOR_PUBLIC_KEY"),
		AggregatorPrivateKey:      viper.GetString("AGGREGATOR_PRIVATE_KEY"),
		AggregatorAccountEVM:      viper.GetString("AGGREGATOR_ACCOUNT_EVM"),
		AggregatorAccountStarknet: viper.GetString("AGGREGATOR_ACCOUNT_STARKNET"),
	}
}

func init() {
	if err := SetupConfig(); err != nil {
		panic(fmt.Sprintf("config SetupConfig() error: %s", err))
	}
}
