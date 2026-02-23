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
	AggregatorEVMPrivateKey   string
	AggregatorAccountStarknet string
	MessageHashMaxSize        int
}

// CryptoConfig sets the crypto configuration
func CryptoConfig() *CryptoConfiguration {

	viper.SetDefault("MESSAGE_HASH_MAX_SIZE", 500)

	return &CryptoConfiguration{
		HDWalletMnemonic:          viper.GetString("HD_WALLET_MNEMONIC"),
		AggregatorPublicKey:       viper.GetString("AGGREGATOR_PUBLIC_KEY"),
		AggregatorPrivateKey:      viper.GetString("AGGREGATOR_PRIVATE_KEY"),
		AggregatorAccountEVM:      viper.GetString("AGGREGATOR_ACCOUNT_EVM"),
		AggregatorEVMPrivateKey:   viper.GetString("AGGREGATOR_EVM_PRIVATE_KEY"),
		AggregatorAccountStarknet: viper.GetString("AGGREGATOR_ACCOUNT_STARKNET"),
		MessageHashMaxSize:        viper.GetInt("MESSAGE_HASH_MAX_SIZE"),
	}
}

func init() {
	if err := SetupConfig(); err != nil {
		panic(fmt.Sprintf("config SetupConfig() error: %s", err))
	}
}
