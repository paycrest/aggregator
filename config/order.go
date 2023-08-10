package config

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/paycrest/paycrest-protocol/utils/logger"
	"github.com/spf13/viper"
)

// OrderConfiguration type defines payment order configurations
type OrderConfiguration struct {
	ReceiveAddressValidity       time.Duration
	PaycrestOrderContractAddress common.Address
	BundlerRPCURL                string
	PaymasterURL                 string
	EntryPointContractAddress    common.Address
}

// OrderConfig sets the order configuration
func OrderConfig() *OrderConfiguration {
	viper.SetDefault("RECEIVE_ADDRESS_VALIDITY", 30)

	return &OrderConfiguration{
		ReceiveAddressValidity:       time.Duration(viper.GetInt("RECEIVE_ADDRESS_VALIDITY")) * time.Minute,
		PaycrestOrderContractAddress: common.HexToAddress(viper.GetString("PAYCREST_ORDER_CONTRACT_ADDRESS")),
		BundlerRPCURL:                viper.GetString("BUNDLER_RPC_URL"),
		PaymasterURL:                 viper.GetString("PAYMASTER_URL"),
		EntryPointContractAddress:    common.HexToAddress(viper.GetString("ENTRY_POINT_CONTRACT_ADDRESS")),
	}
}

func init() {
	if err := SetupConfig(); err != nil {
		logger.Fatalf("config SetupConfig() error: %s", err)
	}
}
