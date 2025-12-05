package config

import (
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/shopspring/decimal"
	"github.com/spf13/viper"
)

// OrderConfiguration type defines payment order configurations
type OrderConfiguration struct {
	OrderFulfillmentValidity         time.Duration
	OrderFulfillmentValidityOtc      time.Duration
	OrderRefundTimeout               time.Duration
	OrderRefundTimeoutOtc            time.Duration
	ReceiveAddressValidity           time.Duration
	OrderRequestValidity             time.Duration
	OrderRequestValidityOtc          time.Duration
	TronProApiKey                    string
	EntryPointContractAddress        common.Address
	BucketQueueRebuildInterval       int
	RefundCancellationCount          int
	PercentDeviationFromExternalRate decimal.Decimal
	PercentDeviationFromMarketRate   decimal.Decimal
	IndexingDuration                 time.Duration
}

// OrderConfig sets the order configuration
func OrderConfig() *OrderConfiguration {
	viper.SetDefault("RECEIVE_ADDRESS_VALIDITY", 1800)
	viper.SetDefault("ORDER_REQUEST_VALIDITY", 30)
	viper.SetDefault("ORDER_REQUEST_VALIDITY_OTC", 300)
	viper.SetDefault("ORDER_FULFILLMENT_VALIDITY", 60)
	viper.SetDefault("ORDER_FULFILLMENT_VALIDITY_OTC", 1800)
	viper.SetDefault("ORDER_REFUND_TIMEOUT", 300)
	viper.SetDefault("ORDER_REFUND_TIMEOUT_OTC", 5400)
	viper.SetDefault("BUCKET_QUEUE_REBUILD_INTERVAL", 1)
	viper.SetDefault("REFUND_CANCELLATION_COUNT", 3)
	viper.SetDefault("NETWORK_FEE", 0.05)
	viper.SetDefault("PERCENT_DEVIATION_FROM_EXTERNAL_RATE", 0.01)
	viper.SetDefault("PERCENT_DEVIATION_FROM_MARKET_RATE", 0.1)
	viper.SetDefault("INDEXING_DURATION", 10)

	return &OrderConfiguration{
		OrderFulfillmentValidity:         time.Duration(viper.GetInt("ORDER_FULFILLMENT_VALIDITY")) * time.Second,
		OrderFulfillmentValidityOtc:      time.Duration(viper.GetInt("ORDER_FULFILLMENT_VALIDITY_OTC")) * time.Second,
		OrderRefundTimeout:               time.Duration(viper.GetInt("ORDER_REFUND_TIMEOUT")) * time.Second,
		OrderRefundTimeoutOtc:            time.Duration(viper.GetInt("ORDER_REFUND_TIMEOUT_OTC")) * time.Second,
		ReceiveAddressValidity:           time.Duration(viper.GetInt("RECEIVE_ADDRESS_VALIDITY")) * time.Second,
		OrderRequestValidity:             time.Duration(viper.GetInt("ORDER_REQUEST_VALIDITY")) * time.Second,
		OrderRequestValidityOtc:          time.Duration(viper.GetInt("ORDER_REQUEST_VALIDITY_OTC")) * time.Second,
		TronProApiKey:                    viper.GetString("TRON_PRO_API_KEY"),
		EntryPointContractAddress:        common.HexToAddress(viper.GetString("ENTRY_POINT_CONTRACT_ADDRESS")),
		BucketQueueRebuildInterval:       viper.GetInt("BUCKET_QUEUE_REBUILD_INTERVAL"),
		RefundCancellationCount:          viper.GetInt("REFUND_CANCELLATION_COUNT"),
		PercentDeviationFromExternalRate: decimal.NewFromFloat(viper.GetFloat64("PERCENT_DEVIATION_FROM_EXTERNAL_RATE")),
		PercentDeviationFromMarketRate:   decimal.NewFromFloat(viper.GetFloat64("PERCENT_DEVIATION_FROM_MARKET_RATE")),
		IndexingDuration:                 time.Duration(viper.GetInt("INDEXING_DURATION")) * time.Second,
	}
}

func init() {
	if err := SetupConfig(); err != nil {
		panic(fmt.Sprintf("config SetupConfig() error: %s", err))
	}
}
