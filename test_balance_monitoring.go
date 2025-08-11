package main

import (
	"fmt"
	"log"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/storage"
)

func main() {
	fmt.Println("Testing Balance Monitoring Service...")

	DSN := config.DBConfig()
	if err := storage.DBConnection(DSN); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer storage.GetClient().Close()

	balanceConfig := config.NewBalanceConfiguration()
	
	balanceConfig.SetCurrencyThresholds("NGN", config.CurrencyThresholds{
		MinimumAvailableBalance: balanceConfig.DefaultMinimumBalance,
		AlertThreshold:         balanceConfig.DefaultAlertThreshold,
		CriticalThreshold:      balanceConfig.DefaultCriticalThreshold,
	})

	fmt.Printf("Balance config: %+v\n", balanceConfig)

	balanceMonitoringService := services.NewBalanceMonitoringService(storage.GetClient(), balanceConfig, nil)

	fmt.Println("\nTesting balance monitoring service...")

	status, err := balanceMonitoringService.GetProviderBalanceStatus("AtGaDPqT", "NGN")
	if err != nil {
		log.Printf("Error getting balance status: %v", err)
	} else {
		fmt.Printf("Provider AtGaDPqT NGN balance status: %s\n", *status)
	}

	isSufficient, err := balanceMonitoringService.IsProviderBalanceSufficient("AtGaDPqT", "NGN")
	if err != nil {
		log.Printf("Error checking balance sufficiency: %v", err)
	} else {
		fmt.Printf("Provider AtGaDPqT NGN balance sufficient: %v\n", isSufficient)
	}

	fmt.Printf("\nNGN thresholds:\n")
	fmt.Printf("  Minimum: %s\n", balanceConfig.GetMinimumBalance("NGN"))
	fmt.Printf("  Alert: %s\n", balanceConfig.GetAlertThreshold("NGN"))
	fmt.Printf("  Critical: %s\n", balanceConfig.GetCriticalThreshold("NGN"))

	fmt.Println("\nTest completed successfully!")
} 