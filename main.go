package main

import (
	"fmt"
	"log"
	"time"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/routers"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/tasks"
	"github.com/paycrest/aggregator/utils/logger"
)

func main() {
	// Set timezone with fallback options
	conf := config.ServerConfig()
	loc, err := time.LoadLocation(conf.Timezone)
	if err != nil {
		// Try fallback timezones if the configured one fails
		fallbackTimezones := []string{"UTC", "GMT", "America/New_York"}
		
		for _, fallback := range fallbackTimezones {
			if fallbackLoc, fallbackErr := time.LoadLocation(fallback); fallbackErr == nil {
				logger.Warnf("Failed to load configured timezone %s, using fallback: %s", conf.Timezone, fallback)
				loc = fallbackLoc
				break
			}
		}
		
		// If all fallbacks fail, use UTC as last resort
		if loc == nil {
			logger.Errorf("All timezone fallbacks failed, using UTC as last resort. Error: %v", err)
			loc = time.UTC
		}
	}
	
	time.Local = loc

	// Connect to the database
	DSN := config.DBConfig()
	if err := storage.DBConnection(DSN); err != nil {
		logger.Fatalf("database DBConnection: %s", err)
	}
	defer storage.GetClient().Close()

	// Fix database mishap
	// err := tasks.FixDatabaseMishap()
	// if err != nil {
	// 	logger.Errorf("FixDatabaseMishap: %v", err)
	// }

	// Fetch provider balances
	err = tasks.FetchProviderBalances()
	if err != nil {
		logger.Errorf("Failed to fetch provider balances: %v", err)
	}

	// Initialize Redis
	if err := storage.InitializeRedis(); err != nil {
		log.Println(err)
		logger.Fatalf("Redis initialization: %v", err)
	}

	// Setup gateway webhooks for all EVM networks
	engineService := services.NewEngineService()
	err = engineService.CreateGatewayWebhook()
	if err != nil {
		logger.Errorf("Failed to create gateway webhooks: %v", err)
	}

	// Subscribe to Redis keyspace events
	tasks.SubscribeToRedisKeyspaceEvents()

	// Start cron jobs
	tasks.StartCronJobs()

	// Run the server
	router := routers.Routes()

	appServer := fmt.Sprintf("%s:%s", conf.Host, conf.Port)
	logger.Infof("Server Running at :%v", appServer)

	logger.Fatalf("%v", router.Run(appServer))
}
