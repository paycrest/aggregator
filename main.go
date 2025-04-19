package main

import (
	"fmt"
	"log"
	"time"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/routers"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/tasks"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

func main() {
	// Set timezone
	conf := config.ServerConfig()
	loc, _ := time.LoadLocation(conf.Timezone)
	time.Local = loc

	// Validate SmileID config
	if err := config.ValidateSmileIDConfig("./smile_id_types.json"); err != nil {
		logger.Fatalf("Failed to validate SmileID config: %v", err)
	}

	// Load SmileID config
	_, err := utils.LoadSmileIDConfig("./smile_id_types.json")
	if err != nil {
		logger.Fatalf("Failed to load SmileID config: %v", err)
	}

	// Connect to the database
	DSN := config.DBConfig()

	if err := storage.DBConnection(DSN); err != nil {
		logger.Fatalf("database DBConnection: %s", err)
	}

	defer storage.GetClient().Close()

	// err := tasks.FixDatabaseMisHap()
	// if err != nil {
	// 	logger.Errorf("FixDatabaseMisHap: %v", err)
	// }

	// Initialize Redis
	if err := storage.InitializeRedis(); err != nil {
		log.Println(err)
		logger.Fatalf("Redis initialization: %v", err)
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
