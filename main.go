package main

import (
	"fmt"
	"log"
	"time"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/routers"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/tasks"
	"github.com/paycrest/aggregator/utils/logger"
)

func main() {
	// Set timezone
	conf := config.ServerConfig()
	loc, _ := time.LoadLocation(conf.Timezone)
	time.Local = loc

	// Connect to the database
	DSN := config.DBConfig()
	fmt.Println("start")
	if err := storage.DBConnection(DSN); err != nil {
		fmt.Println(err)
		logger.Fatalf("database DBConnection: %s", err)
	}
    fmt.Println("start2")
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
