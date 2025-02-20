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
	log.Println("Connecting to the database")
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
	log.Println("Initialize Redis")
	if err := storage.InitializeRedis(); err != nil {
		log.Println(err)
		logger.Fatalf("Redis initialization: %v", err)
	}

	// Subscribe to Redis keyspace events
	log.Println("Subscribe to Redis keyspace events")
	tasks.SubscribeToRedisKeyspaceEvents()

	// Start cron jobs
	log.Println("cron jobs")
	tasks.StartCronJobs()

	// Run the server
	log.Println("run server")
	router := routers.Routes()

	log.Println("done with server")

	appServer := fmt.Sprintf("%s:%s", conf.Host, conf.Port)
	logger.Infof("Server Running at :%v", appServer)

	logger.Fatalf("%v", router.Run(appServer))
}
