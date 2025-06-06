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
	// Use uint64 for block numbers to avoid floating point issues
	latestBlock := uint64(26412000)

	// Constants
	const (
		blockTimeSeconds = 2
		maxChunkSize     = 1000
	)

	// Calculate blocks in given duration
	duration := 2 * time.Hour
	blocksPerSecond := float64(1) / blockTimeSeconds
	blocksInDuration := uint64(blocksPerSecond * float64(duration.Seconds()))

	// Calculate start block
	startBlock := latestBlock - blocksInDuration
	endBlock := latestBlock

	// Process blocks in chunks
	for currentBlock := startBlock; currentBlock < endBlock; currentBlock += maxChunkSize {
		chunkEnd := currentBlock + maxChunkSize - 1
		if chunkEnd > endBlock {
			chunkEnd = endBlock
		}

		fmt.Printf("Processing blocks %d to %d\n", currentBlock, chunkEnd)
	}

	// Set timezone
	conf := config.ServerConfig()
	loc, _ := time.LoadLocation(conf.Timezone)
	time.Local = loc

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
