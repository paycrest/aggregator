package storage

import (
	"context"
	"fmt"

	"github.com/paycrest/aggregator/config"
	"github.com/redis/go-redis/v9"
)

var (
	// Client holds the Redis client
	RedisClient *redis.Client
)

// InitializeRedis initializes the Redis client
func InitializeRedis() error {
	redisConf := config.RedisConfig()

	// Create a Redis client
	RedisClient = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", redisConf.Host, redisConf.Port),
		Password: redisConf.Password,
		DB:       redisConf.DB,
	})

	// Ping Redis to check the connection
	if _, err := RedisClient.Ping(context.Background()).Result(); err != nil {
		return err
	}

	return nil
}
