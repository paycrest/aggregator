package storage

import (
	"context"
	"crypto/tls"
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

	opts := &redis.Options{
		Addr:     fmt.Sprintf("%s:%s", redisConf.Host, redisConf.Port),
		Username: redisConf.Username,
		Password: redisConf.Password,
		DB:       redisConf.DB,
	}
	if redisConf.UseTLS {
		opts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: redisConf.Host,
		}
	}

	RedisClient = redis.NewClient(opts)

	// Ping Redis to check the connection
	if _, err := RedisClient.Ping(context.Background()).Result(); err != nil {
		return err
	}

	return nil
}
