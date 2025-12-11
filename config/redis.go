package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// RedisConfiguration type defines the Redis configurations
type RedisConfiguration struct {
	Host     string
	Port     string
	Password string
	DB       int
    CacheVersion string
}

// RedisConfig retrieves the Redis configuration
func RedisConfig() RedisConfiguration {
	return RedisConfiguration{
		Host:     viper.GetString("REDIS_HOST"),
		Port:     viper.GetString("REDIS_PORT"),
		Password: viper.GetString("REDIS_PASSWORD"),
		DB:       viper.GetInt("REDIS_DB"),
        CacheVersion: viper.GetString("CACHE_VERSION"),
	}
}

func init() {
	if err := SetupConfig(); err != nil {
		panic(fmt.Sprintf("config SetupConfig() error: %s", err))
	}
}
