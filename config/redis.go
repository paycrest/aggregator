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
}

// RedisConfig retrieves the Redis configuration
func RedisConfig() RedisConfiguration {
	return RedisConfiguration{
		Host:     viper.GetString("REDIS_HOST"),
		Port:     viper.GetString("REDIS_PORT"),
		Password: viper.GetString("REDIS_PASSWORD"),
		DB:       viper.GetInt("REDIS_DB"),
	}
}

func init() {
	if err := SetupConfig(); err != nil {
		panic(fmt.Sprintf("config SetupConfig() error: %s", err))
	}
}
