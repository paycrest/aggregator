package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// RedisConfiguration type defines the Redis configurations
type RedisConfiguration struct {
	Host     string
	Port     string
	Username string
	Password string
	DB       int
	UseTLS   bool
}

// RedisConfig retrieves the Redis configuration
func RedisConfig() RedisConfiguration {
	viper.SetDefault("REDIS_TLS", false)
	viper.SetDefault("REDIS_USERNAME", "")
	return RedisConfiguration{
		Host:     viper.GetString("REDIS_HOST"),
		Port:     viper.GetString("REDIS_PORT"),
		Username: viper.GetString("REDIS_USERNAME"),
		Password: viper.GetString("REDIS_PASSWORD"),
		DB:       viper.GetInt("REDIS_DB"),
		UseTLS:   viper.GetBool("REDIS_TLS"),
	}
}

func init() {
	if err := SetupConfig(); err != nil {
		panic(fmt.Sprintf("config SetupConfig() error: %s", err))
	}
}
