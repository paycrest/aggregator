package config

import (
	"sync"

	"github.com/spf13/viper"
)

var (
	voyagerConfigOnce sync.Once
)

// VoyagerConfiguration holds the configuration for Voyager API integration
type VoyagerConfiguration struct {
	ApiKey       string
	RateLimit    int // Requests per second per worker (default: 10 for Basic plan)
	MonthlyLimit int // Maximum API calls per month (default: 300000 for Basic plan)
}

// VoyagerConfig returns the Voyager configuration
func VoyagerConfig() *VoyagerConfiguration {
	// Set defaults only once, even when called concurrently from multiple goroutines
	voyagerConfigOnce.Do(func() {
		viper.SetDefault("VOYAGER_RATE_LIMIT", 10)
		viper.SetDefault("VOYAGER_MONTHLY_LIMIT", 300000) // Default: 300k for Basic plan
	})

	return &VoyagerConfiguration{
		ApiKey:       viper.GetString("VOYAGER_API_KEY"),
		RateLimit:    viper.GetInt("VOYAGER_RATE_LIMIT"),
		MonthlyLimit: viper.GetInt("VOYAGER_MONTHLY_LIMIT"),
	}
}
