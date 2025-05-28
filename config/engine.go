package config

import (
	"github.com/spf13/viper"
)

// EngineConfiguration holds the configuration for Engine integration
type EngineConfiguration struct {
	BaseURL     string
	AccessToken string
}

// EngineConfig returns the Engine configuration
func EngineConfig() *EngineConfiguration {
	return &EngineConfiguration{
		BaseURL:     viper.GetString("ENGINE_BASE_URL"),
		AccessToken: viper.GetString("ENGINE_ACCESS_TOKEN"),
	}
}
