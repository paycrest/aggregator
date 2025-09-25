package config

import (
	"github.com/spf13/viper"
)

// EngineConfiguration holds the configuration for Engine integration
type EngineConfiguration struct {
	BaseURL           string
	AccessToken       string
	ThirdwebSecretKey string
}

// EngineConfig returns the Engine configuration
func EngineConfig() *EngineConfiguration {
	return &EngineConfiguration{
		BaseURL:           viper.GetString("ENGINE_BASE_URL"),
		AccessToken:       viper.GetString("ENGINE_ACCESS_TOKEN"),
		ThirdwebSecretKey: viper.GetString("THIRDWEB_SECRET_KEY"),
	}
}
