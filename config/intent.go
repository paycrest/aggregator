package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// IntentConfiguration defines the intent service configurations
type IntentConfiguration struct {
	OneclickURL  string
	OneclickAuth string
}

// IntentConfig sets the intent service configurations
func IntentConfig() *IntentConfiguration {
	return &IntentConfiguration{
		OneclickURL:  viper.GetString("ONECLICK_URL"),
		OneclickAuth: viper.GetString("ONECLICK_AUTH"),
	}
}

// Env is a singleton instance of IntentConfiguration
var Env *IntentConfiguration

func init() {
	if err := SetupConfig(); err != nil {
		panic(fmt.Sprintf("config SetupConfig() error: %s", err))
	}
	Env = IntentConfig()
}
