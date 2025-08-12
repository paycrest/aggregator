package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// NotificationConfiguration defines the email service configurations
type NotificationConfiguration struct {
	EmailDomain      string
	EmailAPIKey      string
	EmailFromAddress string
	EmailProvider    string
}

// NotificationConfig sets the email configurations
func NotificationConfig() (config *NotificationConfiguration) {
	viper.SetDefault("EMAIL_DOMAIN", "api.brevo.com")
	viper.SetDefault("EMAIL_FROM_ADDRESS", "Paycrest <no-reply@paycrest.io>")
	viper.SetDefault("EMAIL_PROVIDER", "brevo")

	return &NotificationConfiguration{
		EmailDomain:      viper.GetString("EMAIL_DOMAIN"),
		EmailAPIKey:      viper.GetString("EMAIL_API_KEY"),
		EmailFromAddress: viper.GetString("EMAIL_FROM_ADDRESS"),
		EmailProvider:    viper.GetString("EMAIL_PROVIDER"),
	}
}

func init() {
	if err := SetupConfig(); err != nil {
		panic(fmt.Sprintf("config SetupConfig() error: %s", err))
	}
}
