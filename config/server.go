package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// ServerConfiguration type defines the server configurations
type ServerConfiguration struct {
	Debug                     bool
	Host                      string
	Port                      string
	Timezone                  string
	AllowedHosts              string
	Environment               string
	SentryDSN                 string
	HostDomain                string
	RateLimitUnauthenticated  int
	RateLimitAuthenticated    int
	CurrenciesCacheDuration   int
	InstitutionsCacheDuration int
	PubKeyCacheDuration       int
	ServerURL                 string
	SlackWebhookURL           string
}

// ServerConfig sets the server configuration
func ServerConfig() *ServerConfiguration {
	viper.SetDefault("DEBUG", true)
	viper.SetDefault("SERVER_HOST", "0.0.0.0")
	viper.SetDefault("SERVER_PORT", "8000")
	viper.SetDefault("SERVER_TIMEZONE", "Africa/Lagos")
	viper.SetDefault("ALLOWED_HOSTS", "*")
	viper.SetDefault("ENVIRONMENT", "local")
	viper.SetDefault("SENTRY_DSN", "")
	viper.SetDefault("RATE_LIMIT_UNAUTHENTICATED", 5)
	viper.SetDefault("RATE_LIMIT_AUTHENTICATED", 100)
	viper.SetDefault("CURRENCIES_CACHE_DURATION", 24)
	viper.SetDefault("INSTITUTIONS_CACHE_DURATION", 24)
	viper.SetDefault("PUBKEY_CACHE_DURATION", 365)
	viper.SetDefault("SERVER_URL", "")
	viper.SetDefault("SLACK_WEBHOOK_URL", "")

	return &ServerConfiguration{
		Debug:                     viper.GetBool("DEBUG"),
		Host:                      viper.GetString("SERVER_HOST"),
		Port:                      viper.GetString("SERVER_PORT"),
		Timezone:                  viper.GetString("SERVER_TIMEZONE"),
		AllowedHosts:              viper.GetString("ALLOWED_HOSTS"),
		Environment:               viper.GetString("ENVIRONMENT"),
		SentryDSN:                 viper.GetString("SENTRY_DSN"),
		ServerURL:                 viper.GetString("SERVER_URL"),
		HostDomain:                viper.GetString("HOST_DOMAIN"),
		RateLimitUnauthenticated:  viper.GetInt("RATE_LIMIT_UNAUTHENTICATED"),
		RateLimitAuthenticated:    viper.GetInt("RATE_LIMIT_AUTHENTICATED"),
		SlackWebhookURL:           viper.GetString("SLACK_WEBHOOK_URL"),
		CurrenciesCacheDuration:   viper.GetInt("CURRENCIES_CACHE_DURATION"),
		InstitutionsCacheDuration: viper.GetInt("INSTITUTIONS_CACHE_DURATION"),
		PubKeyCacheDuration:       viper.GetInt("PUBKEY_CACHE_DURATION"),
	}
}

func init() {
	if err := SetupConfig(); err != nil {
		panic(fmt.Sprintf("config SetupConfig() error: %s", err))
	}
}
