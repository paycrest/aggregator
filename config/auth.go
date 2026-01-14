package config

import (
	"fmt"
	"sync"
	"time"

	"github.com/spf13/viper"
)

// AuthConfiguration defines the authentication & authorization settings
type AuthConfiguration struct {
	Secret                string
	JwtAccessLifespan     time.Duration
	JwtRefreshLifespan    time.Duration
	HmacTimestampAge      time.Duration
	PasswordResetLifespan time.Duration

	// Slack config
	SlackSigningSecret string
	SlackBotToken      string

	// Turnstile config
	TurnstileSiteKey   string
	TurnstileSecretKey string
	TurnstileEnabled   bool

	// Partner onboarding config
	PartnerOnboardingSecretKey string
}

var (
	authDefaultsOnce sync.Once
	authConfigOnce   sync.Once
	authConfig       *AuthConfiguration
)

// initAuthDefaults sets the default values for auth configuration.
// This is called once during initialization to avoid concurrent map writes.
func initAuthDefaults() {
	authDefaultsOnce.Do(func() {
		viper.SetDefault("JWT_ACCESS_LIFESPAN", 15)     // 15 minutes
		viper.SetDefault("JWT_REFRESH_LIFESPAN", 10080) // 7 days
		viper.SetDefault("HMAC_TIMESTAMP_AGE", 5)
		viper.SetDefault("PASSWORD_RESET_LIFESPAN", 5)

		// Turnstile defaults
		viper.SetDefault("TURNSTILE_ENABLED", true)
		viper.SetDefault("TURNSTILE_SITE_KEY", "")
		viper.SetDefault("TURNSTILE_SECRET_KEY", "")
	})
}

// AuthConfig returns the authentication & authorization configurations.
// The config is initialized once and cached to avoid concurrent map writes.
func AuthConfig() *AuthConfiguration {
	// Ensure defaults are set (thread-safe)
	initAuthDefaults()

	// Build and cache the config (thread-safe)
	authConfigOnce.Do(func() {
		authConfig = &AuthConfiguration{
			Secret:                  viper.GetString("SECRET"),
			SlackSigningSecret:      viper.GetString("SLACK_SIGNING_SECRET"),
			SlackBotToken:           viper.GetString("SLACK_BOT_TOKEN"),
			JwtAccessLifespan:       time.Duration(viper.GetInt("JWT_ACCESS_LIFESPAN")) * time.Minute,
			JwtRefreshLifespan:      time.Duration(viper.GetInt("JWT_REFRESH_LIFESPAN")) * time.Minute,
			HmacTimestampAge:        time.Duration(viper.GetInt("HMAC_TIMESTAMP_AGE")) * time.Minute,
			PasswordResetLifespan:   time.Duration(viper.GetInt("PASSWORD_RESET_LIFESPAN")) * time.Minute,
			TurnstileSiteKey:        viper.GetString("TURNSTILE_SITE_KEY"),
			TurnstileSecretKey:      viper.GetString("TURNSTILE_SECRET_KEY"),
			TurnstileEnabled:        viper.GetBool("TURNSTILE_ENABLED"),
			PartnerOnboardingSecretKey: viper.GetString("PARTNER_ONBOARDING_SECRET_KEY"),
		}
	})
	return authConfig
}

func init() {
	// Initialize auth defaults during package initialization
	initAuthDefaults()

	if err := SetupConfig(); err != nil {
		panic(fmt.Sprintf("config SetupConfig() error: %s", err))
	}
}
