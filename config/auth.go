package config

import (
	"fmt"
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

	// Turnstile config
	TurnstileSiteKey   string
	TurnstileSecretKey string
	TurnstileEnabled   bool
}

// AuthConfig sets the authentication & authorization configurations
func AuthConfig() (config *AuthConfiguration) {
	viper.SetDefault("JWT_ACCESS_LIFESPAN", 15)     // 15 minutes
	viper.SetDefault("JWT_REFRESH_LIFESPAN", 10080) // 7 days
	viper.SetDefault("HMAC_TIMESTAMP_AGE", 5)
	viper.SetDefault("PASSWORD_RESET_LIFESPAN", 5)

	// Turnstile defaults
	viper.SetDefault("TURNSTILE_ENABLED", true)
	viper.SetDefault("TURNSTILE_SITE_KEY", "")
	viper.SetDefault("TURNSTILE_SECRET_KEY", "")

	return &AuthConfiguration{
		Secret:                viper.GetString("SECRET"),
		JwtAccessLifespan:     time.Duration(viper.GetInt("JWT_ACCESS_LIFESPAN")) * time.Minute,
		JwtRefreshLifespan:    time.Duration(viper.GetInt("JWT_REFRESH_LIFESPAN")) * time.Minute,
		HmacTimestampAge:      time.Duration(viper.GetInt("HMAC_TIMESTAMP_AGE")) * time.Minute,
		PasswordResetLifespan: time.Duration(viper.GetInt("PASSWORD_RESET_LIFESPAN")) * time.Minute,
		TurnstileSiteKey:      viper.GetString("TURNSTILE_SITE_KEY"),
		TurnstileSecretKey:    viper.GetString("TURNSTILE_SECRET_KEY"),
		TurnstileEnabled:      viper.GetBool("TURNSTILE_ENABLED"),
	}
}

func init() {
	if err := SetupConfig(); err != nil {
		panic(fmt.Sprintf("config SetupConfig() error: %s", err))
	}
}
