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
	BitgetAccessKey       string
	BitgetSecretKey       string
	BitgetPassphrase      string
}

// AuthConfig sets the authentication & authorization configurations
func AuthConfig() (config *AuthConfiguration) {
	viper.SetDefault("JWT_ACCESS_LIFESPAN", 15)     // 15 minutes
	viper.SetDefault("JWT_REFRESH_LIFESPAN", 10080) // 7 days
	viper.SetDefault("HMAC_TIMESTAMP_AGE", 5)
	viper.SetDefault("PASSWORD_RESET_LIFESPAN", 5)
	viper.SetDefault("BITGET_ACCESS_KEY", "")
	viper.SetDefault("BITGET_SECRET_KEY", "")
	viper.SetDefault("BITGET_PASSPHRASE", "")

	return &AuthConfiguration{
		Secret:                viper.GetString("SECRET"),
		JwtAccessLifespan:     time.Duration(viper.GetInt("JWT_ACCESS_LIFESPAN")) * time.Minute,
		JwtRefreshLifespan:    time.Duration(viper.GetInt("JWT_REFRESH_LIFESPAN")) * time.Minute,
		HmacTimestampAge:      time.Duration(viper.GetInt("HMAC_TIMESTAMP_AGE")) * time.Minute,
		PasswordResetLifespan: time.Duration(viper.GetInt("PASSWORD_RESET_LIFESPAN")) * time.Minute,
		BitgetAccessKey:       viper.GetString("BITGET_ACCESS_KEY"),
		BitgetSecretKey:       viper.GetString("BITGET_SECRET_KEY"),
		BitgetPassphrase:      viper.GetString("BITGET_PASSPHRASE"),
	}
}

func init() {
	if err := SetupConfig(); err != nil {
		panic(fmt.Sprintf("config SetupConfig() error: %s", err))
	}
}
