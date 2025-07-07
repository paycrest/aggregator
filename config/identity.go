package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// IdentityConfiguration defines the identity provider configurations
type IdentityConfiguration struct {
	SmileIdentityBaseUrl   string
	SmileIdentityPartnerId string
	SmileIdentityApiKey    string
	PrivyAppID             string
	PrivyVerificationKey   string
}

// IdentityConfig sets the identity provider configurations
func IdentityConfig() (config *IdentityConfiguration) {

	return &IdentityConfiguration{
		SmileIdentityBaseUrl:   viper.GetString("SMILE_IDENTITY_BASE_URL"),
		SmileIdentityPartnerId: viper.GetString("SMILE_IDENTITY_PARTNER_ID"),
		SmileIdentityApiKey:    viper.GetString("SMILE_IDENTITY_API_KEY"),
		PrivyAppID:             viper.GetString("PRIVY_APP_ID"),
		PrivyVerificationKey:   viper.GetString("PRIVY_VERIFICATION_KEY"),
	}
}

func init() {
	if err := SetupConfig(); err != nil {
		panic(fmt.Sprintf("config SetupConfig() error: %s", err))
	}
}
