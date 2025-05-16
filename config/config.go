package config

import (
	"fmt"
	"os"

	"github.com/cosmos/go-bip39"
	"github.com/spf13/viper"
)

// Configuration type
type Configuration struct {
	Server       ServerConfiguration
	Database     DatabaseConfiguration
	Auth         AuthConfiguration
	Order        OrderConfiguration
	Notification NotificationConfiguration
}

// SetupConfig configuration
func SetupConfig() error {
	var configuration *Configuration

	viper.AddConfigPath("../../../..")
	viper.AddConfigPath("../../..")
	viper.AddConfigPath("../..")
	viper.AddConfigPath("..")
	viper.AddConfigPath(".")

	envFilePath := os.Getenv("ENV_FILE_PATH")
	if envFilePath == "" {
		envFilePath = ".env" // Set default value to ".env"
	}

	viper.SetConfigName(envFilePath)
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error to reading config file, %s", err)
		return err
	}

	err := viper.Unmarshal(&configuration)
	if err != nil {
		fmt.Printf("error to decode, %v", err)
		return err
	}

	var cryptoConf = CryptoConfig()

	valid := bip39.IsMnemonicValid(cryptoConf.HDWalletMnemonic)
	if !valid {
		fmt.Printf("Invalid mnemonic phrase")
		return nil
	}

	return nil
}
