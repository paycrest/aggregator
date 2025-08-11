package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/cosmos/go-bip39"
	"github.com/shopspring/decimal"
	"github.com/spf13/viper"
)

type Configuration struct {
	Server       ServerConfiguration
	Database     DatabaseConfiguration
	Auth         AuthConfiguration
	Order        OrderConfiguration
	Notification NotificationConfiguration
	Engine       EngineConfiguration
	Etherscan    EtherscanConfiguration
	Balance      BalanceConfiguration
}

func SetupConfig() error {
	var configuration *Configuration

	viper.AddConfigPath("../../../..")
	viper.AddConfigPath("../../..")
	viper.AddConfigPath("../..")
	viper.AddConfigPath("..")
	viper.AddConfigPath(".")

	envFilePath := os.Getenv("ENV_FILE_PATH")
	if envFilePath == "" {
		envFilePath = ".env"
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

	balanceConfig := NewBalanceConfiguration()
	
	if redisEnabled := os.Getenv("BALANCE_REDIS_ENABLED"); redisEnabled != "" {
		balanceConfig.RedisEnabled = redisEnabled == "true"
	}
	if redisTTL := os.Getenv("BALANCE_REDIS_TTL"); redisTTL != "" {
		if ttl, err := time.ParseDuration(redisTTL); err == nil {
			balanceConfig.RedisTTL = ttl
		}
	}
	if maxRetries := os.Getenv("BALANCE_REDIS_MAX_RETRIES"); maxRetries != "" {
		if retries, err := strconv.Atoi(maxRetries); err == nil {
			balanceConfig.RedisMaxRetries = retries
		}
	}
	if monitoringEnabled := os.Getenv("BALANCE_MONITORING_ENABLED"); monitoringEnabled != "" {
		balanceConfig.MonitoringEnabled = monitoringEnabled == "true"
	}
	if checkInterval := os.Getenv("BALANCE_MONITORING_CHECK_INTERVAL"); checkInterval != "" {
		if interval, err := time.ParseDuration(checkInterval); err == nil {
			balanceConfig.MonitoringCheckInterval = interval
		}
	}
	if emailEnabled := os.Getenv("BALANCE_MONITORING_EMAIL_ENABLED"); emailEnabled != "" {
		balanceConfig.MonitoringEmailEnabled = emailEnabled == "true"
	}
	
	if defaultMin := os.Getenv("BALANCE_DEFAULT_MINIMUM"); defaultMin != "" {
		if min, err := decimal.NewFromString(defaultMin); err == nil {
			balanceConfig.DefaultMinimumBalance = min
		}
	}
	if defaultAlert := os.Getenv("BALANCE_DEFAULT_ALERT"); defaultAlert != "" {
		if alert, err := decimal.NewFromString(defaultAlert); err == nil {
			balanceConfig.DefaultAlertThreshold = alert
		}
	}
	if defaultCritical := os.Getenv("BALANCE_DEFAULT_CRITICAL"); defaultCritical != "" {
		if critical, err := decimal.NewFromString(defaultCritical); err == nil {
			balanceConfig.DefaultCriticalThreshold = critical
		}
	}
	
	configuration.Balance = *balanceConfig

	var cryptoConf = CryptoConfig()

	valid := bip39.IsMnemonicValid(cryptoConf.HDWalletMnemonic)
	if !valid {
		fmt.Printf("Invalid mnemonic phrase")
		return nil
	}

	return nil
}
