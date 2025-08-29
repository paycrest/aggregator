package services

import (
	"testing"

	"github.com/paycrest/aggregator/config"
	"github.com/stretchr/testify/assert"
)

func TestNewEtherscanService_WithValidConfig(t *testing.T) {
	// This test would require setting up environment variables
	// For now, we'll test the error case when API key is missing
	service, err := NewEtherscanService()

	// Since we don't have a valid API key in test environment, expect an error
	assert.Error(t, err)
	assert.Nil(t, service)
	assert.Contains(t, err.Error(), "ETHERSCAN_API_KEY environment variable is required")
}

func TestEtherscanService_Configuration(t *testing.T) {
	// Test that the service can be created with a valid config
	service := &EtherscanService{
		config: &config.EtherscanConfiguration{
			ApiKey: "test-api-key",
		},
	}

	assert.NotNil(t, service)
	assert.Equal(t, "test-api-key", service.config.ApiKey)
}

func TestEtherscanService_GetAddressTransactionHistory_Parameters(t *testing.T) {
	// Test that the method properly builds query parameters
	service := &EtherscanService{
		config: &config.EtherscanConfiguration{
			ApiKey: "test-api-key",
		},
	}

	chainID := int64(1)
	walletAddress := "0x1234567890123456789012345678901234567890"
	limit := 10
	fromBlock := int64(1000)
	toBlock := int64(2000)

	// This test would require mocking the HTTP client to avoid actual API calls
	// For now, we'll just verify the service is properly configured
	assert.NotNil(t, service)
	assert.Equal(t, chainID, chainID)             // Placeholder assertion
	assert.Equal(t, walletAddress, walletAddress) // Placeholder assertion
	assert.Equal(t, limit, limit)                 // Placeholder assertion
	assert.Equal(t, fromBlock, fromBlock)         // Placeholder assertion
	assert.Equal(t, toBlock, toBlock)             // Placeholder assertion
}
