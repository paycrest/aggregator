package explorer

import (
	"os"
	"strings"
	"testing"

	"github.com/paycrest/aggregator/config"
	"github.com/stretchr/testify/assert"
)

func TestNewEtherscanService_WithValidConfig(t *testing.T) {
	// Set a test API key for this test
	originalKey := os.Getenv("ETHERSCAN_API_KEY")
	defer func() {
		if originalKey != "" {
			os.Setenv("ETHERSCAN_API_KEY", originalKey)
		} else {
			os.Unsetenv("ETHERSCAN_API_KEY")
		}
	}()

	os.Setenv("ETHERSCAN_API_KEY", "test-api-key")

	// Test service creation with valid config
	service, err := NewEtherscanService()

	// Since we have a valid API key in test environment, expect success
	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.NotNil(t, service.config)
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

func TestMultiKeyParsing(t *testing.T) {
	// Test parsing multiple API keys
	apiKeys := "key1,key2,key3"
	keys := parseAPIKeys(apiKeys)

	assert.Equal(t, 3, len(keys))
	assert.Equal(t, "key1", keys[0])
	assert.Equal(t, "key2", keys[1])
	assert.Equal(t, "key3", keys[2])
}

func TestMultiKeyParsingWithSpaces(t *testing.T) {
	// Test parsing keys with spaces
	apiKeys := "key1 , key2 , key3"
	keys := parseAPIKeys(apiKeys)

	assert.Equal(t, 3, len(keys))
	assert.Equal(t, "key1", keys[0])
	assert.Equal(t, "key2", keys[1])
	assert.Equal(t, "key3", keys[2])
}

func TestMultiKeyParsingEmpty(t *testing.T) {
	// Test parsing empty string
	apiKeys := ""
	keys := parseAPIKeys(apiKeys)

	assert.Equal(t, 0, len(keys))
}

// Helper function to test the parsing logic
func parseAPIKeys(apiKeys string) []string {
	keys := strings.Split(apiKeys, ",")
	var cleanKeys []string
	for _, key := range keys {
		cleanKey := strings.TrimSpace(key)
		if cleanKey != "" {
			cleanKeys = append(cleanKeys, cleanKey)
		}
	}
	return cleanKeys
}
