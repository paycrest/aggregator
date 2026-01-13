package crypto

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/paycrest/aggregator/ent"
	"github.com/stretchr/testify/assert"
)

func TestCreateEOA(t *testing.T) {
	// Mock the server config
	cryptoConf.HDWalletMnemonic = "media nerve fog identify typical physical aspect doll bar fossil frost because"

	t.Run("evm account creation", func(t *testing.T) {
		// Set the expected account index and address
		expectedAccountIndex := 1
		expectedAddress := "0xc60F0aDe1483fa6A355f32E0d3406127C49d4d7f"

		// Call the GenerateAccountFromIndex Function
		address, privateKey, err := GenerateAccountFromIndex(expectedAccountIndex)
		assert.NoError(t, err, "unexpected error")

		// Assert the generated address
		assert.Equal(t, expectedAddress, address.Hex(), "incorrect address")
		assert.NotEmpty(t, privateKey, "private key should not be empty")
	})

	t.Run("tron account creation", func(t *testing.T) {
		// Set the expected account index and address
		expectedAccountIndex := 1
		expectedAddress := "TFR3TTx4YzWwNoqmcuVEi477PJoSyo9zwx"

		// Call the GenerateTronAccountFromIndex Function
		wallet, err := GenerateTronAccountFromIndex(expectedAccountIndex)
		assert.NoError(t, err, "unexpected error")

		// Assert the generated address
		assert.Equal(t, expectedAddress, wallet.AddressBase58, "incorrect address")
		assert.NotEmpty(t, wallet.PrivateKey, "private key should not be empty")
	})
}

func TestGetOrderRecipientFromMessageHash(t *testing.T) {
	t.Run("basic encryption and decryption", func(t *testing.T) {
		// Create a mock payment order
		order := &ent.PaymentOrder{
			AccountIdentifier: "1234567890",
			AccountName:       "John Doe",
			Institution:       "Test Bank",
			Memo:              "Test payment",
			Metadata: map[string]interface{}{
				"reference": "TEST123",
				"note":      "Test transaction",
			},
		}

		// Encrypt the order recipient
		messageHash, err := EncryptOrderRecipient(order)
		assert.NoError(t, err, "encryption should succeed")
		assert.NotEmpty(t, messageHash, "message hash should not be empty")

		// Decrypt and verify
		recipient, err := GetOrderRecipientFromMessageHash(messageHash)
		assert.NoError(t, err, "decryption should succeed")
		assert.NotNil(t, recipient, "recipient should not be nil")
		assert.Equal(t, order.AccountIdentifier, recipient.AccountIdentifier)
		assert.Equal(t, order.AccountName, recipient.AccountName)
		assert.Equal(t, order.Institution, recipient.Institution)
		assert.Equal(t, order.Memo, recipient.Memo)
	})

	t.Run("encryption with provider", func(t *testing.T) {
		// Create a mock payment order with provider
		order := &ent.PaymentOrder{
			AccountIdentifier: "9876543210",
			AccountName:       "Jane Smith",
			Institution:       "Another Bank",
			Memo:              "Provider test",
			Edges: ent.PaymentOrderEdges{
				Provider: &ent.ProviderProfile{
					ID: "provider-123",
				},
			},
			Metadata: map[string]interface{}{
				"type": "provider_payment",
			},
		}

		// Encrypt the order recipient
		messageHash, err := EncryptOrderRecipient(order)
		assert.NoError(t, err, "encryption should succeed")

		// Decrypt and verify
		recipient, err := GetOrderRecipientFromMessageHash(messageHash)
		assert.NoError(t, err, "decryption should succeed")
		assert.Equal(t, "provider-123", recipient.ProviderID)
	})

	t.Run("large payload encryption with hybrid encryption", func(t *testing.T) {
		// With hybrid encryption, we should be able to encrypt larger payloads
		// Test with a payload under the 500 bytes limit
		largeMetadata := make(map[string]interface{})
		for i := 0; i < 5; i++ {
			largeMetadata[string(rune('A'+i))] = strings.Repeat("X", 30)
		}

		order := &ent.PaymentOrder{
			AccountIdentifier: strings.Repeat("1234567890", 2),
			AccountName:       "Test User with Long Name",
			Institution:       "Test Bank with Long Name",
			Memo:              strings.Repeat("Memo. ", 10),
			Metadata:          largeMetadata,
		}

		// This should succeed with hybrid encryption (under 500 bytes)
		messageHash, err := EncryptOrderRecipient(order)
		assert.NoError(t, err, "encryption with large payload should succeed with hybrid encryption")
		assert.NotEmpty(t, messageHash)

		// Decrypt and verify
		recipient, err := GetOrderRecipientFromMessageHash(messageHash)
		assert.NoError(t, err, "decryption should succeed")
		assert.Equal(t, order.AccountIdentifier, recipient.AccountIdentifier)
		assert.Equal(t, order.AccountName, recipient.AccountName)
		assert.Equal(t, order.Institution, recipient.Institution)
		assert.Equal(t, order.Memo, recipient.Memo)
		assert.Equal(t, len(order.Metadata), len(recipient.Metadata))

		t.Logf("✓ Successfully encrypted and decrypted large payload with hybrid encryption")
	})

	t.Run("max size limit - 500 bytes should pass", func(t *testing.T) {
		// Test with payload close to but under 500 bytes
		order := &ent.PaymentOrder{
			AccountIdentifier: strings.Repeat("A", 40),
			AccountName:       strings.Repeat("B", 40),
			Institution:       strings.Repeat("C", 40),
			Memo:              strings.Repeat("D", 150), // Adjust to be close to 500 bytes total
			Metadata: map[string]interface{}{
				"key1": "val1",
				"key2": "val2",
			},
		}

		// Calculate approximate size
		message := struct {
			Nonce             string
			AccountIdentifier string
			AccountName       string
			Institution       string
			ProviderID        string
			Memo              string
			Metadata          map[string]interface{}
		}{
			"1234567890123456", order.AccountIdentifier, order.AccountName, order.Institution, "", order.Memo, order.Metadata,
		}
		jsonBytes, _ := json.Marshal(message)
		jsonSize := len(jsonBytes)
		t.Logf("Payload size: %d bytes", jsonSize)

		// Should succeed if under 500 bytes
		if jsonSize <= 500 {
			messageHash, err := EncryptOrderRecipient(order)
			assert.NoError(t, err, "encryption should succeed for payload under 500 bytes")
			assert.NotEmpty(t, messageHash)

			recipient, err := GetOrderRecipientFromMessageHash(messageHash)
			assert.NoError(t, err, "decryption should succeed")
			assert.Equal(t, order.AccountIdentifier, recipient.AccountIdentifier)
			t.Logf("✓ Successfully encrypted %d bytes (under 500 byte limit)", jsonSize)
		}
	})

	t.Run("max size limit - over 500 bytes should fail", func(t *testing.T) {
		// Test with payload exceeding 500 bytes
		largeMetadata := make(map[string]interface{})
		for i := 0; i < 15; i++ {
			largeMetadata[string(rune('A'+i))] = strings.Repeat("X", 50)
		}

		order := &ent.PaymentOrder{
			AccountIdentifier: strings.Repeat("A", 50),
			AccountName:       strings.Repeat("B", 50),
			Institution:       strings.Repeat("C", 50),
			Memo:              strings.Repeat("D", 100),
			Metadata:          largeMetadata,
		}

		// Calculate size to verify it's over 500 bytes
		message := struct {
			Nonce             string
			AccountIdentifier string
			AccountName       string
			Institution       string
			ProviderID        string
			Memo              string
			Metadata          map[string]interface{}
		}{
			"1234567890123456", order.AccountIdentifier, order.AccountName, order.Institution, "", order.Memo, order.Metadata,
		}
		jsonBytes, _ := json.Marshal(message)
		jsonSize := len(jsonBytes)
		t.Logf("Payload size: %d bytes (exceeds 500 byte limit)", jsonSize)
		assert.Greater(t, jsonSize, 500, "payload should exceed 500 bytes for this test")

		// This should fail due to size limit
		_, err := EncryptOrderRecipient(order)
		assert.Error(t, err, "encryption should fail when payload exceeds 500 bytes")
		assert.Contains(t, err.Error(), "payload too large", "error should indicate size limit exceeded")

		t.Logf("✓ Correctly rejected %d bytes payload (over 500 byte limit)", jsonSize)
	})

	t.Run("small metadata", func(t *testing.T) {
		// Test with small metadata
		metadata := make(map[string]interface{})
		metadata["ref"] = "123"
		metadata["id"] = "456"

		order := &ent.PaymentOrder{
			AccountIdentifier: "1234567890",
			AccountName:       "Test User",
			Institution:       "Test Bank",
			Memo:              "Small test",
			Metadata:          metadata,
		}

		messageHash, err := EncryptOrderRecipient(order)
		assert.NoError(t, err, "encryption with small metadata should succeed")

		recipient, err := GetOrderRecipientFromMessageHash(messageHash)
		assert.NoError(t, err, "decryption should succeed")
		assert.Equal(t, order.AccountIdentifier, recipient.AccountIdentifier)
	})

	t.Run("invalid base64 message hash", func(t *testing.T) {
		// Test with invalid base64
		invalidHash := "not-valid-base64!!!"
		recipient, err := GetOrderRecipientFromMessageHash(invalidHash)
		assert.Error(t, err, "should fail with invalid base64")
		assert.Nil(t, recipient)
	})

	t.Run("tampered message hash", func(t *testing.T) {
		// Create valid encrypted message
		order := &ent.PaymentOrder{
			AccountIdentifier: "1234567890",
			AccountName:       "Test User",
			Institution:       "Test Bank",
			Memo:              "Test",
		}

		messageHash, err := EncryptOrderRecipient(order)
		assert.NoError(t, err)

		// Tamper with the message hash
		decoded, _ := base64.StdEncoding.DecodeString(messageHash)
		if len(decoded) > 10 {
			decoded[5] ^= 0xFF // Flip some bits
		}
		tamperedHash := base64.StdEncoding.EncodeToString(decoded)

		// Try to decrypt tampered message
		recipient, err := GetOrderRecipientFromMessageHash(tamperedHash)
		assert.Error(t, err, "should fail with tampered message")
		assert.Nil(t, recipient)
	})

	t.Run("empty fields", func(t *testing.T) {
		// Test with minimal data
		order := &ent.PaymentOrder{
			AccountIdentifier: "",
			AccountName:       "",
			Institution:       "",
			Memo:              "",
		}

		messageHash, err := EncryptOrderRecipient(order)
		assert.NoError(t, err, "encryption with empty fields should succeed")

		recipient, err := GetOrderRecipientFromMessageHash(messageHash)
		assert.NoError(t, err, "decryption should succeed")
		assert.Equal(t, "", recipient.AccountIdentifier)
		assert.Equal(t, "", recipient.AccountName)
	})

	t.Run("nonce randomness", func(t *testing.T) {
		// Verify that each encryption produces a unique nonce
		order := &ent.PaymentOrder{
			AccountIdentifier: "1234567890",
			AccountName:       "Test User",
			Institution:       "Test Bank",
			Memo:              "Nonce test",
		}

		hash1, err1 := EncryptOrderRecipient(order)
		hash2, err2 := EncryptOrderRecipient(order)

		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.NotEqual(t, hash1, hash2, "consecutive encryptions should produce different hashes due to random nonce")

		// Both should decrypt successfully
		recipient1, err := GetOrderRecipientFromMessageHash(hash1)
		assert.NoError(t, err)
		assert.NotEmpty(t, recipient1.Nonce)

		recipient2, err := GetOrderRecipientFromMessageHash(hash2)
		assert.NoError(t, err)
		assert.NotEmpty(t, recipient2.Nonce)
		assert.NotEqual(t, recipient1.Nonce, recipient2.Nonce, "nonces should be different")
	})
}
