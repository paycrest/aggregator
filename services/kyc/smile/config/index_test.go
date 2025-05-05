package config

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"crypto/hmac"
	"crypto/sha256"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jarcoal/httpmock"
	_ "github.com/mattn/go-sqlite3"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent/enttest"
	"github.com/paycrest/aggregator/ent/identityverificationrequest"
	db "github.com/paycrest/aggregator/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateValidSignature(t *testing.T, walletAddress, nonce string) string {
	// This is a test private key - never use in production
	privateKey, err := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19")
	require.NoError(t, err)

	message := fmt.Sprintf("I accept the KYC Policy and hereby request an identity verification check for %s with nonce %s", walletAddress, nonce)
	prefix := "\x19Ethereum Signed Message:\n" + fmt.Sprint(len(message))
	hash := crypto.Keccak256Hash([]byte(prefix + message))

	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	require.NoError(t, err)

	// Add recovery ID
	signature[64] += 27

	return hex.EncodeToString(signature)
}

func TestSmileIDService(t *testing.T) {
	// Set up test database client
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	db.Client = client

	// Activate httpmock
	httpmock.Activate()
	defer httpmock.Deactivate()

	// Mock the Smile ID API response
	httpmock.RegisterResponder("POST", "https://testapi.smileidentity.com/v1/smile_links",
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewJsonResponse(200, map[string]interface{}{
				"link":   "https://links.usesmileid.com/1234/abcd",
				"ref_id": "abcd1234",
			})
		},
	)

	service := &SmileIDService{
		identityConf: &config.IdentityConfiguration{
			SmileIdentityBaseUrl:   "https://testapi.smileidentity.com",
			SmileIdentityPartnerId: "1234",
			SmileIdentityApiKey:    "test_api_key",
		},
		serverConf: &config.ServerConfiguration{
			HostDomain: "https://api.example.com",
		},
		db: client,
	}

	// ==================== RequestVerification Tests ====================
	t.Run("RequestVerification", func(t *testing.T) {
		// Clear any existing verification requests before each test
		_, err := client.IdentityVerificationRequest.Delete().Exec(context.Background())
		require.NoError(t, err)

		// Test: Valid request creates new verification
		t.Run("Valid request creates new verification", func(t *testing.T) {
			// Generate a valid wallet address and signature
			walletAddress := "0x96216849c49358B10257cb55b28eA603c874b05E"
			nonce := "test_nonce_123"
			signature := generateValidSignature(t, walletAddress, nonce)

			// Create request payload
			payload := NewIDVerificationRequest{
				WalletAddress: walletAddress,
				Signature:     signature,
				Nonce:         nonce,
			}

			// Call the method
			resp, err := service.RequestVerification(context.Background(), payload)

			// Assertions
			require.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Equal(t, "https://links.usesmileid.com/1234/abcd", resp.URL)

			// Verify database entry
			ivr, err := client.IdentityVerificationRequest.
				Query().
				Where(identityverificationrequest.WalletAddressEQ(walletAddress)).
				Only(context.Background())
			require.NoError(t, err)
			assert.Equal(t, walletAddress, ivr.WalletAddress)
			assert.Equal(t, signature, ivr.WalletSignature)
			assert.Equal(t, "smile_id", ivr.Platform.String())
			assert.Equal(t, "abcd1234", ivr.PlatformRef)
			assert.Equal(t, "https://links.usesmileid.com/1234/abcd", ivr.VerificationURL)
			assert.Equal(t, identityverificationrequest.StatusPending, ivr.Status)
		})

		// Test: Invalid signature format
		t.Run("Invalid signature format", func(t *testing.T) {
			// Clear any existing verification requests
			_, err := client.IdentityVerificationRequest.Delete().Exec(context.Background())
			require.NoError(t, err)

			payload := NewIDVerificationRequest{
				WalletAddress: "0x96216849c49358B10257cb55b28eA603c874b05E",
				Signature:     "invalid_signature",
				Nonce:         "test_nonce",
			}

			resp, err := service.RequestVerification(context.Background(), payload)

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), "invalid signature: signature is not in the correct format")
		})

		// Test: Already verified wallet
		t.Run("Already verified wallet", func(t *testing.T) {
			// Clear any existing verification requests
			_, err := client.IdentityVerificationRequest.Delete().Exec(context.Background())
			require.NoError(t, err)

			// Create a verified entry in the database
			walletAddress := "0x96216849c49358B10257cb55b28eA603c874b05E"
			nonce := "test_nonce_456"
			signature := generateValidSignature(t, walletAddress, nonce)

			_, err = client.IdentityVerificationRequest.
				Create().
				SetWalletAddress(walletAddress).
				SetWalletSignature("previous_signature").
				SetPlatform("smile_id").
				SetPlatformRef("ref123").
				SetVerificationURL("https://example.com").
				SetStatus(identityverificationrequest.StatusSuccess).
				SetLastURLCreatedAt(time.Now()).
				Save(context.Background())
			require.NoError(t, err)

			// Try to request verification again
			payload := NewIDVerificationRequest{
				WalletAddress: walletAddress,
				Signature:     signature,
				Nonce:         nonce,
			}

			resp, err := service.RequestVerification(context.Background(), payload)

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), "this account has already been successfully verified")
		})

		// Test: Reuse same signature
		t.Run("Reuse same signature", func(t *testing.T) {
			// Clear any existing verification requests
			_, err := client.IdentityVerificationRequest.Delete().Exec(context.Background())
			require.NoError(t, err)

			// Create an entry with a specific signature
			walletAddress := "0x96216849c49358B10257cb55b28eA603c874b05E"
			nonce := "test_nonce_789"
			signature := generateValidSignature(t, walletAddress, nonce)

			_, err = client.IdentityVerificationRequest.
				Create().
				SetWalletAddress(walletAddress).
				SetWalletSignature(signature).
				SetPlatform("smile_id").
				SetPlatformRef("ref456").
				SetVerificationURL("https://example.com").
				SetStatus(identityverificationrequest.StatusPending).
				SetLastURLCreatedAt(time.Now()).
				Save(context.Background())
			require.NoError(t, err)

			// Try to request verification with the same signature
			payload := NewIDVerificationRequest{
				WalletAddress: walletAddress,
				Signature:     signature,
				Nonce:         nonce,
			}

			resp, err := service.RequestVerification(context.Background(), payload)

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), "signature already used for identity verification")
		})

		t.Run("Pending but not expired", func(t *testing.T) {
			// Clear any existing verification requests
			_, err := client.IdentityVerificationRequest.Delete().Exec(context.Background())
			require.NoError(t, err)

			// Create a pending entry that's not expired
			walletAddress := "0x96216849c49358B10257cb55b28eA603c874b05E"
			oldSignature := "old_signature"
			nonce := "test_nonce_101112"
			newSignature := generateValidSignature(t, walletAddress, nonce)
			verificationURL := "https://links.usesmileid.com/pending/notexpired"

			lastURLCreatedAt := time.Now().Add(-5 * time.Minute) // 5 minutes ago, not expired

			_, err = client.IdentityVerificationRequest.
				Create().
				SetWalletAddress(walletAddress).
				SetWalletSignature(oldSignature).
				SetPlatform("smile_id").
				SetPlatformRef("ref789").
				SetVerificationURL(verificationURL).
				SetStatus(identityverificationrequest.StatusPending).
				SetLastURLCreatedAt(lastURLCreatedAt).
				Save(context.Background())
			require.NoError(t, err)

			// Request with new signature
			payload := NewIDVerificationRequest{
				WalletAddress: walletAddress,
				Signature:     newSignature,
				Nonce:         nonce,
			}

			resp, err := service.RequestVerification(context.Background(), payload)

			assert.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Equal(t, verificationURL, resp.URL)

			// Compare only the Unix timestamps to avoid timezone issues
			assert.Equal(t, lastURLCreatedAt.Unix(), resp.ExpiresAt.Unix())

			// Verify the signature was updated
			ivr, err := client.IdentityVerificationRequest.
				Query().
				Where(identityverificationrequest.WalletAddressEQ(walletAddress)).
				Only(context.Background())
			require.NoError(t, err)
			assert.Equal(t, newSignature, ivr.WalletSignature)
		})
	})

	// ==================== CheckStatus Tests ====================
	t.Run("CheckStatus", func(t *testing.T) {
		// Create test data
		pendingWallet := "0x1234567890123456789012345678901234567890"
		successWallet := "0x2345678901234567890123456789012345678901"
		failedWallet := "0x3456789012345678901234567890123456789012"
		expiredWallet := "0x4567890123456789012345678901234567890123"
		nonExistentWallet := "0x5678901234567890123456789012345678901234"

		// Create pending verification
		_, err := client.IdentityVerificationRequest.
			Create().
			SetWalletAddress(pendingWallet).
			SetWalletSignature("sig1").
			SetPlatform("smile_id").
			SetPlatformRef("ref1").
			SetVerificationURL("https://example.com/pending").
			SetStatus(identityverificationrequest.StatusPending).
			SetLastURLCreatedAt(time.Now()).
			Save(context.Background())
		require.NoError(t, err)

		// Create successful verification
		_, err = client.IdentityVerificationRequest.
			Create().
			SetWalletAddress(successWallet).
			SetWalletSignature("sig2").
			SetPlatform("smile_id").
			SetPlatformRef("ref2").
			SetVerificationURL("https://example.com/success").
			SetStatus(identityverificationrequest.StatusSuccess).
			SetLastURLCreatedAt(time.Now()).
			Save(context.Background())
		require.NoError(t, err)

		// Create failed verification
		_, err = client.IdentityVerificationRequest.
			Create().
			SetWalletAddress(failedWallet).
			SetWalletSignature("sig3").
			SetPlatform("smile_id").
			SetPlatformRef("ref3").
			SetVerificationURL("https://example.com/failed").
			SetStatus(identityverificationrequest.StatusFailed).
			SetLastURLCreatedAt(time.Now()).
			Save(context.Background())
		require.NoError(t, err)

		// Create expired verification
		_, err = client.IdentityVerificationRequest.
			Create().
			SetWalletAddress(expiredWallet).
			SetWalletSignature("sig4").
			SetPlatform("smile_id").
			SetPlatformRef("ref4").
			SetVerificationURL("https://example.com/expired").
			SetStatus(identityverificationrequest.StatusPending).
			SetLastURLCreatedAt(time.Now().Add(-2 * time.Hour)). // 2 hours ago, expired
			Save(context.Background())
		require.NoError(t, err)

		// Test: Pending verification
		t.Run("Pending verification", func(t *testing.T) {
			resp, err := service.CheckStatus(context.Background(), pendingWallet)

			assert.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Equal(t, "pending", resp.Status)
			assert.Equal(t, "https://example.com/pending", resp.URL)
		})

		// Test: Successful verification
		t.Run("Successful verification", func(t *testing.T) {
			resp, err := service.CheckStatus(context.Background(), successWallet)

			assert.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Equal(t, "success", resp.Status)
			assert.Equal(t, "https://example.com/success", resp.URL)
		})

		// Test: Failed verification
		t.Run("Failed verification", func(t *testing.T) {
			resp, err := service.CheckStatus(context.Background(), failedWallet)

			assert.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Equal(t, "failed", resp.Status)
			assert.Equal(t, "https://example.com/failed", resp.URL)
		})

		// Test: Expired verification
		t.Run("Expired verification", func(t *testing.T) {
			resp, err := service.CheckStatus(context.Background(), expiredWallet)

			assert.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Equal(t, "expired", resp.Status)
			assert.Equal(t, "https://example.com/expired", resp.URL)
		})

		// Test: Non-existent wallet
		t.Run("Non-existent wallet", func(t *testing.T) {
			resp, err := service.CheckStatus(context.Background(), nonExistentWallet)

			assert.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), "no verification request found for this wallet address")
		})
	})

	// ==================== HandleWebhook Tests ====================
	t.Run("HandleWebhook", func(t *testing.T) {
		// Create test data - a pending verification
		_, err := client.IdentityVerificationRequest.Delete().Exec(context.Background())
		require.NoError(t, err)

		// Create test data - a pending verification
		testWallet := "0x1234567890123456789012345678901234567890"
		_, err = client.IdentityVerificationRequest.
			Create().
			SetWalletAddress(testWallet).
			SetWalletSignature("sig1").
			SetPlatform("smile_id").
			SetPlatformRef("ref1").
			SetVerificationURL("https://example.com/pending").
			SetStatus(identityverificationrequest.StatusPending).
			SetLastURLCreatedAt(time.Now()).
			Save(context.Background())
		require.NoError(t, err)

		// Helper function to create a valid webhook payload
		createWebhookPayload := func(resultCode string, userID string) []byte {
			timestamp := time.Now().Format(time.RFC3339Nano)

			// Generate a valid signature
			h := hmac.New(sha256.New, []byte("test_api_key"))
			h.Write([]byte(timestamp))
			h.Write([]byte("1234"))
			h.Write([]byte("sid_request"))
			signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

			payload := SmileIDWebhookPayload{
				ResultCode: resultCode,
				PartnerParams: struct {
					UserID string `json:"user_id"`
				}{
					UserID: userID,
				},
				Signature: signature,
				Timestamp: timestamp,
			}

			jsonData, _ := json.Marshal(payload)
			return jsonData
		}

		// Test: Success webhook
		t.Run("Success webhook", func(t *testing.T) {
			// Create a webhook payload with a success code
			payloadBytes := createWebhookPayload("0810", testWallet)

			err := service.HandleWebhook(context.Background(), payloadBytes)
			assert.NoError(t, err)

			// Verify the status was updated
			ivr, err := client.IdentityVerificationRequest.
				Query().
				Where(identityverificationrequest.WalletAddressEQ(testWallet)).
				Only(context.Background())
			require.NoError(t, err)
			assert.Equal(t, identityverificationrequest.StatusSuccess, ivr.Status)
		})

		// Test: Failed webhook
		t.Run("Failed webhook", func(t *testing.T) {
			// Reset the status to pending
			_, err := client.IdentityVerificationRequest.
				Update().
				Where(identityverificationrequest.WalletAddressEQ(testWallet)).
				SetStatus(identityverificationrequest.StatusPending).
				Save(context.Background())
			require.NoError(t, err)

			// Create a webhook payload with a failure code
			payloadBytes := createWebhookPayload("0811", testWallet)

			err = service.HandleWebhook(context.Background(), payloadBytes)
			assert.NoError(t, err)

			// Verify the status was updated
			ivr, err := client.IdentityVerificationRequest.
				Query().
				Where(identityverificationrequest.WalletAddressEQ(testWallet)).
				Only(context.Background())
			require.NoError(t, err)
			assert.Equal(t, identityverificationrequest.StatusFailed, ivr.Status)
		})

		// Test: Invalid signature
		t.Run("Invalid signature", func(t *testing.T) {
			// Create an invalid webhook payload
			payload := SmileIDWebhookPayload{
				ResultCode: "0810",
				PartnerParams: struct {
					UserID string `json:"user_id"`
				}{
					UserID: testWallet,
				},
				Signature: "invalid_signature",
				Timestamp: time.Now().Format(time.RFC3339Nano),
			}
			jsonData, _ := json.Marshal(payload)

			err := service.HandleWebhook(context.Background(), jsonData)
			assert.Error(t, err)
			assert.Equal(t, "invalid signature", err.Error())
		})
	})
}
