package services

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/token"
)

// APIKeyService provides functionality related to API keys.
type APIKeyService struct{}

// NewAPIKeyService creates a new instance of APIKeyService.
func NewAPIKeyService() *APIKeyService {
	return &APIKeyService{}
}

// GenerateAPIKey generates a new API key for the user.
func (s *APIKeyService) GenerateAPIKey(
	ctx context.Context,
	tx *ent.Tx,
	sender *ent.SenderProfile,
	provider *ent.ProviderProfile,
) (*ent.APIKey, string, error) {
	// Generate a new secret key
	secretKey, err := token.GeneratePrivateKey()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate API key: %w", err)
	}

	// Encrypt the secret key
	encryptedSecret, _ := crypto.EncryptPlain([]byte(secretKey))
	encodedSecret := base64.StdEncoding.EncodeToString(encryptedSecret)

	var apiKey *ent.APIKey

	if sender != nil {
		if tx != nil {
			apiKey, err = tx.APIKey.
				Create().
				SetSecret(encodedSecret).
				SetSenderProfile(sender).
				Save(ctx)
			if err != nil {
				return nil, "", fmt.Errorf("failed to create API key: %w", err)
			}
		} else {
			apiKey, err = storage.Client.APIKey.
				Create().
				SetSecret(encodedSecret).
				SetSenderProfile(sender).
				Save(ctx)
			if err != nil {
				return nil, "", fmt.Errorf("failed to create API key: %w", err)
			}
		}
	} else if provider != nil {
		if tx != nil {
			apiKey, err = tx.APIKey.
				Create().
				SetSecret(encodedSecret).
				SetProviderProfile(provider).
				Save(ctx)
			if err != nil {
				return nil, "", fmt.Errorf("failed to create API key: %w", err)
			}
		} else {
			apiKey, err = storage.Client.APIKey.
				Create().
				SetSecret(encodedSecret).
				SetProviderProfile(provider).
				Save(ctx)
			if err != nil {
				return nil, "", fmt.Errorf("failed to create API key: %w", err)
			}
		}
	} else {
		return nil, "", fmt.Errorf("profile not provided")
	}

	return apiKey, secretKey, nil
}

// GetAPIKey gets the API key for a user profile.
func (s *APIKeyService) GetAPIKey(
	ctx context.Context,
	sender *ent.SenderProfile,
	provider *ent.ProviderProfile,
) (*types.APIKeyResponse, error) {
	var apiKey *ent.APIKey

	if sender != nil {
		apiKey, _ = sender.QueryAPIKey().Only(ctx)
	} else if provider != nil {
		apiKey, _ = provider.QueryAPIKey().Only(ctx)
	} else {
		return nil, fmt.Errorf("profile not provided")
	}

	// Decrypt the secret key
	decodedSecret, _ := base64.StdEncoding.DecodeString(apiKey.Secret)
	decryptedSecret, _ := crypto.DecryptPlain(decodedSecret)

	return &types.APIKeyResponse{
		ID:     apiKey.ID,
		Secret: string(decryptedSecret),
	}, nil
}
