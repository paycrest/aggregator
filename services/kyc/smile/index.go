package smile

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/identityverificationrequest"
	kycErrors "github.com/paycrest/aggregator/services/kyc/errors"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
)

//go:embed id_types.json
var idTypesJSON []byte

type SmileIDService struct {
	identityConf *config.IdentityConfiguration
	serverConf   *config.ServerConfiguration
	db           *ent.Client
}

func NewSmileIDService() types.KYCProvider {
	return &SmileIDService{
		identityConf: config.IdentityConfig(),
		serverConf:   config.ServerConfig(),
		db:           storage.Client,
	}
}

// RequestVerification implements the KYCProvider interface
func (s *SmileIDService) RequestVerification(ctx context.Context, req types.VerificationRequest) (*types.VerificationResponse, error) {
	ivr, err := s.db.IdentityVerificationRequest.
		Query().
		Where(identityverificationrequest.WalletAddressEQ(req.WalletAddress)).
		Only(ctx)
	if err != nil {
		if !ent.IsNotFound(err) {
			return nil, kycErrors.ErrDatabase{Err: err}
		}
	}

	timestamp := time.Now()

	if ivr != nil {
		if ivr.WalletSignature == req.Signature {
			return nil, kycErrors.ErrSignatureAlreadyUsed{}
		}

		expiryPeriod := 15 * time.Minute

		if ivr.Status == identityverificationrequest.StatusFailed || (ivr.Status == identityverificationrequest.StatusPending && ivr.LastURLCreatedAt.Add(expiryPeriod).Before(timestamp)) {
			_, err := s.db.IdentityVerificationRequest.
				Delete().
				Where(identityverificationrequest.WalletAddressEQ(req.WalletAddress)).
				Exec(ctx)
			if err != nil {
				return nil, kycErrors.ErrDatabase{Err: err}
			}
		} else if ivr.Status == identityverificationrequest.StatusPending && (ivr.LastURLCreatedAt.Add(expiryPeriod).Equal(timestamp) || ivr.LastURLCreatedAt.Add(expiryPeriod).After(timestamp)) {
			_, err = ivr.
				Update().
				SetWalletSignature(req.Signature).
				Save(ctx)
			if err != nil {
				return nil, kycErrors.ErrDatabase{Err: err}
			}
			return &types.VerificationResponse{
				URL:       ivr.VerificationURL,
				ExpiresAt: ivr.LastURLCreatedAt,
			}, nil
		}

		if ivr.Status == identityverificationrequest.StatusSuccess {
			return nil, kycErrors.ErrAlreadyVerified{}
		}
	}

	// Load and flatten the JSON file
	idTypes, err := loadSmileIDConfig(idTypesJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to load ID types: %v", err)
	}

	smileIDSignature := s.getSmileIDSignature(timestamp.Format(time.RFC3339Nano))
	res, err := fastshot.NewClient(s.identityConf.SmileIdentityBaseUrl).
		Config().SetTimeout(30 * time.Second).
		Build().POST("/v1/smile_links").
		Body().AsJSON(map[string]interface{}{
		"partner_id":              s.identityConf.SmileIdentityPartnerId,
		"signature":               smileIDSignature,
		"timestamp":               timestamp,
		"name":                    "Aggregator KYC",
		"company_name":            "Paycrest",
		"id_types":                idTypes,
		"callback_url":            fmt.Sprintf("%s/v1/kyc/webhook", s.serverConf.ServerURL),
		"data_privacy_policy_url": "https://paycrest.notion.site/KYC-Policy-10e2482d45a280e191b8d47d76a8d242",
		"logo_url":                "https://res.cloudinary.com/de6e0wihu/image/upload/v1738088043/xxhlrsld2wy9lzekahur.png",
		"is_single_use":           true,
		"user_id":                 req.WalletAddress,
		"expires_at":              timestamp.Add(1 * time.Hour).Format(time.RFC3339Nano),
	}).
		Send()
	if err != nil {
		return nil, kycErrors.ErrProviderUnreachable{Err: err}
	}

	// Check for HTTP errors
	if res.Status().IsError() {
		body, _ := res.Body().AsString()
		return nil, kycErrors.ErrProviderResponse{Err: fmt.Errorf("HTTP error %d: %s", res.Status().Code(), body)}
	}

	var data map[string]interface{}
	err = res.Body().AsJSON(&data)
	if err != nil {
		return nil, kycErrors.ErrProviderResponse{Err: err}
	}

	ivr, err = s.db.IdentityVerificationRequest.
		Create().
		SetWalletAddress(req.WalletAddress).
		SetWalletSignature(req.Signature).
		SetPlatform("smile_id").
		SetPlatformRef(data["ref_id"].(string)).
		SetVerificationURL(data["link"].(string)).
		SetLastURLCreatedAt(timestamp).
		Save(ctx)
	if err != nil {
		return nil, kycErrors.ErrDatabase{Err: err}
	}

	return &types.VerificationResponse{
		URL:       ivr.VerificationURL,
		ExpiresAt: ivr.LastURLCreatedAt,
	}, nil
}

// CheckStatus implements the KYCProvider interface
func (s *SmileIDService) CheckStatus(ctx context.Context, walletAddress string) (*types.VerificationStatus, error) {
	ivr, err := s.db.IdentityVerificationRequest.
		Query().
		Where(identityverificationrequest.WalletAddressEQ(walletAddress)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, kycErrors.ErrNotFound{}
		}
		return nil, kycErrors.ErrDatabase{Err: err}
	}

	response := &types.VerificationStatus{
		URL:    ivr.VerificationURL,
		Status: ivr.Status.String(),
	}

	// Check if the verification URL has expired
	if ivr.LastURLCreatedAt.Add(1*time.Hour).Before(time.Now()) && ivr.Status == identityverificationrequest.StatusPending {
		response.Status = "expired"
	}

	return response, nil
}

// HandleWebhook implements the KYCProvider interface
func (s *SmileIDService) HandleWebhook(ctx context.Context, payload []byte) error {
	var smilePayload SmileIDWebhookPayload

	// Parse the JSON payload
	if err := json.Unmarshal(payload, &smilePayload); err != nil {
		return fmt.Errorf("invalid payload")
	}

	if !s.verifySmileIDWebhookSignature(smilePayload, smilePayload.Signature) {
		return fmt.Errorf("invalid signature")
	}

	// Process the webhook
	status := identityverificationrequest.StatusPending

	// Check for success codes
	successCodes := []string{
		"0810", // Document Verified
		"1020", // Exact Match (Basic KYC and Enhanced KYC)
		"1012", // Valid ID / ID Number Validated (Enhanced KYC)
		"0820", // Authenticate User Machine Judgement - PASS
		"0840", // Enroll User PASS - Machine Judgement
	}

	// Check for failed codes
	failedCodes := []string{
		"0811", // No Face Match
		"0812", // Filed Security Features Check
		"0813", // Document Not Verified - Machine Judgement
		"1022", // No Match
		"1023", // No Found
		"1011", // Invalid ID / ID Number Invalid
		"1013", // ID Number Not Found
		"1014", // Unsupported ID Type
		"0821", // Images did not match
		"0911", // No Face Found
		"0912", // Face Not Matching
		"0921", // Face Not Found
		"0922", // Selfie Quality Too Poor
		"0841", // Enroll User FAIL
		"0941", // Face Not Found
		"0942", // Face Poor Quality
	}

	if slices.Contains(successCodes, smilePayload.ResultCode) {
		status = identityverificationrequest.StatusSuccess
	}
	if slices.Contains(failedCodes, smilePayload.ResultCode) {
		status = identityverificationrequest.StatusFailed
	}

	// Update the verification status in the database
	_, err := s.db.IdentityVerificationRequest.
		Update().
		Where(
			identityverificationrequest.WalletAddressEQ(smilePayload.PartnerParams.UserID),
			identityverificationrequest.StatusEQ(identityverificationrequest.StatusPending),
		).
		SetStatus(status).
		Save(ctx)
	if err != nil {
		return kycErrors.ErrDatabase{Err: err}
	}

	return nil
}

// verifyWebhookSignature verifies the signature of a Smile Identity webhook
func (s *SmileIDService) verifySmileIDWebhookSignature(payload SmileIDWebhookPayload, receivedSignature string) bool {
	computedSignature := s.getSmileIDSignature(payload.Timestamp)
	return computedSignature == receivedSignature
}

// getSmileIDSignature generates a signature for a Smile ID request
func (s *SmileIDService) getSmileIDSignature(timestamp string) string {
	h := hmac.New(sha256.New, []byte(s.identityConf.SmileIdentityApiKey))
	h.Write([]byte(timestamp))
	h.Write([]byte(s.identityConf.SmileIdentityPartnerId))
	h.Write([]byte("sid_request"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// FlattenSmileIDConfig converts the hierarchical SmileIDConfig into a flat array of id_types
func flattenSmileIDConfig(config SmileIDConfig) ([]map[string]interface{}, error) {
	var idTypes []map[string]interface{}

	for _, continent := range config.Continents {
		for _, country := range continent.Countries {
			for _, idType := range country.IDTypes {
				idTypeEntry := map[string]interface{}{
					"country":             country.Code,
					"id_type":             idType.Type,
					"verification_method": idType.VerificationMethod,
				}
				idTypes = append(idTypes, idTypeEntry)
			}
		}
	}

	if len(idTypes) == 0 {
		return nil, fmt.Errorf("no ID types found in configuration")
	}

	return idTypes, nil
}

// LoadSmileIDConfig loads and flattens the JSON data
func loadSmileIDConfig(data []byte) ([]map[string]interface{}, error) {
	// Parse the JSON into SmileIDConfig
	var config SmileIDConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Flatten the structure
	return flattenSmileIDConfig(config)
}

type IDType struct {
	Type               string `json:"type"`
	VerificationMethod string `json:"verification_method"`
}

type Country struct {
	Name    string   `json:"name"`
	Code    string   `json:"code"`
	IDTypes []IDType `json:"id_types"`
}

type Continent struct {
	Name      string    `json:"name"`
	Countries []Country `json:"countries"`
}

type SmileIDConfig struct {
	Continents []Continent `json:"continents"`
}

// SmileIDWebhookPayload represents the payload structure from Smile Identity
type SmileIDWebhookPayload struct {
	ResultCode    string `json:"ResultCode"`
	PartnerParams struct {
		UserID string `json:"user_id"`
	} `json:"PartnerParams"`
	Signature string `json:"signature"`
	Timestamp string `json:"timestamp"`
	// Add other fields as needed
}
