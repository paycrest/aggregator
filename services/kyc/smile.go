package kyc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/identityverificationrequest"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

type SmileIDService struct {
	identityConf *config.IdentityConfiguration
	serverConf   *config.ServerConfiguration
	db           *ent.Client
}

func NewSmileIDService() *SmileIDService {
	return &SmileIDService{
		identityConf: config.IdentityConfig(),
		serverConf:   config.ServerConfig(),
		db:           storage.Client,
	}
}

func (s *SmileIDService) RequestVerification(ctx context.Context, payload NewIDVerificationRequest) (*NewIDVerificationResponse, error) {
	signature, err := hex.DecodeString(payload.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: signature is not in the correct format")
	}
	if len(signature) != 65 {
		return nil, fmt.Errorf("invalid signature: signature length is not correct")
	}
	if signature[64] != 27 && signature[64] != 28 {
		return nil, fmt.Errorf("invalid signature: invalid recovery ID")
	}
	signature[64] -= 27

	message := fmt.Sprintf("I accept the KYC Policy and hereby request an identity verification check for %s with nonce %s", payload.WalletAddress, payload.Nonce)
	prefix := "\x19Ethereum Signed Message:\n" + fmt.Sprint(len(message))
	hash := crypto.Keccak256Hash([]byte(prefix + message))

	sigPublicKeyECDSA, err := crypto.SigToPub(hash.Bytes(), signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature")
	}
	recoveredAddress := crypto.PubkeyToAddress(*sigPublicKeyECDSA)
	if !strings.EqualFold(recoveredAddress.Hex(), payload.WalletAddress) {
		return nil, fmt.Errorf("invalid signature")
	}

	ivr, err := s.db.IdentityVerificationRequest.
		Query().
		Where(identityverificationrequest.WalletAddressEQ(payload.WalletAddress)).
		Only(ctx)
	if err != nil {
		if !ent.IsNotFound(err) {
			logger.Errorf("error: %v", err)
			return nil, fmt.Errorf("failed to request identity verification")
		}
	}

	timestamp := time.Now()

	if ivr != nil {
		if ivr.WalletSignature == payload.Signature {
			return nil, fmt.Errorf("signature already used for identity verification")
		}

		expiryPeriod := 15 * time.Minute

		if ivr.Status == identityverificationrequest.StatusFailed || (ivr.Status == identityverificationrequest.StatusPending && ivr.LastURLCreatedAt.Add(expiryPeriod).Before(timestamp)) {
			_, err := s.db.IdentityVerificationRequest.
				Delete().
				Where(identityverificationrequest.WalletAddressEQ(payload.WalletAddress)).
				Exec(ctx)
			if err != nil {
				logger.Errorf("error: %v", err)
				return nil, fmt.Errorf("failed to request identity verification")
			}
		} else if ivr.Status == identityverificationrequest.StatusPending && (ivr.LastURLCreatedAt.Add(expiryPeriod).Equal(timestamp) || ivr.LastURLCreatedAt.Add(expiryPeriod).After(timestamp)) {
			_, err = ivr.
				Update().
				SetWalletSignature(payload.Signature).
				Save(ctx)
			if err != nil {
				logger.Errorf("error: %v", err)
				return nil, fmt.Errorf("failed to request identity verification")
			}
			return &NewIDVerificationResponse{
				URL:       ivr.VerificationURL,
				ExpiresAt: ivr.LastURLCreatedAt,
			}, nil
		}

		if ivr.Status == identityverificationrequest.StatusSuccess {
			return nil, fmt.Errorf("this account has already been successfully verified")
		}
	}

	filePath, err := filepath.Abs("../../aggregator/config/smile_id_types.json")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve file path: %v", err)
	}

	// Load and flatten the JSON file
	idTypes, err := utils.LoadSmileIDConfig(filePath)
	if err != nil {
		fmt.Printf("Failed to flatten JSON: %v\n", err)
		return nil, fmt.Errorf("failed to flatten JSON: %v", err)
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
		"callback_url":            fmt.Sprintf("%s/v1/kyc/webhook", s.serverConf.HostDomain),
		"data_privacy_policy_url": "https://paycrest.notion.site/KYC-Policy-10e2482d45a280e191b8d47d76a8d242",
		"logo_url":                "https://res.cloudinary.com/de6e0wihu/image/upload/v1738088043/xxhlrsld2wy9lzekahur.png",
		"is_single_use":           true,
		"user_id":                 payload.WalletAddress,
		"expires_at":              timestamp.Add(1 * time.Hour).Format(time.RFC3339Nano),
	}).
		Send()
	if err != nil {
		logger.Errorf("error: %v", err)
		return nil, fmt.Errorf("failed to request identity verification: couldn't reach identity provider")
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		logger.Errorf("error: %v %v", err, data)
		return nil, fmt.Errorf("failed to request identity verification: %v", data)
	}

	ivr, err = s.db.IdentityVerificationRequest.
		Create().
		SetWalletAddress(payload.WalletAddress).
		SetWalletSignature(payload.Signature).
		SetPlatform("smile_id").
		SetPlatformRef(data["ref_id"].(string)).
		SetVerificationURL(data["link"].(string)).
		SetLastURLCreatedAt(timestamp).
		Save(ctx)
	if err != nil {
		logger.Errorf("error: %v", err)
		return nil, fmt.Errorf("failed to request identity verification")
	}

	return &NewIDVerificationResponse{
		URL:       ivr.VerificationURL,
		ExpiresAt: ivr.LastURLCreatedAt,
	}, nil
}

func (s *SmileIDService) CheckStatus(ctx context.Context, walletAddress string) (*IDVerificationStatusResponse, error) {

	ivr, err := s.db.IdentityVerificationRequest.
		Query().
		Where(identityverificationrequest.WalletAddressEQ(walletAddress)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			// Check the platform's status endpoint
			return nil, fmt.Errorf("no verification request found for this wallet address")
		}
		logger.Errorf("error: %v", err)
		return nil, fmt.Errorf("failed to fetch identity verification status")
	}

	response := &IDVerificationStatusResponse{
		URL:    ivr.VerificationURL,
		Status: ivr.Status.String(),
	}

	// Check if the verification URL has expired
	if ivr.LastURLCreatedAt.Add(1*time.Hour).Before(time.Now()) && ivr.Status == identityverificationrequest.StatusPending {
		response.Status = "expired"
	}

	return response, nil
}

func (s *SmileIDService) HandleWebhook(ctx context.Context, payload []byte) error {
	var smilePayload SmileIDWebhookPayload

	// Parse the JSON payload
	if err := json.Unmarshal(payload, &smilePayload); err != nil {
		logger.Errorf("failed to parse webhook payload: %v", err)
		return fmt.Errorf("invalid payload")
	}

	if !s.verifySmileIDWebhookSignature(smilePayload, smilePayload.Signature) {
		logger.Errorf("invalid webhook signature")
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
		logger.Errorf("failed to update verification status: %v", err)
		return fmt.Errorf("failed to process webhook")
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
