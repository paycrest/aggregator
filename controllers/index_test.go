package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jarcoal/httpmock"
	_ "github.com/mattn/go-sqlite3"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/routers/middleware"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/shopspring/decimal"

	"github.com/gin-gonic/gin"
	"github.com/paycrest/aggregator/ent/beneficialowner"
	"github.com/paycrest/aggregator/ent/enttest"
	"github.com/paycrest/aggregator/ent/identityverificationrequest"
	"github.com/paycrest/aggregator/ent/kybprofile"
	"github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/utils/test"
	tokenUtils "github.com/paycrest/aggregator/utils/token"
	"github.com/stretchr/testify/assert"
)

var testCtx = struct {
	currency *ent.FiatCurrency
}{}

func setup() error {
	// Set up test data
	currency, err := test.CreateTestFiatCurrency(nil)
	if err != nil {
		return err
	}
	testCtx.currency = currency

	return nil
}

func TestIndex(t *testing.T) {
	// Set up test database client
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	db.Client = client

	// Setup test data
	err := setup()
	assert.NoError(t, err)

	// Set up test routers
	// var ctrl Controller
	ctrl := NewController()
	router := gin.New()

	router.GET("currencies", ctrl.GetFiatCurrencies)
	router.GET("pubkey", ctrl.GetAggregatorPublicKey)
	router.GET("institutions/:currency_code", ctrl.GetInstitutionsByCurrency)
	router.POST("kyc", ctrl.RequestIDVerification)
	router.GET("kyc/:wallet_address", ctrl.GetIDVerificationStatus)
	router.POST("kyc/webhook", ctrl.KYCWebhook)
	router.GET("/v1/tokens", ctrl.GetSupportedTokens)
	router.POST("/v1/kyb-submission", middleware.JWTMiddleware, ctrl.HandleKYBSubmission)

	t.Run("GetInstitutions By Currency", func(t *testing.T) {

		res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/institutions/%s", testCtx.currency.Code), nil, nil, router)
		assert.NoError(t, err)

		type Response struct {
			Status  string                        `json:"status"`
			Message string                        `json:"message"`
			Data    []types.SupportedInstitutions `json:"data"`
		}

		var response Response
		// Assert the response body
		assert.Equal(t, http.StatusOK, res.Code)

		err = json.Unmarshal(res.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "OK", response.Message)
		assert.Equal(t, 2, len(response.Data), "SupportedInstitutions should be two")
	})

	t.Run("Currencies", func(t *testing.T) {
		t.Run("fetch supported fiat currencies", func(t *testing.T) {
			res, err := test.PerformRequest(t, "GET", "/currencies?scope=sender", nil, nil, router)
			assert.NoError(t, err)

			// Assert the response code.
			assert.Equal(t, http.StatusOK, res.Code)

			var response struct {
				Data    []types.SupportedCurrencies
				Message string
			}
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "OK", response.Message)

			// Assert /currencies response with the seeded Naira currency.
			nairaCurrency := types.SupportedCurrencies{
				Code:       "NGN",
				Name:       "Nigerian Naira",
				ShortName:  "Naira",
				Decimals:   2,
				Symbol:     "₦",
				MarketRate: decimal.NewFromFloat(950.0),
			}

			assert.Equal(t, nairaCurrency.Code, response.Data[0].Code)
			assert.Equal(t, nairaCurrency.Name, response.Data[0].Name)
			assert.Equal(t, nairaCurrency.ShortName, response.Data[0].ShortName)
			assert.Equal(t, nairaCurrency.Decimals, response.Data[0].Decimals)
			assert.Equal(t, nairaCurrency.Symbol, response.Data[0].Symbol)
			assert.True(t, response.Data[0].MarketRate.Equal(nairaCurrency.MarketRate))
		})
	})

	t.Run("Get Aggregator Public key", func(t *testing.T) {
		t.Run("fetch Aggregator Public key", func(t *testing.T) {
			res, err := test.PerformRequest(t, "GET", "/pubkey", nil, nil, router)
			assert.NoError(t, err)

			// Assert the response code.
			assert.Equal(t, http.StatusOK, res.Code)

			var response struct {
				Data    string
				Message string
			}
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "OK", response.Message)

			assert.Equal(t, response.Data, config.CryptoConfig().AggregatorPublicKey)
		})
	})

	t.Run("Request ID Verification", func(t *testing.T) {
		// activate httpmock
		httpmock.Activate()
		defer httpmock.Deactivate()

		// register mock response
		httpmock.RegisterResponder("POST", identityConf.SmileIdentityBaseUrl+"/v1/smile_links",
			func(r *http.Request) (*http.Response, error) {
				resp := httpmock.NewBytesResponse(202, []byte(`{"link": "https://links.usesmileid.com/1111/123456", "ref_id": "123456"}`))
				return resp, nil
			},
		)
		t.Run("with valid details", func(t *testing.T) {
			payload := types.VerificationRequest{
				WalletAddress: "0xf4c5c4deDde7A86b25E7430796441e209e23eBFB",
				Signature:     "b1dcfa6beba6c93e5abd38c23890a1ff2e553721c5c379a80b66a2ad74b3755f543cd8e7d8fb064ae4fdeeba93302c156bd012e390c2321a763eddaa12e5ab5d1c",
				Nonce:         "e08511abb6087c47",
			}

			res, err := test.PerformRequest(t, "POST", "/kyc", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response code.
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Identity verification requested successfully", response.Message)
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data is not of type map[string]interface{}")
			assert.Equal(t, "https://links.usesmileid.com/1111/123456", data["url"])

			ivr, err := db.Client.IdentityVerificationRequest.
				Query().
				Where(
					identityverificationrequest.WalletAddressEQ(payload.WalletAddress),
					identityverificationrequest.WalletSignatureEQ(payload.Signature),
				).
				Only(context.Background())

			assert.NoError(t, err)
			assert.Equal(t, "success", response.Status)
			assert.Equal(t, "https://links.usesmileid.com/1111/123456", ivr.VerificationURL)
			assert.Equal(t, "123456", ivr.PlatformRef)
		})

		t.Run("with an already used signature", func(t *testing.T) {
			payload := types.VerificationRequest{
				Signature:     "b1dcfa6beba6c93e5abd38c23890a1ff2e553721c5c379a80b66a2ad74b3755f543cd8e7d8fb064ae4fdeeba93302c156bd012e390c2321a763eddaa12e5ab5d1c",
				WalletAddress: "0xf4c5c4deDde7A86b25E7430796441e209e23eBFB",
				Nonce:         "e08511abb6087c47",
			}

			res, err := test.PerformRequest(t, "POST", "/kyc", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response code.
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "error", response.Status)
			assert.Equal(t, "Signature already used for identity verification", response.Message)
			assert.Nil(t, response.Data)
		})

		t.Run("with a different signature for same wallet address with validity duration", func(t *testing.T) {
			payload := types.VerificationRequest{
				Signature:     "dea3406fa45aa364283e1704b3a8c3b70973a25c262540b71e857efe25e8582b23f98b969cebe320dd2851e5ea36c781253edf7e7d1cd5fe6be704f5709f76df1b",
				WalletAddress: "0xf4c5c4deDde7A86b25E7430796441e209e23eBFB",
				Nonce:         "8c400162fbfe0527",
			}

			res, err := test.PerformRequest(t, "POST", "/kyc", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response code.
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "success", response.Status)
			assert.Equal(t, "Identity verification requested successfully", response.Message)
		})

		t.Run("with invalid signature", func(t *testing.T) {
			payload := types.VerificationRequest{
				Signature:     "invalid_signature",
				WalletAddress: "0xf4c5c4deDde7A86b25E7430796441e209e23eBFB",
				Nonce:         "e08511abb6087c47",
			}

			res, err := test.PerformRequest(t, "POST", "/kyc", payload, nil, router)
			assert.NoError(t, err)

			// Assert the response code.
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "error", response.Status)
			assert.Equal(t, "Invalid signature", response.Message)
		})
	})

	t.Run("Get ID Verification Status", func(t *testing.T) {
		// Test with a valid wallet address
		res, err := test.PerformRequest(t, "GET", fmt.Sprintf("/kyc/%s", "0xf4c5c4deDde7A86b25E7430796441e209e23eBFB"), nil, nil, router)
		assert.NoError(t, err)

		// Assert the response code.
		assert.Equal(t, http.StatusOK, res.Code)

		var response types.Response
		err = json.Unmarshal(res.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "Identity verification status fetched successfully", response.Message)
		assert.Equal(t, "success", response.Status)
		data, ok := response.Data.(map[string]interface{})
		assert.True(t, ok, "response.Data is not of type map[string]interface{}")
		assert.Equal(t, "pending", data["status"])
	})

	t.Run("GetSupportedTokens", func(t *testing.T) {
		// Setup test data for tokens
		networks, tokens := test.CreateTestTokenData(t, client)

		// Define response structure
		type Response struct {
			Status  string                         `json:"status"`
			Message string                         `json:"message"`
			Data    []types.SupportedTokenResponse `json:"data"`
		}

		t.Run("Fetch all enabled tokens", func(t *testing.T) {
			res, err := test.PerformRequest(t, "GET", "/v1/tokens", nil, nil, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusOK, res.Code)

			var response Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "success", response.Status)
			assert.Equal(t, "Tokens retrieved successfully", response.Message)
			assert.Equal(t, 2, len(response.Data)) // Should only include enabled tokens

			// Verify token details
			assert.Equal(t, tokens[0].Symbol, response.Data[0].Symbol)
			assert.Equal(t, tokens[0].ContractAddress, response.Data[0].ContractAddress)
			assert.Equal(t, tokens[0].Decimals, response.Data[0].Decimals)
			assert.Equal(t, tokens[0].BaseCurrency, response.Data[0].BaseCurrency)
			assert.Equal(t, networks[0].Identifier, response.Data[0].Network)
		})

		t.Run("Fetch tokens by network", func(t *testing.T) {
			res, err := test.PerformRequest(t, "GET", "/v1/tokens?network=arbitrum-one", nil, nil, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusOK, res.Code)

			var response Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "success", response.Status)
			assert.Equal(t, "Tokens retrieved successfully", response.Message)
			assert.Equal(t, 1, len(response.Data)) // Should only include tokens for the specified network

			assert.Equal(t, "USDC", response.Data[0].Symbol)
			assert.Equal(t, "arbitrum-one", response.Data[0].Network)
		})

		t.Run("Fetch with invalid network", func(t *testing.T) {
			res, err := test.PerformRequest(t, "GET", "/v1/tokens?network=invalid-network", nil, nil, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusOK, res.Code)

			var response Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "success", response.Status)
			assert.Equal(t, "Tokens retrieved successfully", response.Message)
			assert.Equal(t, 0, len(response.Data)) // No tokens for invalid network
		})

		t.Run("Fetch with no enabled tokens", func(t *testing.T) {
			// Disable all tokens
			_, err := client.Token.Update().
				Where(token.IsEnabled(true)).
				SetIsEnabled(false).
				Save(context.Background())
			assert.NoError(t, err)

			res, err := test.PerformRequest(t, "GET", "/v1/tokens", nil, nil, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusOK, res.Code)

			var response Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "success", response.Status)
			assert.Equal(t, "Tokens retrieved successfully", response.Message)
			assert.Equal(t, 0, len(response.Data)) // No enabled tokens
		})
	})

	t.Run("HandleKYBSubmission", func(t *testing.T) {
		// Create a test user first
		testUser, err := test.CreateTestUser(map[string]interface{}{
			"firstName": "Test",
			"lastName":  "User",
			"email":     "testuser@example.com",
			"scope":     "sender",
		})
		assert.NoError(t, err)

		// Generate JWT token for the test user
		token, err := tokenUtils.GenerateAccessJWT(testUser.ID.String(), "sender")
		assert.NoError(t, err)

		// Test data for KYB submission
		validKYBSubmission := types.KYBSubmissionInput{
			MobileNumber:                  "+1234567890",
			CompanyName:                   "Test Company Ltd",
			RegisteredBusinessAddress:     "123 Business St, Test City, TC 12345",
			CertificateOfIncorporationUrl: "https://example.com/cert.pdf",
			ArticlesOfIncorporationUrl:    "https://example.com/articles.pdf",
			BusinessLicenseUrl:            nil, // Optional field
			ProofOfBusinessAddressUrl:     "https://example.com/business-address.pdf",
			ProofOfResidentialAddressUrl:  "https://example.com/residential-address.pdf",
			AmlPolicyUrl:                  nil, // Optional field
			KycPolicyUrl:                  nil, // Optional field
			BeneficialOwners: []types.BeneficialOwnerInput{
				{
					FullName:                     "John Doe",
					ResidentialAddress:           "456 Residential Ave, Test City, TC 12345",
					ProofOfResidentialAddressUrl: "https://example.com/john-residential.pdf",
					GovernmentIssuedIdUrl:        "https://example.com/john-id.pdf",
					DateOfBirth:                  "1990-01-01",
					OwnershipPercentage:          60.0,
					GovernmentIssuedIdType:       "passport",
				},
				{
					FullName:                     "Jane Smith",
					ResidentialAddress:           "789 Residential Blvd, Test City, TC 12345",
					ProofOfResidentialAddressUrl: "https://example.com/jane-residential.pdf",
					GovernmentIssuedIdUrl:        "https://example.com/jane-id.pdf",
					DateOfBirth:                  "1985-05-15",
					OwnershipPercentage:          40.0,
					GovernmentIssuedIdType:       "drivers_license",
				},
			},
		}

		t.Run("successful KYB submission", func(t *testing.T) {
			headers := map[string]string{
				"Authorization": "Bearer " + token,
			}

			res, err := test.PerformRequest(t, "POST", "/v1/kyb-submission", validKYBSubmission, headers, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusCreated, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "success", response.Status)
			assert.Equal(t, "KYB submission submitted successfully", response.Message)

			// Verify the response data contains submission_id
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data should be map[string]interface{}")
			assert.Contains(t, data, "submission_id")

			// Verify KYB profile was created in database
			submissionID, ok := data["submission_id"].(string)
			assert.True(t, ok, "submission_id should be a string")

			kybProfileUUID, err := uuid.Parse(submissionID)
			assert.NoError(t, err)

			kybProfile, err := db.Client.KYBProfile.
				Query().
				Where(kybprofile.IDEQ(kybProfileUUID)).
				WithUser().
				WithBeneficialOwners().
				Only(context.Background())
			assert.NoError(t, err)

			// Verify KYB profile details
			assert.Equal(t, validKYBSubmission.MobileNumber, kybProfile.MobileNumber)
			assert.Equal(t, validKYBSubmission.CompanyName, kybProfile.CompanyName)
			assert.Equal(t, validKYBSubmission.RegisteredBusinessAddress, kybProfile.RegisteredBusinessAddress)
			assert.Equal(t, validKYBSubmission.CertificateOfIncorporationUrl, kybProfile.CertificateOfIncorporationURL)
			assert.Equal(t, validKYBSubmission.ArticlesOfIncorporationUrl, kybProfile.ArticlesOfIncorporationURL)
			assert.Equal(t, validKYBSubmission.ProofOfBusinessAddressUrl, kybProfile.ProofOfBusinessAddressURL)
			assert.Equal(t, testUser.ID, kybProfile.Edges.User.ID)

			// Verify beneficial owners were created
			assert.Equal(t, 2, len(kybProfile.Edges.BeneficialOwners))

			// Check first beneficial owner
			owner1 := kybProfile.Edges.BeneficialOwners[0]
			assert.Equal(t, validKYBSubmission.BeneficialOwners[0].FullName, owner1.FullName)
			assert.Equal(t, validKYBSubmission.BeneficialOwners[0].ResidentialAddress, owner1.ResidentialAddress)
			assert.Equal(t, validKYBSubmission.BeneficialOwners[0].ProofOfResidentialAddressUrl, owner1.ProofOfResidentialAddressURL)
			assert.Equal(t, validKYBSubmission.BeneficialOwners[0].GovernmentIssuedIdUrl, owner1.GovernmentIssuedIDURL)
			assert.Equal(t, validKYBSubmission.BeneficialOwners[0].DateOfBirth, owner1.DateOfBirth)
			assert.Equal(t, validKYBSubmission.BeneficialOwners[0].OwnershipPercentage, owner1.OwnershipPercentage)
			assert.Equal(t, beneficialowner.GovernmentIssuedIDType(validKYBSubmission.BeneficialOwners[0].GovernmentIssuedIdType), owner1.GovernmentIssuedIDType)
		})

		t.Run("duplicate KYB submission", func(t *testing.T) {
			headers := map[string]string{
				"Authorization": "Bearer " + token,
			}

			res, err := test.PerformRequest(t, "POST", "/v1/kyb-submission", validKYBSubmission, headers, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusConflict, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "error", response.Status)
			assert.Equal(t, "KYB submission already submitted for this user", response.Message)
		})

		t.Run("missing authorization header", func(t *testing.T) {
			res, err := test.PerformRequest(t, "POST", "/v1/kyb-submission", validKYBSubmission, nil, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusUnauthorized, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "error", response.Status)
			assert.Equal(t, "Authorization header is missing", response.Message)
		})

		t.Run("invalid JWT token", func(t *testing.T) {
			headers := map[string]string{
				"Authorization": "Bearer invalid-token",
			}

			res, err := test.PerformRequest(t, "POST", "/v1/kyb-submission", validKYBSubmission, headers, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusUnauthorized, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "error", response.Status)
		})

		t.Run("invalid input - missing required fields", func(t *testing.T) {
			invalidSubmission := types.KYBSubmissionInput{
				MobileNumber: "+1234567890",
				// Missing other required fields
			}

			headers := map[string]string{
				"Authorization": "Bearer " + token,
			}

			res, err := test.PerformRequest(t, "POST", "/v1/kyb-submission", invalidSubmission, headers, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "error", response.Status)
			assert.Equal(t, "Invalid input", response.Message)
		})

		t.Run("invalid input - invalid beneficial owner data", func(t *testing.T) {
			invalidSubmission := validKYBSubmission
			invalidSubmission.BeneficialOwners = []types.BeneficialOwnerInput{
				{
					FullName:                     "John Doe",
					ResidentialAddress:           "456 Residential Ave, Test City, TC 12345",
					ProofOfResidentialAddressUrl: "https://example.com/john-residential.pdf",
					GovernmentIssuedIdUrl:        "https://example.com/john-id.pdf",
					DateOfBirth:                  "1990-01-01",
					OwnershipPercentage:          150.0, // Invalid: > 100%
					GovernmentIssuedIdType:       "passport",
				},
			}

			headers := map[string]string{
				"Authorization": "Bearer " + token,
			}

			res, err := test.PerformRequest(t, "POST", "/v1/kyb-submission", invalidSubmission, headers, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "error", response.Status)
			assert.Equal(t, "Invalid input", response.Message)
		})
	})
}
