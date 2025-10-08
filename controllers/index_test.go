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
	"github.com/paycrest/aggregator/ent/user"
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
	router.GET("/v1/kyb-submission", middleware.JWTMiddleware, ctrl.GetKYBDocuments)

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
			IAcceptTerms:         true,
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

			// ✅ NEW: Verify user's KYB verification status was updated to "pending"
			updatedUser, err := db.Client.User.
				Query().
				Where(user.IDEQ(testUser.ID)).
				Only(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, user.KybVerificationStatusPending, updatedUser.KybVerificationStatus,
				"User's KYB verification status should be updated to 'pending' after submission")
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

		t.Run("KYB resubmission after rejection", func(t *testing.T) {
			// First, check if a KYB profile already exists for this test user
			existingKYBProfile, err := db.Client.KYBProfile.
				Query().
				Where(kybprofile.HasUserWith(user.IDEQ(testUser.ID))).
				Only(context.Background())

			var kybProfile *ent.KYBProfile
			if err != nil {
				if ent.IsNotFound(err) {
					// No existing profile found, create a new one
					kybProfile, err = db.Client.KYBProfile.
						Create().
						SetMobileNumber("+1234567890").
						SetCompanyName("Test Company Ltd").
						SetRegisteredBusinessAddress("123 Business St, Test City, TC 12345").
						SetCertificateOfIncorporationURL("https://example.com/cert.pdf").
						SetArticlesOfIncorporationURL("https://example.com/articles.pdf").
						SetProofOfBusinessAddressURL("https://example.com/business-address.pdf").
						SetUserID(testUser.ID).
						Save(context.Background())
					assert.NoError(t, err)
				} else {
					// Unexpected error during query
					assert.NoError(t, err)
				}
			} else {
				// Existing profile found, reuse it
				kybProfile = existingKYBProfile
			}

			// Simulate a rejected KYB by updating the user's status and adding a rejection comment
			_, err = db.Client.User.
				Update().
				Where(user.IDEQ(testUser.ID)).
				SetKybVerificationStatus(user.KybVerificationStatusRejected).
				Save(context.Background())
			assert.NoError(t, err)

			// Update the KYB profile with a rejection comment
			_, err = db.Client.KYBProfile.
				Update().
				Where(kybprofile.IDEQ(kybProfile.ID)).
				SetKybRejectionComment("Incomplete documentation::Please provide clearer business license").
				Save(context.Background())
			assert.NoError(t, err)

			// Create a modified KYB submission for resubmission
			businessLicenseUrl := "https://example.com/new-business-license.pdf"
			amlPolicyUrl := "https://example.com/new-aml-policy.pdf"
			kycPolicyUrl := "https://example.com/new-kyc-policy.pdf"

			modifiedKYBSubmission := types.KYBSubmissionInput{
				MobileNumber:                  "+9876543210",
				CompanyName:                   "Updated Business Solutions Ltd",
				RegisteredBusinessAddress:     "456 Corporate Blvd, New City, New Country",
				CertificateOfIncorporationUrl: "https://example.com/new-cert-inc.pdf",
				ArticlesOfIncorporationUrl:    "https://example.com/new-articles-inc.pdf",
				BusinessLicenseUrl:            &businessLicenseUrl,
				ProofOfBusinessAddressUrl:     "https://example.com/new-proof-business-address.pdf",
				ProofOfResidentialAddressUrl:  "https://example.com/new-proof-residential-address.pdf",
				AmlPolicyUrl:                  &amlPolicyUrl,
				KycPolicyUrl:                  &kycPolicyUrl,
				IAcceptTerms:         true,
				BeneficialOwners: []types.BeneficialOwnerInput{
					{
						FullName:                     "Robert Johnson",
						ResidentialAddress:           "789 Executive Lane, New City, New Country",
						ProofOfResidentialAddressUrl: "https://example.com/robert-proof-address.pdf",
						GovernmentIssuedIdUrl:        "https://example.com/robert-id.pdf",
						DateOfBirth:                  "1975-03-20",
						OwnershipPercentage:          70.0,
						GovernmentIssuedIdType:       "drivers_license",
					},
					{
						FullName:                     "Sarah Wilson",
						ResidentialAddress:           "321 Manager Street, New City, New Country",
						ProofOfResidentialAddressUrl: "https://example.com/sarah-proof-address.pdf",
						GovernmentIssuedIdUrl:        "https://example.com/sarah-id.pdf",
						DateOfBirth:                  "1982-07-10",
						OwnershipPercentage:          30.0,
						GovernmentIssuedIdType:       "national_id",
					},
				},
			}

			headers := map[string]string{
				"Authorization": "Bearer " + token,
			}

			// Test resubmission - should succeed
			res, err := test.PerformRequest(t, "POST", "/v1/kyb-submission", modifiedKYBSubmission, headers, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusCreated, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "success", response.Status)
			assert.Equal(t, "KYB submission updated successfully", response.Message)

			// Verify the KYB profile was updated
			updatedKYBProfile, err := db.Client.KYBProfile.
				Query().
				Where(kybprofile.HasUserWith(user.IDEQ(testUser.ID))).
				WithBeneficialOwners().
				Only(context.Background())
			assert.NoError(t, err)

			// Verify updated fields
			assert.Equal(t, modifiedKYBSubmission.MobileNumber, updatedKYBProfile.MobileNumber)
			assert.Equal(t, modifiedKYBSubmission.CompanyName, updatedKYBProfile.CompanyName)
			assert.Equal(t, modifiedKYBSubmission.RegisteredBusinessAddress, updatedKYBProfile.RegisteredBusinessAddress)
			assert.Equal(t, modifiedKYBSubmission.CertificateOfIncorporationUrl, updatedKYBProfile.CertificateOfIncorporationURL)
			assert.Equal(t, modifiedKYBSubmission.ArticlesOfIncorporationUrl, updatedKYBProfile.ArticlesOfIncorporationURL)
			assert.Equal(t, *modifiedKYBSubmission.BusinessLicenseUrl, *updatedKYBProfile.BusinessLicenseURL)
			assert.Equal(t, modifiedKYBSubmission.ProofOfBusinessAddressUrl, updatedKYBProfile.ProofOfBusinessAddressURL)
			assert.Equal(t, *modifiedKYBSubmission.AmlPolicyUrl, updatedKYBProfile.AmlPolicyURL)
			assert.Equal(t, *modifiedKYBSubmission.KycPolicyUrl, *updatedKYBProfile.KycPolicyURL)

			// Verify beneficial owners were updated
			assert.Equal(t, 2, len(updatedKYBProfile.Edges.BeneficialOwners))

			// Check first beneficial owner
			owner1 := updatedKYBProfile.Edges.BeneficialOwners[0]
			assert.Equal(t, modifiedKYBSubmission.BeneficialOwners[0].FullName, owner1.FullName)
			assert.Equal(t, modifiedKYBSubmission.BeneficialOwners[0].ResidentialAddress, owner1.ResidentialAddress)
			assert.Equal(t, modifiedKYBSubmission.BeneficialOwners[0].ProofOfResidentialAddressUrl, owner1.ProofOfResidentialAddressURL)
			assert.Equal(t, modifiedKYBSubmission.BeneficialOwners[0].GovernmentIssuedIdUrl, owner1.GovernmentIssuedIDURL)
			assert.Equal(t, modifiedKYBSubmission.BeneficialOwners[0].DateOfBirth, owner1.DateOfBirth)
			assert.Equal(t, modifiedKYBSubmission.BeneficialOwners[0].OwnershipPercentage, owner1.OwnershipPercentage)
			assert.Equal(t, beneficialowner.GovernmentIssuedIDType(modifiedKYBSubmission.BeneficialOwners[0].GovernmentIssuedIdType), owner1.GovernmentIssuedIDType)

			// Verify user's KYB verification status was updated to pending
			updatedUser, err := db.Client.User.
				Query().
				Where(user.IDEQ(testUser.ID)).
				Only(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, user.KybVerificationStatusPending, updatedUser.KybVerificationStatus,
				"User's KYB verification status should be updated to 'pending' after resubmission")

			// Test that another resubmission is blocked
			res, err = test.PerformRequest(t, "POST", "/v1/kyb-submission", modifiedKYBSubmission, headers, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusConflict, res.Code)

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
				IAcceptTerms: true,
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

		t.Run("invalid input - terms not accepted", func(t *testing.T) {
			termsNotAcceptedSubmission := validKYBSubmission
			termsNotAcceptedSubmission.IAcceptTerms = false

			headers := map[string]string{
				"Authorization": "Bearer " + token,
			}

			res, err := test.PerformRequest(t, "POST", "/v1/kyb-submission", termsNotAcceptedSubmission, headers, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "error", response.Status)
			assert.Equal(t, "Kindly accept the terms and conditions to proceed", response.Message)
		})

		t.Run("invalid input - invalid beneficial owner data", func(t *testing.T) {
			invalidSubmission := validKYBSubmission
			// Create a copy of beneficial owners to avoid modifying the original
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

	t.Run("GetKYBDocuments", func(t *testing.T) {
		// Create a test user first
		testUser, err := test.CreateTestUser(map[string]interface{}{
			"firstName": "Rejected",
			"lastName":  "User",
			"email":     "rejecteduser@example.com",
			"scope":     "provider",
		})
		assert.NoError(t, err)

		// Generate JWT token for the test user
		token, err := tokenUtils.GenerateAccessJWT(testUser.ID.String(), "provider")
		assert.NoError(t, err)

		headers := map[string]string{
			"Authorization": "Bearer " + token,
		}

		// Test data for KYB submission (we'll create this in the database)
		kybData := types.KYBSubmissionInput{
			MobileNumber:                  "+1234567890",
			CompanyName:                   "Rejected Company Ltd",
			RegisteredBusinessAddress:     "456 Rejected St, Test City, TC 12345",
			CertificateOfIncorporationUrl: "https://example.com/rejected-cert.pdf",
			ArticlesOfIncorporationUrl:    "https://example.com/rejected-articles.pdf",
			BusinessLicenseUrl:            nil,
			ProofOfBusinessAddressUrl:     "https://example.com/rejected-business-address.pdf",
			ProofOfResidentialAddressUrl:  "https://example.com/rejected-residential-address.pdf",
			AmlPolicyUrl:                  nil,
			KycPolicyUrl:                  nil,
			IAcceptTerms:         true,
			BeneficialOwners: []types.BeneficialOwnerInput{
				{
					FullName:                     "Rejected Owner",
					ResidentialAddress:           "789 Rejected Ave, Test City, TC 12345",
					ProofOfResidentialAddressUrl: "https://example.com/rejected-owner-residential.pdf",
					GovernmentIssuedIdUrl:        "https://example.com/rejected-owner-id.pdf",
					DateOfBirth:                  "1980-12-25",
					OwnershipPercentage:          100.0,
					GovernmentIssuedIdType:       "national_id",
				},
			},
		}

		t.Run("success - rejected user can retrieve documents", func(t *testing.T) {
			// Set user status to rejected
			_, err := db.Client.User.
				UpdateOneID(testUser.ID).
				SetKybVerificationStatus(user.KybVerificationStatusRejected).
				Save(context.Background())
			assert.NoError(t, err)

			// Create KYB profile in database
			rejectionComment := "Certificate of incorporation document is not clear. Please upload a higher quality document."
			kybProfile, err := db.Client.KYBProfile.
				Create().
				SetMobileNumber(kybData.MobileNumber).
				SetCompanyName(kybData.CompanyName).
				SetRegisteredBusinessAddress(kybData.RegisteredBusinessAddress).
				SetCertificateOfIncorporationURL(kybData.CertificateOfIncorporationUrl).
				SetArticlesOfIncorporationURL(kybData.ArticlesOfIncorporationUrl).
				SetProofOfBusinessAddressURL(kybData.ProofOfBusinessAddressUrl).
				SetKybRejectionComment(rejectionComment).
				SetUserID(testUser.ID).
				Save(context.Background())
			assert.NoError(t, err)

			// Create beneficial owners
			for _, owner := range kybData.BeneficialOwners {
				_, err := db.Client.BeneficialOwner.
					Create().
					SetFullName(owner.FullName).
					SetResidentialAddress(owner.ResidentialAddress).
					SetProofOfResidentialAddressURL(owner.ProofOfResidentialAddressUrl).
					SetGovernmentIssuedIDURL(owner.GovernmentIssuedIdUrl).
					SetDateOfBirth(owner.DateOfBirth).
					SetOwnershipPercentage(owner.OwnershipPercentage).
					SetGovernmentIssuedIDType(beneficialowner.GovernmentIssuedIDType(owner.GovernmentIssuedIdType)).
					SetKybProfileID(kybProfile.ID).
					Save(context.Background())
				assert.NoError(t, err)
			}

			// Make the request
			res, err := test.PerformRequest(t, "GET", "/v1/kyb-submission", nil, headers, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "success", response.Status)
			assert.Equal(t, "KYB documents retrieved", response.Message)

			// Verify the response data
			data, ok := response.Data.(map[string]interface{})
			assert.True(t, ok, "response.Data should be map[string]interface{}")

			// Check company details
			assert.Equal(t, kybData.CompanyName, data["companyName"])
			assert.Equal(t, kybData.MobileNumber, data["mobileNumber"])
			assert.Equal(t, kybData.RegisteredBusinessAddress, data["registeredBusinessAddress"])
			assert.Equal(t, kybData.CertificateOfIncorporationUrl, data["certificateOfIncorporationUrl"])
			assert.Equal(t, kybData.ArticlesOfIncorporationUrl, data["articlesOfIncorporationUrl"])
			assert.Equal(t, kybData.ProofOfBusinessAddressUrl, data["proofOfBusinessAddressUrl"])
			assert.Equal(t, rejectionComment, data["rejectionComment"])

			// Check beneficial owners
			beneficialOwners, ok := data["beneficialOwners"].([]interface{})
			assert.True(t, ok, "beneficialOwners should be []interface{}")
			assert.Equal(t, 1, len(beneficialOwners))

			owner := beneficialOwners[0].(map[string]interface{})
			assert.Equal(t, kybData.BeneficialOwners[0].FullName, owner["fullName"])
			assert.Equal(t, kybData.BeneficialOwners[0].ResidentialAddress, owner["residentialAddress"])
			assert.Equal(t, kybData.BeneficialOwners[0].DateOfBirth, owner["dateOfBirth"])
			assert.Equal(t, kybData.BeneficialOwners[0].OwnershipPercentage, owner["ownershipPercentage"])
			assert.Equal(t, kybData.BeneficialOwners[0].GovernmentIssuedIdType, owner["governmentIssuedIdType"])
			assert.Equal(t, kybData.BeneficialOwners[0].GovernmentIssuedIdUrl, owner["governmentIssuedIdUrl"])
			assert.Equal(t, kybData.BeneficialOwners[0].ProofOfResidentialAddressUrl, owner["proofOfResidentialAddressUrl"])
		})

		t.Run("forbidden - non-rejected user cannot access documents", func(t *testing.T) {
			// Create another test user with approved status
			approvedUser, err := test.CreateTestUser(map[string]interface{}{
				"firstName": "Approved",
				"lastName":  "User",
				"email":     "approveduser@example.com",
				"scope":     "provider",
			})
			assert.NoError(t, err)

			// Set user status to approved
			_, err = db.Client.User.
				UpdateOneID(approvedUser.ID).
				SetKybVerificationStatus(user.KybVerificationStatusApproved).
				Save(context.Background())
			assert.NoError(t, err)

			// Generate JWT token for the approved user
			approvedToken, err := tokenUtils.GenerateAccessJWT(approvedUser.ID.String(), "provider")
			assert.NoError(t, err)

			approvedHeaders := map[string]string{
				"Authorization": "Bearer " + approvedToken,
			}

			// Make the request
			res, err := test.PerformRequest(t, "GET", "/v1/kyb-submission", nil, approvedHeaders, router)
			assert.NoError(t, err)

			assert.Equal(t, http.StatusForbidden, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "error", response.Status)
			assert.Equal(t, "Documents only available for rejected submissions", response.Message)
		})
	})
}
