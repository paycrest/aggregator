package accounts

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/routers/middleware"
	"github.com/paycrest/aggregator/services"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/shopspring/decimal"

	"github.com/gin-gonic/gin"
	"github.com/paycrest/aggregator/ent/enttest"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/senderordertoken"
	"github.com/paycrest/aggregator/ent/senderprofile"
	tokenDB "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/user"
	"github.com/paycrest/aggregator/utils/test"
	"github.com/paycrest/aggregator/utils/token"
	"github.com/stretchr/testify/assert"
)

var testCtx = struct {
	user            *ent.User
	providerProfile *ent.ProviderProfile
	token           *ent.Token
	client          types.RPCClient
}{}

func setup() error {
	// Set up test blockchain client
	client, err := test.SetUpTestBlockchain()
	if err != nil {
		return err
	}

	testCtx.client = client
	// Create a test token
	token, err := test.CreateERC20Token(
		client,
		map[string]interface{}{
			"deployContract": false,
		})
	if err != nil {
		return err
	}
	testCtx.token = token

	// Set up test data
	user, err := test.CreateTestUser(map[string]interface{}{
		"scope": "provider",
		"email": "providerjohndoe@test.com",
	})
	if err != nil {
		return err
	}
	testCtx.user = user

	currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
		"code":        "KES",
		"short_name":  "Shilling",
		"decimals":    2,
		"symbol":      "KSh",
		"name":        "Kenyan Shilling",
		"market_rate": 550.0,
	})
	if err != nil {
		return err
	}

	provderProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
		"user_id":     testCtx.user.ID,
		"currency_id": currency.ID,
	})
	if err != nil {
		return err
	}
	testCtx.providerProfile = provderProfile

	return nil
}

func TestProfile(t *testing.T) {
	// Set up test database client
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	db.Client = client

	// Setup test data
	err := setup()
	assert.NoError(t, err)

	// Set up test routers
	router := gin.New()
	ctrl := &ProfileController{}

	router.GET(
		"/settings/sender",
		middleware.JWTMiddleware,
		middleware.OnlySenderMiddleware,
		ctrl.GetSenderProfile,
	)
	router.GET(
		"/settings/provider",
		middleware.JWTMiddleware,
		middleware.OnlyProviderMiddleware,
		ctrl.GetProviderProfile,
	)
	router.PATCH(
		"/settings/sender",
		middleware.JWTMiddleware,
		middleware.OnlySenderMiddleware,
		ctrl.UpdateSenderProfile,
	)
	router.PATCH(
		"/settings/provider",
		middleware.JWTMiddleware,
		middleware.OnlyProviderMiddleware,
		ctrl.UpdateProviderProfile,
	)

	t.Run("UpdateSenderProfile", func(t *testing.T) {
		t.Run("with all fields", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"domain_whitelist": []string{"example.com"},
				"user_id":          testUser.ID,
				"token":            testCtx.token.Symbol,
			})
			assert.NoError(t, err)

			// Test partial update
			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}
			payload := types.SenderProfilePayload{
				DomainWhitelist: []string{"example.com", "mydomain.com"},
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Profile updated successfully", response.Message)
			assert.Nil(t, response.Data, "response.Data is not nil")

			senderProfile, err := db.Client.SenderProfile.
				Query().
				Where(senderprofile.HasUserWith(user.ID(testUser.ID))).
				Only(context.Background())
			assert.NoError(t, err)

			assert.Contains(t, senderProfile.DomainWhitelist, "mydomain.com")
		})

		t.Run("with an invalid webhook", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{
				"scope": "sender",
				"email": "johndoe2@test.com",
			})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"domain_whitelist": []string{"example.com"},
				"user_id":          testUser.ID,
			})
			assert.NoError(t, err)

			// Test partial update
			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}
			payload := types.SenderProfilePayload{
				WebhookURL:      "examplecom",
				DomainWhitelist: []string{"example.com", "mydomain.com"},
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Failed to validate payload", response.Message)
			assert.Equal(t, "error", response.Status)
			data, ok := response.Data.([]interface{})
			assert.True(t, ok, "response.Data is not of type []interface{}")
			assert.NotNil(t, data, "response.Data is nil")

			// Assert the response errors in data
			assert.Len(t, data, 1)
			errorMap, ok := data[0].(map[string]interface{})
			assert.True(t, ok, "error is not of type map[string]interface{}")
			assert.NotNil(t, errorMap, "error is nil")
			assert.Contains(t, errorMap, "field")
			assert.Equal(t, "WebhookURL", errorMap["field"].(string))
			assert.Contains(t, errorMap, "message")
			assert.Equal(t, "Invalid URL", errorMap["message"].(string))
		})

		t.Run("with all fields and check if it is active", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{
				"scope": "sender",
				"email": "johndoe3@test.com",
			})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"domain_whitelist": []string{"example.com"},
				"user_id":          testUser.ID,
				"token":            testCtx.token.Symbol,
			})
			assert.NoError(t, err)

			// Test partial update
			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// setup payload
			tokenPayload := make([]types.SenderOrderTokenPayload, 2)
			tokenAddresses := make([]types.SenderOrderAddressPayload, 1)

			// setup ERC20 token
			tokenAddresses[0].FeeAddress = "0xD4EB9067111F81b9bAabE06E2b8ebBaDADEd5DAf"
			tokenAddresses[0].Network = testCtx.token.Edges.Network.Identifier
			tokenAddresses[0].RefundAddress = "0xD4EB9067111F81b9bAabE06E2b8ebBaDADEd5DA0"

			tokenPayload[0].FeePercent = decimal.NewFromInt(1)
			tokenPayload[0].Symbol = testCtx.token.Symbol
			tokenPayload[0].Addresses = tokenAddresses

			// setup TRC token
			tronToken, err := test.CreateTRC20Token(testCtx.client, map[string]interface{}{})
			assert.NoError(t, err)
			assert.NotEqual(t, "localhost", tronToken.Edges.Network.Identifier)

			// setup TRC20 token
			tronTokenAddresses := make([]types.SenderOrderAddressPayload, 1)
			tronTokenAddresses[0].FeeAddress = "TFRKiHrHCeSyWL67CEwydFvUMYJ6CbYYX7"
			tronTokenAddresses[0].Network = tronToken.Edges.Network.Identifier
			tronTokenAddresses[0].RefundAddress = "TFRKiHrHCeSyWL67CEwydFvUMYJ6CbYYXR"

			tokenPayload[1].FeePercent = decimal.NewFromInt(2)
			tokenPayload[1].Symbol = tronToken.Symbol
			tokenPayload[1].Addresses = tronTokenAddresses

			// put the payload together
			payload := types.SenderProfilePayload{
				DomainWhitelist: []string{"example.com", "mydomain.com"},
				WebhookURL:      "https://example.com",
				Tokens:          tokenPayload,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Profile updated successfully", response.Message)
			assert.Nil(t, response.Data, "response.Data is not nil")

			senderProfile, err := db.Client.SenderProfile.
				Query().
				Where(senderprofile.HasUserWith(user.ID(testUser.ID))).
				WithOrderTokens().
				Only(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, len(senderProfile.Edges.OrderTokens), 2)

			t.Run("check If Tron was added", func(t *testing.T) {
				senderorder, err := db.Client.SenderOrderToken.
					Query().
					Where(
						senderordertoken.HasSenderWith(
							senderprofile.IDEQ(senderProfile.ID),
						),
						senderordertoken.HasTokenWith(tokenDB.IDEQ(tronToken.ID)),
					).
					Only(context.Background())
				assert.NoError(t, err)
				assert.Equal(t, senderorder.FeeAddress, "TFRKiHrHCeSyWL67CEwydFvUMYJ6CbYYX7")
				assert.Equal(t, senderorder.RefundAddress, "TFRKiHrHCeSyWL67CEwydFvUMYJ6CbYYXR")
			})

			t.Run("check If EVM chain was added", func(t *testing.T) {
				senderorder, err := db.Client.SenderOrderToken.
					Query().
					Where(
						senderordertoken.HasSenderWith(
							senderprofile.IDEQ(senderProfile.ID),
						),
						senderordertoken.HasTokenWith(tokenDB.IDEQ(testCtx.token.ID)),
					).
					Only(context.Background())
				assert.NoError(t, err)
				assert.Equal(t, senderorder.FeeAddress, "0xD4EB9067111F81b9bAabE06E2b8ebBaDADEd5DAf")
				assert.Equal(t, senderorder.RefundAddress, "0xD4EB9067111F81b9bAabE06E2b8ebBaDADEd5DA0")
			})
			assert.Contains(t, senderProfile.DomainWhitelist, "mydomain.com")
			assert.True(t, senderProfile.IsActive)
		})

	})

	t.Run("UpdateProviderProfile", func(t *testing.T) {

		t.Run("with all fields complete and check if it is active", func(t *testing.T) {
			// Test partial update
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}
			payload := types.ProviderProfilePayload{
				TradingName:      "My Trading Name",
				Currencies:       []string{"KES"},
				HostIdentifier:   "example.com",
				BusinessDocument: "https://example.com/business_doc.png",
				IdentityDocument: "https://example.com/national_id.png",
				IsAvailable:      true,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Profile updated successfully", response.Message)
			assert.Nil(t, response.Data, "response.Data is not nil")

			providerProfile, err := db.Client.ProviderProfile.
				Query().
				Where(providerprofile.HasUserWith(user.ID(testCtx.user.ID))).
				WithCurrencies().
				Only(context.Background())
			assert.NoError(t, err)

			assert.Contains(t, providerProfile.TradingName, payload.TradingName)
			assert.Contains(t, providerProfile.HostIdentifier, payload.HostIdentifier)
			// assert.Contains(t, providerProfile.Edges.Currency.Code, payload.Currency)
			assert.Contains(t, providerProfile.BusinessDocument, payload.BusinessDocument)
			assert.Contains(t, providerProfile.IdentityDocument, payload.IdentityDocument)
			assert.True(t, providerProfile.IsActive)
			// assert for currencies
			assert.Equal(t, len(providerProfile.Edges.Currencies), 1)
			assert.Equal(t, providerProfile.Edges.Currencies[0].Code, payload.Currencies[0])
		})

		t.Run("with token rate slippage", func(t *testing.T) {
			profileUpdateRequest := func(payload types.ProviderProfilePayload) *httptest.ResponseRecorder {
				accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
				headers := map[string]string{
					"Authorization": "Bearer " + accessToken,
				}
				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				return res
			}

			// Base token payload with required fields
			baseTokenPayload := types.ProviderOrderTokenPayload{
				Symbol:                 "TST",
				ConversionRateType:     providerordertoken.ConversionRateTypeFixed,
				FixedConversionRate:    decimal.NewFromFloat(50000),
				FloatingConversionRate: decimal.NewFromFloat(0),
				MaxOrderAmount:         decimal.NewFromFloat(1),
				MinOrderAmount:         decimal.NewFromFloat(0.001),
				RateSlippage:           decimal.NewFromFloat(10),
			}

			t.Run("fails when rate slippage exceeds 20%", func(t *testing.T) {

				tokenPayload := baseTokenPayload
				tokenPayload.RateSlippage = decimal.NewFromFloat(25) // 25% slippage

				payload := types.ProviderProfilePayload{
					TradingName:    testCtx.providerProfile.TradingName,
					HostIdentifier: testCtx.providerProfile.HostIdentifier,
					Currencies:     []string{"KES"},
					Tokens:         []types.ProviderOrderTokenPayload{tokenPayload},
				}

				res := profileUpdateRequest(payload)
				assert.Equal(t, http.StatusBadRequest, res.Code)

				var response types.Response
				err := json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Rate slippage cannot exceed 20% of market rate", response.Message)

			})

			t.Run("succeeds with valid rate slippage", func(t *testing.T) {
				tokenPayload := baseTokenPayload
				tokenPayload.RateSlippage = decimal.NewFromFloat(15) // 15% slippage

				payload := types.ProviderProfilePayload{
					TradingName:    testCtx.providerProfile.TradingName,
					HostIdentifier: testCtx.providerProfile.HostIdentifier,
					Currencies:     []string{"KES"},
					Tokens:         []types.ProviderOrderTokenPayload{tokenPayload},
				}

				res := profileUpdateRequest(payload)
				assert.Equal(t, http.StatusOK, res.Code)

				var response types.Response
				err := json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Profile updated successfully", response.Message)

				// Verify the rate slippage was saved correctly
				providerToken, err := db.Client.ProviderOrderToken.
					Query().
					Where(
						// providerordertoken.SymbolEQ("TST"),
						providerordertoken.HasProviderWith(providerprofile.IDEQ(testCtx.providerProfile.ID)),
					).
					Only(context.Background())

				assert.NoError(t, err)
				assert.Equal(t, decimal.NewFromFloat(15), providerToken.RateSlippage)
			})

			t.Run("defaults to zero slippage when not specified", func(t *testing.T) {
				tokenPayload := baseTokenPayload
				// Don't set RateSlippage field

				payload := types.ProviderProfilePayload{
					TradingName:    testCtx.providerProfile.TradingName,
					HostIdentifier: testCtx.providerProfile.HostIdentifier,
					Currencies:     []string{"KES"},
					Tokens:         []types.ProviderOrderTokenPayload{tokenPayload},
				}

				res := profileUpdateRequest(payload)
				assert.Equal(t, http.StatusOK, res.Code)

				// Verify the rate slippage defaulted to zero
				providerToken, err := db.Client.ProviderOrderToken.
					Query().
					Where(
						// providerordertoken.SymbolEQ("TST"),
						providerordertoken.HasProviderWith(providerprofile.IDEQ(testCtx.providerProfile.ID)),
					).
					Only(context.Background())

				assert.NoError(t, err)
				assert.True(t, providerToken.RateSlippage.IsZero())
			})

			t.Run("uses token-specific slippage during rate matching", func(t *testing.T) {
				tokenPayload := baseTokenPayload
				tokenPayload.RateSlippage = decimal.NewFromFloat(15) // 15% slippage

				payload := types.ProviderProfilePayload{
					TradingName:    testCtx.providerProfile.TradingName,
					HostIdentifier: testCtx.providerProfile.HostIdentifier,
					Currencies:     []string{"KES"},
					Tokens:         []types.ProviderOrderTokenPayload{tokenPayload},
				}

				accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
				headers := map[string]string{
					"Authorization": "Bearer " + accessToken,
				}

				// Update profile with token
				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				assert.Equal(t, http.StatusOK, res.Code)

				// Retrieve the saved provider token
				providerToken, err := db.Client.ProviderOrderToken.
					Query().
					Where(
						// providerordertoken.SymbolEQ("TST"),
						providerordertoken.HasProviderWith(providerprofile.IDEQ(testCtx.providerProfile.ID)),
					).
					Only(context.Background())
				assert.NoError(t, err)

				// Simulate rate matching logic
				marketRate := decimal.NewFromFloat(100)
				allowedDeviation := marketRate.Mul(providerToken.RateSlippage.Div(decimal.NewFromInt(100)))

				// Test various rates within and outside slippage
				withinSlippageRate := decimal.NewFromFloat(115)  // within 15%
				outsideSlippageRate := decimal.NewFromFloat(116) // outside 15%

				assert.True(t,
					withinSlippageRate.Sub(marketRate).Abs().LessThanOrEqual(allowedDeviation),
					"Rate should match within token-specific slippage",
				)
				assert.False(t,
					outsideSlippageRate.Sub(marketRate).Abs().LessThanOrEqual(allowedDeviation),
					"Rate should not match outside token-specific slippage",
				)
			})

		})

		t.Run("with visibility", func(t *testing.T) {
			// Test partial update
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}
			payload := types.ProviderProfilePayload{
				VisibilityMode: "private",
				TradingName:    testCtx.providerProfile.TradingName,
				HostIdentifier: testCtx.providerProfile.HostIdentifier,
				Currencies:     []string{"KES"},
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Profile updated successfully", response.Message)
			assert.Nil(t, response.Data, "response.Data is not nil")

			providerProfile, err := db.Client.ProviderProfile.Query().
				Where(providerprofile.VisibilityModeEQ(providerprofile.VisibilityModePrivate)).
				Count(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, 1, providerProfile)
		})

		t.Run("with optional fields", func(t *testing.T) {
			profileUpdateRequest := func(payload types.ProviderProfilePayload) *httptest.ResponseRecorder {
				// Test partial update
				accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
				headers := map[string]string{
					"Authorization": "Bearer " + accessToken,
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)

				return res
			}
			t.Run("fails for invalid mobile number", func(t *testing.T) {
				payload := types.ProviderProfilePayload{
					MobileNumber:   "01234567890",
					TradingName:    testCtx.providerProfile.TradingName,
					HostIdentifier: testCtx.providerProfile.HostIdentifier,
					Currencies:     []string{"KES"},
				}
				res1 := profileUpdateRequest(payload)

				payload.MobileNumber = "+023456789029"
				res2 := profileUpdateRequest(payload)

				// Assert the response body
				assert.Equal(t, http.StatusBadRequest, res1.Code)
				assert.Equal(t, http.StatusBadRequest, res2.Code)

				var response types.Response
				err = json.Unmarshal(res1.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid mobile number", response.Message)

				err = json.Unmarshal(res2.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid mobile number", response.Message)
			})

			t.Run("success for valid moblie number", func(t *testing.T) {
				payload := types.ProviderProfilePayload{
					MobileNumber:   "+2347012345678",
					TradingName:    testCtx.providerProfile.TradingName,
					HostIdentifier: testCtx.providerProfile.HostIdentifier,
					Currencies:     []string{"KES"},
				}
				res := profileUpdateRequest(payload)

				// Assert the response body
				assert.Equal(t, http.StatusOK, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Profile updated successfully", response.Message)

				// Assert optional fields were correctly set and retrieved
				providerProfile, err := db.Client.ProviderProfile.
					Query().
					Where(providerprofile.HasUserWith(user.ID(testCtx.user.ID))).
					Only(context.Background())
				assert.NoError(t, err)

				assert.Equal(t, providerProfile.MobileNumber, "+2347012345678")
			})

			t.Run("fails for invalid identity document type", func(t *testing.T) {
				payload := types.ProviderProfilePayload{
					IdentityDocumentType: "student_id",
					TradingName:          testCtx.providerProfile.TradingName,
					HostIdentifier:       testCtx.providerProfile.HostIdentifier,
				}
				res1 := profileUpdateRequest(payload)

				payload.IdentityDocumentType = "bank_statement"
				res2 := profileUpdateRequest(payload)

				// Assert the response body
				assert.Equal(t, http.StatusBadRequest, res1.Code)
				assert.Equal(t, http.StatusBadRequest, res2.Code)

				var response types.Response
				err = json.Unmarshal(res1.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid identity document type", response.Message)

				err = json.Unmarshal(res2.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid identity document type", response.Message)
			})

			t.Run("fails for invalid identity document url", func(t *testing.T) {
				payload := types.ProviderProfilePayload{
					IdentityDocument: "img.png",
					TradingName:      testCtx.providerProfile.TradingName,
					HostIdentifier:   testCtx.providerProfile.HostIdentifier,
				}
				res1 := profileUpdateRequest(payload)

				payload.IdentityDocument = "ftp://123.example.com/file.png"
				res2 := profileUpdateRequest(payload)

				// Assert the response body
				assert.Equal(t, http.StatusBadRequest, res1.Code)
				assert.Equal(t, http.StatusBadRequest, res2.Code)

				var response types.Response
				err = json.Unmarshal(res1.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid identity document URL", response.Message)

				err = json.Unmarshal(res2.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid identity document URL", response.Message)
				// assert.Nil(t, response.Data, "response.Data is not nil")
			})

			t.Run("fails for invalid business document url", func(t *testing.T) {
				payload := types.ProviderProfilePayload{
					BusinessDocument: "http://123.example.com/file.ai",
					TradingName:      testCtx.providerProfile.TradingName,
					HostIdentifier:   testCtx.providerProfile.HostIdentifier,
				}
				res := profileUpdateRequest(payload)
				// Assert the response body
				assert.Equal(t, http.StatusBadRequest, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Invalid business document URL", response.Message)
				// assert.Nil(t, response.Data, "response.Data is not nil")
			})

			t.Run("succeeds with valid optional fields", func(t *testing.T) {
				payload := types.ProviderProfilePayload{
					Address:              "123, Example Street, Nairobi, Kenya",
					MobileNumber:         "+2347012345678",
					DateOfBirth:          time.Date(2022, time.January, 1, 12, 30, 0, 0, time.UTC),
					BusinessName:         "Example Business",
					IdentityDocumentType: "national_id",
					IdentityDocument:     "https://example.com/national_id.png",
					BusinessDocument:     "https://example.com/business_doc.png",
					TradingName:          testCtx.providerProfile.TradingName,
					HostIdentifier:       testCtx.providerProfile.HostIdentifier,
				}
				res := profileUpdateRequest(payload)
				// Assert the response body
				assert.Equal(t, http.StatusOK, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Profile updated successfully", response.Message)

				// Assert optional fields were correctly set and retrieved
				providerProfile, err := db.Client.ProviderProfile.
					Query().
					Where(providerprofile.HasUserWith(user.ID(testCtx.user.ID))).
					Only(context.Background())
				assert.NoError(t, err)

				assert.Equal(t, providerProfile.Address, "123, Example Street, Nairobi, Kenya")
				assert.Equal(t, providerProfile.MobileNumber, "+2347012345678")
				assert.Equal(t, providerProfile.DateOfBirth, time.Date(2022, time.January, 1, 12, 30, 0, 0, time.UTC))
				assert.Equal(t, providerProfile.BusinessName, "Example Business")
				assert.Equal(t, string(providerProfile.IdentityDocumentType), "national_id")
				assert.Equal(t, providerProfile.IdentityDocument, "https://example.com/national_id.png")
				assert.Equal(t, providerProfile.BusinessDocument, "https://example.com/business_doc.png")
			})

		})

	})

	t.Run("GetProviderProfile", func(t *testing.T) {
		t.Run("with currency filter", func(t *testing.T) {
			ctx := context.Background()

			// Create a USD fiat currency
			usd, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			// Add USD to the provider profile's currencies
			err = db.Client.ProviderProfile.
				UpdateOneID(testCtx.providerProfile.ID).
				AddCurrencies(usd).
				Exec(ctx)
			assert.NoError(t, err)

			// Retrieve the pre-created KES fiat currency (from setup)
			kes, err := db.Client.FiatCurrency.
				Query().
				Where(fiatcurrency.CodeEQ("KES")).
				Only(ctx)
			assert.NoError(t, err)

			// Create a provider order token for KES
			_, err = db.Client.ProviderOrderToken.
				Create().
				SetProviderID(testCtx.providerProfile.ID).
				SetTokenID(testCtx.token.ID).
				SetCurrencyID(kes.ID).
				SetConversionRateType("floating").
				SetFixedConversionRate(decimal.NewFromInt(0)).
				SetFloatingConversionRate(decimal.NewFromInt(1)).
				SetMaxOrderAmount(decimal.NewFromInt(100)).
				SetMinOrderAmount(decimal.NewFromInt(1)).
				SetAddress("address_kes").
				SetNetwork("polygon").
				Save(ctx)
			assert.NoError(t, err)

			// Create a provider order token for USD
			_, err = db.Client.ProviderOrderToken.
				Create().
				SetProviderID(testCtx.providerProfile.ID).
				SetTokenID(testCtx.token.ID).
				SetCurrencyID(usd.ID).
				SetConversionRateType("floating").
				SetFixedConversionRate(decimal.NewFromInt(0)).
				SetFloatingConversionRate(decimal.NewFromInt(2)).
				SetMaxOrderAmount(decimal.NewFromInt(200)).
				SetMinOrderAmount(decimal.NewFromInt(10)).
				SetAddress("address_usd").
				SetNetwork("polygon").
				Save(ctx)
			assert.NoError(t, err)

			// Generate a provider API key
			apiKeyService := services.NewAPIKeyService()
			_, _, err = apiKeyService.GenerateAPIKey(
				context.Background(),
				nil,
				nil,
				testCtx.providerProfile,
			)
			assert.NoError(t, err)

			// Prepare a GET request with a currency filter for KES
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}
			resKES, err := test.PerformRequest(t, "GET", "/settings/provider?currency=KES", nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, resKES.Code)

			var respKES struct {
				Data    types.ProviderProfileResponse `json:"data"`
				Message string                        `json:"message"`
				Status  string                        `json:"status"`
			}
			err = json.Unmarshal(resKES.Body.Bytes(), &respKES)
			assert.NoError(t, err)
			// Expect only one token when filtering by KES
			assert.Len(t, respKES.Data.Tokens, 1)
			if len(respKES.Data.Tokens) > 0 {
				assert.Equal(t, "KES", respKES.Data.Tokens[0].Currency)
			}

			// Perform a GET request with no currency filter to retrieve both tokens
			resAll, err := test.PerformRequest(t, "GET", "/settings/provider", nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, resAll.Code)

			var respAll struct {
				Data    types.ProviderProfileResponse `json:"data"`
				Message string                        `json:"message"`
				Status  string                        `json:"status"`
			}
			err = json.Unmarshal(resAll.Body.Bytes(), &respAll)
			assert.NoError(t, err)
			// Expect two tokens (one for KES and one for USD)
			assert.Len(t, respAll.Data.Tokens, 2)

		})
	})

}
