package accounts

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
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
	"github.com/paycrest/aggregator/ent/migrate"
	"github.com/paycrest/aggregator/ent/providerbankaccount"
	"github.com/paycrest/aggregator/ent/providercurrencies"
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
	orderToken      *ent.ProviderOrderToken
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

	providerProfile, err := test.CreateTestProviderProfile(map[string]interface{}{
		"user_id":     testCtx.user.ID,
		"currency_id": currency.ID,
	})
	if err != nil {
		return err
	}

	testCtx.providerProfile = providerProfile
	orderToken, err := test.AddProviderOrderTokenToProvider(map[string]interface{}{
		"fixed_conversion_rate":    decimal.NewFromFloat(550),
		"conversion_rate_type":     "fixed",
		"floating_conversion_rate": decimal.NewFromFloat(0),
		"provider":                 testCtx.providerProfile,
		"token_id":                 testCtx.token.ID,
		"currency_id":              currency.ID,
	})
	if err != nil {
		return err
	}
	testCtx.orderToken = orderToken

	return nil
}

func TestProfile(t *testing.T) {
	// Set up test database client
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	defer client.Close()

	// Run schema migrations
	if err := client.Schema.Create(context.Background(), migrate.WithGlobalUniqueID(true)); err != nil {
		t.Fatal(err)
	}

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
	router.POST(
		"/settings/provider/bank-accounts",
		middleware.JWTMiddleware,
		middleware.OnlyProviderMiddleware,
		ctrl.CreateBankAccount,
	)
	router.GET(
		"/settings/provider/bank-accounts",
		middleware.JWTMiddleware,
		middleware.OnlyProviderMiddleware,
		ctrl.ListBankAccounts,
	)
	router.DELETE(
		"/settings/provider/bank-accounts/:id",
		middleware.JWTMiddleware,
		middleware.OnlyProviderMiddleware,
		ctrl.DeleteBankAccount,
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
		profileUpdateRequest := func(payload types.ProviderProfilePayload) *httptest.ResponseRecorder {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}
			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			return res
		}

		t.Run("with all fields complete and check if it is active", func(t *testing.T) {
			// Test partial update
			payload := types.ProviderProfilePayload{
				TradingName:    "My Trading Name",
				Currency:       "KES",
				HostIdentifier: "https://example.com",
				IsAvailable:    true,
			}

			res := profileUpdateRequest(payload)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Profile updated successfully", response.Message)
			assert.Nil(t, response.Data, "response.Data is not nil")

			providerProfile, err := db.Client.ProviderProfile.
				Query().
				Where(
					providerprofile.HasUserWith(user.ID(testCtx.user.ID)),
					providerprofile.HasProviderCurrenciesWith(
						providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(payload.Currency)),
					),
				).
				WithProviderCurrencies(
					func(query *ent.ProviderCurrenciesQuery) {
						query.WithCurrency()
					},
				).
				Only(context.Background())
			assert.NoError(t, err)

			assert.Equal(t, payload.TradingName, providerProfile.TradingName)
			assert.Equal(t, payload.HostIdentifier, providerProfile.HostIdentifier)
			// assert for currencies
			assert.Equal(t, len(providerProfile.Edges.ProviderCurrencies), 1)
			assert.Equal(t, providerProfile.Edges.ProviderCurrencies[0].Edges.Currency.Code, payload.Currency)
			// assert availability from ProviderCurrencies
			assert.True(t, providerProfile.Edges.ProviderCurrencies[0].IsAvailable)
		})

		t.Run("with availability set to false", func(t *testing.T) {
			payload := types.ProviderProfilePayload{
				TradingName:    "Updated Trading Name",
				HostIdentifier: testCtx.providerProfile.HostIdentifier,
				Currency:       "KES",
				IsAvailable:    false,
			}

			res := profileUpdateRequest(payload)

			// Assert the response body
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Profile updated successfully", response.Message)

			// Assert fields were correctly updated
			providerProfile, err := db.Client.ProviderProfile.
				Query().
				Where(providerprofile.HasUserWith(user.ID(testCtx.user.ID))).
				WithProviderCurrencies(
					func(query *ent.ProviderCurrenciesQuery) {
						query.WithCurrency()
					},
				).
				Only(context.Background())
			assert.NoError(t, err)

			assert.Equal(t, "Updated Trading Name", providerProfile.TradingName)

			// Assert availability from ProviderCurrencies
			assert.Len(t, providerProfile.Edges.ProviderCurrencies, 1)
			assert.False(t, providerProfile.Edges.ProviderCurrencies[0].IsAvailable)
		})

		t.Run("with token rate slippage", func(t *testing.T) {

			t.Run("fails when rate slippage exceeds 5 percent of market rate", func(t *testing.T) {
				payload := types.ProviderProfilePayload{
					TradingName:    testCtx.providerProfile.TradingName,
					HostIdentifier: testCtx.providerProfile.HostIdentifier,
					Currency:       "KES",
					Tokens: []types.ProviderOrderTokenPayload{{
						Symbol:       testCtx.orderToken.Edges.Token.Symbol,
						Network:      testCtx.orderToken.Network,
						RateSlippage: decimal.NewFromFloat(25), // 25% slippage
					}},
				}
				res := profileUpdateRequest(payload)
				assert.Equal(t, http.StatusBadRequest, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Rate slippage is too high for TST", response.Message)
			})

			t.Run("fails when rate slippage is less than 0.1", func(t *testing.T) {
				payload := types.ProviderProfilePayload{
					TradingName:    testCtx.providerProfile.TradingName,
					HostIdentifier: testCtx.providerProfile.HostIdentifier,
					Currency:       "KES",
					Tokens: []types.ProviderOrderTokenPayload{{
						Symbol:       testCtx.orderToken.Edges.Token.Symbol,
						Network:      testCtx.orderToken.Network,
						RateSlippage: decimal.NewFromFloat(0.09), // 0.09% slippage
					}},
				}
				res := profileUpdateRequest(payload)
				assert.Equal(t, http.StatusBadRequest, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Rate slippage cannot be less than 0.1% for TST", response.Message)
			})

			t.Run("succeeds with valid rate slippage", func(t *testing.T) {
				payload := types.ProviderProfilePayload{
					TradingName:    testCtx.providerProfile.TradingName,
					HostIdentifier: testCtx.providerProfile.HostIdentifier,
					Currency:       "KES",
					Tokens: []types.ProviderOrderTokenPayload{{
						Symbol:                 testCtx.orderToken.Edges.Token.Symbol,
						ConversionRateType:     testCtx.orderToken.ConversionRateType,
						FixedConversionRate:    testCtx.orderToken.FixedConversionRate,
						FloatingConversionRate: testCtx.orderToken.FloatingConversionRate,
						MaxOrderAmount:         testCtx.orderToken.MaxOrderAmount,
						MinOrderAmount:         testCtx.orderToken.MinOrderAmount,
						Network:                testCtx.orderToken.Network,
						RateSlippage:           decimal.NewFromFloat(5), // 5% slippage
					}},
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
						providerordertoken.HasProviderWith(providerprofile.IDEQ(testCtx.providerProfile.ID)),
					).
					Only(context.Background())

				assert.NoError(t, err)
				assert.Equal(t, decimal.NewFromFloat(5), providerToken.RateSlippage)
			})

			// TODO: restore when dashboard has been updated
			// t.Run("defaults to 0%% slippage when not specified", func(t *testing.T) {
			// 	payload := types.ProviderProfilePayload{
			// 		TradingName:    testCtx.providerProfile.TradingName,
			// 		HostIdentifier: testCtx.providerProfile.HostIdentifier,
			// 		Currencies:     []string{"KES"},
			// 		Tokens: []types.ProviderOrderTokenPayload{{
			// 			Currency:               testCtx.orderToken.Edges.Currency.Code,
			// 			Symbol:                 testCtx.orderToken.Edges.Token.Symbol,
			// 			ConversionRateType:     testCtx.orderToken.ConversionRateType,
			// 			FixedConversionRate:    testCtx.orderToken.FixedConversionRate,
			// 			FloatingConversionRate: testCtx.orderToken.FloatingConversionRate,
			// 			MaxOrderAmount:         testCtx.orderToken.MaxOrderAmount,
			// 			MinOrderAmount:         testCtx.orderToken.MinOrderAmount,
			// 			Network:                testCtx.orderToken.Network,
			// 		}},
			// 	}
			// 	res := profileUpdateRequest(payload)
			// 	assert.Equal(t, http.StatusOK, res.Code)

			// 	// Verify the rate slippage defaulted to 0%
			// 	providerToken, err := db.Client.ProviderOrderToken.
			// 		Query().
			// 		Where(
			// 			providerordertoken.HasProviderWith(providerprofile.IDEQ(testCtx.providerProfile.ID)),
			// 		).
			// 		Only(context.Background())

			// 	assert.NoError(t, err)
			// 	assert.Equal(t, decimal.NewFromFloat(0), providerToken.RateSlippage)
			// })
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
				Currency:       "KES",
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

			t.Run("success for valid provider profile fields", func(t *testing.T) {
				payload := types.ProviderProfilePayload{
					TradingName:    "Updated Trading Name",
					HostIdentifier: testCtx.providerProfile.HostIdentifier,
					Currency:       "KES",
					VisibilityMode: "public",
					IsAvailable:    true,
				}
				res := profileUpdateRequest(payload)

				// Assert the response body
				assert.Equal(t, http.StatusOK, res.Code)

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Profile updated successfully", response.Message)

				// Assert fields were correctly updated
				providerProfile, err := db.Client.ProviderProfile.
					Query().
					Where(
						providerprofile.HasUserWith(user.ID(testCtx.user.ID)),
						providerprofile.HasProviderCurrenciesWith(
							providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(payload.Currency)),
						),
					).
					WithProviderCurrencies().
					Only(context.Background())
				assert.NoError(t, err)

				assert.Equal(t, "Updated Trading Name", providerProfile.TradingName)
				assert.Equal(t, "public", string(providerProfile.VisibilityMode))

				// Assert availability from ProviderCurrencies
				assert.Len(t, providerProfile.Edges.ProviderCurrencies, 1)
				assert.True(t, providerProfile.Edges.ProviderCurrencies[0].IsAvailable)

			})
		})

		t.Run("HostIdentifier URL validation", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			t.Run("fails for HTTP URL", func(t *testing.T) {
				payload := types.ProviderProfilePayload{
					TradingName:    "Paycrest Profile",
					HostIdentifier: "http://example.com",
					Currency:       "KES",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				assert.Equal(t, http.StatusBadRequest, res.Code)
				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Host identifier must use HTTPS protocol and be a valid URL", response.Message)
				assert.NotNil(t, response.Data, "Response data should not be nil")
			})

			t.Run("fails for malformed URL", func(t *testing.T) {
				payload := types.ProviderProfilePayload{
					TradingName:    "Paycrest Profile",
					HostIdentifier: "not-a-valid-url",
					Currency:       "KES",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				assert.Equal(t, http.StatusBadRequest, res.Code)
				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Host identifier must use HTTPS protocol and be a valid URL", response.Message)
			})

			t.Run("fails for URL without host", func(t *testing.T) {
				payload := types.ProviderProfilePayload{
					TradingName:    "Paycrest Profile",
					HostIdentifier: "https://",
					Currency:       "KES",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				assert.Equal(t, http.StatusBadRequest, res.Code)
				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Host identifier must use HTTPS protocol and be a valid URL", response.Message)
			})

			t.Run("succeeds with valid HTTPS URL", func(t *testing.T) {
				payload := types.ProviderProfilePayload{
					TradingName:    "Paycrest Profile",
					HostIdentifier: "https://example.com",
					Currency:       "KES",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				assert.Equal(t, http.StatusOK, res.Code)
				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Profile updated successfully", response.Message)
				providerProfile, err := db.Client.ProviderProfile.
					Query().
					Where(providerprofile.HasUserWith(user.ID(testCtx.user.ID))).
					Only(context.Background())
				assert.NoError(t, err)
				assert.Equal(t, "https://example.com", providerProfile.HostIdentifier)
			})
		})
	})

	t.Run("GetSenderProfile", func(t *testing.T) {
		testUser, err := test.CreateTestUser(map[string]interface{}{
			"email": "hello@test.com",
			"scope": "sender",
		})
		assert.NoError(t, err)

		sender, err := test.CreateTestSenderProfile(map[string]interface{}{
			"domain_whitelist": []string{"mydomain.com"},
			"user_id":          testUser.ID,
		})
		assert.NoError(t, err)

		apiKeyService := services.NewAPIKeyService()
		_, _, err = apiKeyService.GenerateAPIKey(
			context.Background(),
			nil,
			sender,
			nil,
		)
		assert.NoError(t, err)

		accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
		headers := map[string]string{
			"Authorization": "Bearer " + accessToken,
		}
		res, err := test.PerformRequest(t, "GET", "/settings/sender", nil, headers, router)
		assert.NoError(t, err)

		// Assert the response body
		assert.Equal(t, http.StatusOK, res.Code)
		var response struct {
			Data    types.SenderProfileResponse
			Message string
		}
		err = json.Unmarshal(res.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "Profile retrieved successfully", response.Message)
		assert.NotNil(t, response.Data, "response.Data is nil")
		assert.Greater(t, len(response.Data.Tokens), 0)
		assert.Contains(t, response.Data.WebhookURL, "https://example.com")
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
			_, err = db.Client.ProviderCurrencies.
				Create().
				SetProviderID(testCtx.providerProfile.ID).
				SetCurrency(usd).
				SetAvailableBalance(decimal.Zero).
				SetTotalBalance(decimal.Zero).
				SetReservedBalance(decimal.Zero).
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
				SetRateSlippage(decimal.NewFromInt(0)).
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
	t.Run("CreateBankAccount", func(t *testing.T) {
		ctx := context.Background()

		institution, err := db.Client.Institution.
			Create().
			SetCode("ZENITH").
			SetName("Zenith Bank").
			SetType("bank").
			Save(ctx)
		assert.NoError(t, err)

		accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
		headers := map[string]string{
			"Authorization": "Bearer " + accessToken,
		}

		t.Run("successfully creates a bank account", func(t *testing.T) {
			payload := types.CreateBankAccountPayload{
				AccountIdentifier: "1234567890",
				AccountName:       "John Doe",
				Institution:       institution.Code,
			}

			res, err := test.PerformRequest(t, "POST", "/settings/provider/bank-accounts", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusCreated, res.Code)

			var response struct {
				Data    types.BankAccountResponse `json:"data"`
				Message string                    `json:"message"`
				Status  string                    `json:"status"`
			}
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Bank account created successfully", response.Message)
			assert.Equal(t, "success", response.Status)
			assert.Equal(t, payload.AccountIdentifier, response.Data.AccountIdentifier)
			assert.Equal(t, payload.AccountName, response.Data.AccountName)
			assert.Equal(t, payload.Institution, response.Data.Institution)
			assert.NotEqual(t, uuid.Nil, response.Data.ID)
		})

		t.Run("successfully creates a bank account without account name", func(t *testing.T) {
			payload := types.CreateBankAccountPayload{
				AccountIdentifier: "0987654321",
				Institution:       institution.Code,
			}

			res, err := test.PerformRequest(t, "POST", "/settings/provider/bank-accounts", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusCreated, res.Code)

			var response struct {
				Data    types.BankAccountResponse `json:"data"`
				Message string                    `json:"message"`
				Status  string                    `json:"status"`
			}
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "success", response.Status)
			assert.Equal(t, payload.AccountIdentifier, response.Data.AccountIdentifier)
			assert.Empty(t, response.Data.AccountName)
		})

		t.Run("fails with invalid payload", func(t *testing.T) {
			payload := map[string]interface{}{
				"account_identifier": "",
				"institution":        "",
			}

			res, err := test.PerformRequest(t, "POST", "/settings/provider/bank-accounts", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "error", response.Status)
			assert.Equal(t, "Failed to validate payload", response.Message)
		})

		t.Run("fails with unsupported institution", func(t *testing.T) {
			payload := types.CreateBankAccountPayload{
				AccountIdentifier: "1111111111",
				Institution:       "UNSUPPORTED_BANK",
			}

			res, err := test.PerformRequest(t, "POST", "/settings/provider/bank-accounts", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "error", response.Status)
			assert.Contains(t, response.Message, "is not supported")
		})

		t.Run("fails when duplicate account exists", func(t *testing.T) {
			payload := types.CreateBankAccountPayload{
				AccountIdentifier: "2222222222",
				Institution:       institution.Code,
			}

			res, err := test.PerformRequest(t, "POST", "/settings/provider/bank-accounts", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusCreated, res.Code)

			res, err = test.PerformRequest(t, "POST", "/settings/provider/bank-accounts", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusConflict, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "error", response.Status)
			assert.Contains(t, response.Message, "already exists")
		})

		t.Run("fails without authentication", func(t *testing.T) {
			payload := types.CreateBankAccountPayload{
				AccountIdentifier: "3333333333",
				Institution:       institution.Code,
			}

			res, err := test.PerformRequest(t, "POST", "/settings/provider/bank-accounts", payload, nil, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusUnauthorized, res.Code)
		})

		t.Run("allows same account at different institutions", func(t *testing.T) {
			anotherInstitution, err := db.Client.Institution.
				Create().
				SetCode("GTB").
				SetName("Guaranty Trust Bank").
				SetType("bank").
				Save(ctx)
			assert.NoError(t, err)

			payload := types.CreateBankAccountPayload{
				AccountIdentifier: "1234567890", 
				Institution:       anotherInstitution.Code,
			}

			res, err := test.PerformRequest(t, "POST", "/settings/provider/bank-accounts", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusCreated, res.Code)

			var response struct {
				Data    types.BankAccountResponse `json:"data"`
				Message string                    `json:"message"`
				Status  string                    `json:"status"`
			}
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "success", response.Status)
			assert.Equal(t, anotherInstitution.Code, response.Data.Institution)
		})
	})

	t.Run("ListBankAccounts", func(t *testing.T) {
		ctx := context.Background()

		institution1, err := db.Client.Institution.
			Create().
			SetCode("WEMA").
			SetName("Wema Bank").
			SetType("bank").
			Save(ctx)
		assert.NoError(t, err)

		institution2, err := db.Client.Institution.
			Create().
			SetCode("FIRST_BANK").
			SetName("First Bank").
			SetType("bank").
			Save(ctx)
		assert.NoError(t, err)

		// Create test bank accounts
		_, err = db.Client.ProviderBankAccount.
			Create().
			SetAccountIdentifier("4444444444").
			SetAccountName("Account One").
			SetInstitution(institution1.Code).
			SetProviderID(testCtx.providerProfile.ID).
			Save(ctx)
		assert.NoError(t, err)

		_, err = db.Client.ProviderBankAccount.
			Create().
			SetAccountIdentifier("5555555555").
			SetAccountName("Account Two").
			SetInstitution(institution2.Code).
			SetProviderID(testCtx.providerProfile.ID).
			Save(ctx)
		assert.NoError(t, err)

		accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
		headers := map[string]string{
			"Authorization": "Bearer " + accessToken,
		}

		t.Run("successfully lists all bank accounts", func(t *testing.T) {
			res, err := test.PerformRequest(t, "GET", "/settings/provider/bank-accounts", nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)

			var response struct {
				Data    types.BankAccountListResponse `json:"data"`
				Message string                        `json:"message"`
				Status  string                        `json:"status"`
			}
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "success", response.Status)
			assert.Equal(t, "Bank accounts retrieved successfully", response.Message)
			assert.GreaterOrEqual(t, response.Data.TotalRecords, 2)
			assert.GreaterOrEqual(t, len(response.Data.Accounts), 2)
		})

		t.Run("successfully filters by institution", func(t *testing.T) {
			res, err := test.PerformRequest(t, "GET", "/settings/provider/bank-accounts?institution="+institution1.Code, nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)

			var response struct {
				Data    types.BankAccountListResponse `json:"data"`
				Message string                        `json:"message"`
				Status  string                        `json:"status"`
			}
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "success", response.Status)

			// Verify all returned accounts are from the filtered institution
			for _, account := range response.Data.Accounts {
				assert.Equal(t, institution1.Code, account.Institution)
			}
		})

		t.Run("returns empty list when no accounts match filter", func(t *testing.T) {
			res, err := test.PerformRequest(t, "GET", "/settings/provider/bank-accounts?institution=NONEXISTENT", nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)

			var response struct {
				Data    types.BankAccountListResponse `json:"data"`
				Message string                        `json:"message"`
				Status  string                        `json:"status"`
			}
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "success", response.Status)
			assert.Equal(t, 0, response.Data.TotalRecords)
			assert.Empty(t, response.Data.Accounts)
		})

		t.Run("fails without authentication", func(t *testing.T) {
			res, err := test.PerformRequest(t, "GET", "/settings/provider/bank-accounts", nil, nil, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusUnauthorized, res.Code)
		})
	})

	t.Run("DeleteBankAccount", func(t *testing.T) {
		ctx := context.Background()

		// Create a test institution
		institution, err := db.Client.Institution.
			Create().
			SetCode("ACCESS").
			SetName("Access Bank").
			SetType("bank").
			Save(ctx)
		assert.NoError(t, err)

		accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
		headers := map[string]string{
			"Authorization": "Bearer " + accessToken,
		}

		t.Run("successfully deletes a bank account", func(t *testing.T) {
			// Create an account to delete
			account, err := db.Client.ProviderBankAccount.
				Create().
				SetAccountIdentifier("6666666666").
				SetAccountName("Account to Delete").
				SetInstitution(institution.Code).
				SetProviderID(testCtx.providerProfile.ID).
				Save(ctx)
			assert.NoError(t, err)

			res, err := test.PerformRequest(t, "DELETE", "/settings/provider/bank-accounts/"+account.ID.String(), nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "success", response.Status)
			assert.Equal(t, "Bank account deleted successfully", response.Message)

			// Verify the account was deleted
			exists, err := db.Client.ProviderBankAccount.
				Query().
				Where(providerbankaccount.IDEQ(account.ID)).
				Exist(ctx)
			assert.NoError(t, err)
			assert.False(t, exists)
		})

		t.Run("fails with invalid account ID format", func(t *testing.T) {
			res, err := test.PerformRequest(t, "DELETE", "/settings/provider/bank-accounts/invalid-uuid", nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "error", response.Status)
			assert.Equal(t, "Invalid account ID", response.Message)
		})

		t.Run("fails when account does not exist", func(t *testing.T) {
			nonExistentID := uuid.New()
			res, err := test.PerformRequest(t, "DELETE", "/settings/provider/bank-accounts/"+nonExistentID.String(), nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusNotFound, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "error", response.Status)
			assert.Equal(t, "Bank account not found", response.Message)
		})

		t.Run("fails when account belongs to different provider", func(t *testing.T) {
			// Create another provider
			otherUser, err := test.CreateTestUser(map[string]interface{}{
				"scope": "provider",
				"email": "otherprovider@test.com",
			})
			assert.NoError(t, err)

			currency, err := db.Client.FiatCurrency.
				Query().
				Where(fiatcurrency.CodeEQ("KES")).
				Only(ctx)
			assert.NoError(t, err)

			otherProvider, err := test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     otherUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			// Create an account for the other provider
			otherAccount, err := db.Client.ProviderBankAccount.
				Create().
				SetAccountIdentifier("7777777777").
				SetInstitution(institution.Code).
				SetProviderID(otherProvider.ID).
				Save(ctx)
			assert.NoError(t, err)

			// Try to delete the other provider's account
			res, err := test.PerformRequest(t, "DELETE", "/settings/provider/bank-accounts/"+otherAccount.ID.String(), nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusNotFound, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "error", response.Status)
			assert.Equal(t, "Bank account not found", response.Message)

			// Verify the account still exists
			exists, err := db.Client.ProviderBankAccount.
				Query().
				Where(providerbankaccount.IDEQ(otherAccount.ID)).
				Exist(ctx)
			assert.NoError(t, err)
			assert.True(t, exists)
		})

		t.Run("fails without authentication", func(t *testing.T) {
			accountID := uuid.New()
			res, err := test.PerformRequest(t, "DELETE", "/settings/provider/bank-accounts/"+accountID.String(), nil, nil, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusUnauthorized, res.Code)
		})
	})
}
