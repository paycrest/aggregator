package accounts

import (
	"fmt"
	"strings"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
				assert.Equal(t, "Rate slippage is too high", response.Message)
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
				assert.Equal(t, "Rate slippage cannot be less than 0.1%", response.Message)
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


	t.Run("Authentication and Authorization Tests", func(t *testing.T) {
		t.Run("GetSenderProfile fails without JWT token", func(t *testing.T) {
			res, err := test.PerformRequest(t, "GET", "/settings/sender", nil, nil, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusUnauthorized, res.Code)
		})

		t.Run("GetProviderProfile fails without JWT token", func(t *testing.T) {
			res, err := test.PerformRequest(t, "GET", "/settings/provider", nil, nil, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusUnauthorized, res.Code)
		})

		t.Run("UpdateSenderProfile fails without JWT token", func(t *testing.T) {
			payload := types.SenderProfilePayload{
				DomainWhitelist: []string{"example.com"},

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}
			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, nil, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusUnauthorized, res.Code)
		})

		t.Run("UpdateProviderProfile fails without JWT token", func(t *testing.T) {
			payload := types.ProviderProfilePayload{
				TradingName: "Test Name",
				Currency:    "KES",

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}
			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, nil, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusUnauthorized, res.Code)
		})

		t.Run("Sender cannot access provider endpoints", func(t *testing.T) {
			senderUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)
			accessToken, _ := token.GenerateAccessJWT(senderUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}
			res, err := test.PerformRequest(t, "GET", "/settings/provider", nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusForbidden, res.Code)
		})

		t.Run("Provider cannot access sender endpoints", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}
			res, err := test.PerformRequest(t, "GET", "/settings/sender", nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusForbidden, res.Code)
		})

		t.Run("Invalid JWT token fails", func(t *testing.T) {
			headers := map[string]string{
				"Authorization": "Bearer invalid.token.here",

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}
			res, err := test.PerformRequest(t, "GET", "/settings/sender", nil, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusUnauthorized, res.Code)
		})
	})

	t.Run("UpdateSenderProfile Advanced Tests", func(t *testing.T) {
		t.Run("handles empty domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)
			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"domain_whitelist": []string{"example.com"},
				"user_id":          testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}
			payload := types.SenderProfilePayload{
				DomainWhitelist: []string{},

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)

			senderProfile, err := db.Client.SenderProfile.
				Query().
				Where(senderprofile.HasUserWith(user.ID(testUser.ID))).
				Only(context.Background())
			assert.NoError(t, err)
			assert.Empty(t, senderProfile.DomainWhitelist)
		})

		t.Run("handles malformed JSON payload", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)
			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization":  "Bearer " + accessToken,
				"Content-Type":   "application/json",

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			// Send malformed JSON
			res := httptest.NewRecorder()
			req := httptest.NewRequest("PATCH", "/settings/sender", strings.NewReader(`{"invalid": json}`))
			for k, v := range headers {
				req.Header.Set(k, v)

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}
			router.ServeHTTP(res, req)

			assert.Equal(t, http.StatusBadRequest, res.Code)
			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Failed to validate payload", response.Message)
		})

		t.Run("handles webhook URL validation edge cases", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)
			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			// Test various invalid URL formats
			invalidURLs := []string{
				"not-a-url",
				"ftp://example.com",
				"http://",
				"://example.com",
				"example.com",
				" https://example.com ",
				"https://",
				"javascript:alert(1)",

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			for _, invalidURL := range invalidURLs {
				payload := types.SenderProfilePayload{
					WebhookURL: invalidURL,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
				assert.NoError(t, err)
				assert.Equal(t, http.StatusBadRequest, res.Code, fmt.Sprintf("Should reject invalid URL: %s", invalidURL))

				var response types.Response
				err = json.Unmarshal(res.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "Failed to validate payload", response.Message)

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}
		})

		t.Run("handles token address validation for different networks", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)
			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			// Test invalid Ethereum addresses
			invalidEthAddresses := []string{
				"0x123", // Too short
				"123456789012345678901234567890123456789012", // No 0x prefix
				"0xGGGG567890123456789012345678901234567890", // Invalid hex
				"0x0000000000000000000000000000000000000000000", // Too long

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			for _, invalidAddr := range invalidEthAddresses {
				tokenAddresses := []types.SenderOrderAddressPayload{{
					FeeAddress:    invalidAddr,
					Network:       testCtx.token.Edges.Network.Identifier,
					RefundAddress: "0xD4EB9067111F81b9bAabE06E2b8ebBaDADEd5DA0",

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
				}}

				tokenPayload := []types.SenderOrderTokenPayload{{
					Symbol:    testCtx.token.Symbol,
					Addresses: tokenAddresses,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
				}}

				payload := types.SenderProfilePayload{
					Tokens: tokenPayload,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
				assert.NoError(t, err)
				assert.Equal(t, http.StatusBadRequest, res.Code, fmt.Sprintf("Should reject invalid Ethereum address: %s", invalidAddr))

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}
		})

		t.Run("handles token with no addresses", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)
			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			tokenPayload := []types.SenderOrderTokenPayload{{
				Symbol:    testCtx.token.Symbol,
				Addresses: []types.SenderOrderAddressPayload{}, // Empty addresses

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}}

			payload := types.SenderProfilePayload{
				Tokens: tokenPayload,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response.Message, "No wallet address provided")
		})

		t.Run("handles unsupported token symbol", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)
			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			tokenAddresses := []types.SenderOrderAddressPayload{{
				FeeAddress:    "0xD4EB9067111F81b9bAabE06E2b8ebBaDADEd5DAf",
				Network:       "ethereum",
				RefundAddress: "0xD4EB9067111F81b9bAabE06E2b8ebBaDADEd5DA0",

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}}

			tokenPayload := []types.SenderOrderTokenPayload{{
				Symbol:    "NONEXISTENT",
				Addresses: tokenAddresses,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}}

			payload := types.SenderProfilePayload{
				Tokens: tokenPayload,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, "Token not supported", response.Message)
		})

		t.Run("handles unsupported network", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)
			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			tokenAddresses := []types.SenderOrderAddressPayload{{
				FeeAddress:    "0xD4EB9067111F81b9bAabE06E2b8ebBaDADEd5DAf",
				Network:       "unsupported_network",
				RefundAddress: "0xD4EB9067111F81b9bAabE06E2b8ebBaDADEd5DA0",

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}}

			tokenPayload := []types.SenderOrderTokenPayload{{
				Symbol:    testCtx.token.Symbol,
				Addresses: tokenAddresses,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}}

			payload := types.SenderProfilePayload{
				Tokens: tokenPayload,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, res.Code)

			var response types.Response
			err = json.Unmarshal(res.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response.Message, "Network not supported")
		})

		t.Run("activates sender profile when tokens are configured", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)
			senderProfile, err := test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)
			assert.False(t, senderProfile.IsActive, "Profile should start inactive")

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			tokenAddresses := []types.SenderOrderAddressPayload{{
				FeeAddress:    "0xD4EB9067111F81b9bAabE06E2b8ebBaDADEd5DAf",
				Network:       testCtx.token.Edges.Network.Identifier,
				RefundAddress: "0xD4EB9067111F81b9bAabE06E2b8ebBaDADEd5DA0",

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}}

			tokenPayload := []types.SenderOrderTokenPayload{{
				Symbol:     testCtx.token.Symbol,
				Addresses:  tokenAddresses,
				FeePercent: decimal.NewFromInt(1),

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}}

			payload := types.SenderProfilePayload{
				DomainWhitelist: []string{"example.com"},
				Tokens:          tokenPayload,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)

			// Verify profile is now active
			updatedProfile, err := db.Client.SenderProfile.
				Query().
				Where(senderprofile.HasUserWith(user.ID(testUser.ID))).
				Only(context.Background())
			assert.NoError(t, err)
			assert.True(t, updatedProfile.IsActive)
		})
	})

	t.Run("UpdateProviderProfile Advanced Tests", func(t *testing.T) {
		t.Run("handles malformed JSON payload", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization":  "Bearer " + accessToken,
				"Content-Type":   "application/json",

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			// Send malformed JSON
			res := httptest.NewRecorder()
			req := httptest.NewRequest("PATCH", "/settings/provider", strings.NewReader(`{"currency": "KES", invalid: json}`))
			for k, v := range headers {
				req.Header.Set(k, v)

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}
			router.ServeHTTP(res, req)

			assert.Equal(t, http.StatusBadRequest, res.Code)
		})

		t.Run("handles empty trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}
			payload := types.ProviderProfilePayload{
				TradingName:    "",
				HostIdentifier: "https://example.com",
				Currency:       "KES",

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Empty trading name should be allowed (field is optional)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles missing required currency field", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}
			payload := types.ProviderProfilePayload{
				TradingName:    "Test Provider",
				HostIdentifier: "https://example.com",
				// Currency field missing - this is required

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, res.Code)
		})

		t.Run("validates HTTPS requirement for host identifier", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			// Test various invalid URL schemes
			invalidHosts := []string{
				"http://example.com",      // HTTP not allowed
				"ftp://example.com",       // FTP not allowed
				"not-a-valid-url",         // Not a URL
				"https://",                // Incomplete URL
				"://example.com",          // Missing scheme
				" https://example.com ",   // Whitespace

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles Unicode and emoji characters", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "测试公司 🚀 Тест Компания العربية 🌍",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.Code)
		})

		t.Run("handles large domain whitelist", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Create large domain whitelist
			largeDomainList := make([]string, 100)
			for i := 0; i < 100; i++ {
				largeDomainList[i] = fmt.Sprintf("domain%d.com", i)
			}

			payload := types.SenderProfilePayload{
				DomainWhitelist: largeDomainList,
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})
	})

	t.Run("Concurrency and Performance Tests", func(t *testing.T) {
		t.Run("handles concurrent profile updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "sender"})
			assert.NoError(t, err)

			_, err = test.CreateTestSenderProfile(map[string]interface{}{
				"user_id": testUser.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "sender")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Simulate concurrent updates
			done := make(chan bool, 3)
			results := make([]int, 3)

			for i := 0; i < 3; i++ {
				go func(index int) {
					defer func() { done <- true }()
					payload := types.SenderProfilePayload{
						DomainWhitelist: []string{fmt.Sprintf("domain%d.com", index)},
					}
					res, err := test.PerformRequest(t, "PATCH", "/settings/sender", payload, headers, router)
					assert.NoError(t, err)
					results[index] = res.Code
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				<-done
			}

			// At least one should succeed, others may fail due to concurrency
			successCount := 0
			for _, code := range results {
				if code == http.StatusOK {
					successCount++
				}
			}
			assert.Greater(t, successCount, 0, "At least one concurrent update should succeed")
		})

		t.Run("stress test with rapid sequential updates", func(t *testing.T) {
			testUser, err := test.CreateTestUser(map[string]interface{}{"scope": "provider"})
			assert.NoError(t, err)

			currency, err := test.CreateTestFiatCurrency(map[string]interface{}{
				"code":        "USD",
				"short_name":  "US Dollar",
				"decimals":    2,
				"symbol":      "$",
				"name":        "US Dollar",
				"market_rate": 1.0,
			})
			assert.NoError(t, err)

			_, err = test.CreateTestProviderProfile(map[string]interface{}{
				"user_id":     testUser.ID,
				"currency_id": currency.ID,
			})
			assert.NoError(t, err)

			accessToken, _ := token.GenerateAccessJWT(testUser.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			// Perform rapid sequential updates
			successCount := 0
			for i := 0; i < 10; i++ {
				payload := types.ProviderProfilePayload{
					TradingName:    fmt.Sprintf("Test Provider %d", i),
					HostIdentifier: "https://example.com",
					Currency:       "USD",
				}

				res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
				assert.NoError(t, err)
				if res.Code == http.StatusOK {
					successCount++
				}
			}

			assert.Greater(t, successCount, 5, "Most sequential updates should succeed")
		})
	})
			}

			for _, invalidHost := range invalidHosts {
				payload := types.ProviderProfilePayload{
					TradingName:    "Test Provider",
					HostIdentifier: invalidHost,
					Currency:       "KES",

	t.Run("Input Validation and Boundary Tests", func(t *testing.T) {
		t.Run("handles extremely long trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			longName := strings.Repeat("A", 1000) // Very long name
			payload := types.ProviderProfilePayload{
				TradingName:    longName,
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.PerformRequest(t, "PATCH", "/settings/provider", payload, headers, router)
			assert.NoError(t, err)
			// Should either succeed or fail with proper validation
			assert.True(t, res.Code == http.StatusOK || res.Code == http.StatusBadRequest)
		})

		t.Run("handles special characters in trading name", func(t *testing.T) {
			accessToken, _ := token.GenerateAccessJWT(testCtx.user.ID.String(), "provider")
			headers := map[string]string{
				"Authorization": "Bearer " + accessToken,
			}

			payload := types.ProviderProfilePayload{
				TradingName:    "Test & Co. (2023) - Special #1 @Provider! €₹¥£",
				HostIdentifier: "https://example.com",
				Currency:       "KES",
			}

			res, err := test.Perfo
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
}
