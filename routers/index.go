package routers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/paycrest/aggregator/controllers"
	"github.com/paycrest/aggregator/controllers/accounts"
	"github.com/paycrest/aggregator/controllers/provider"
	"github.com/paycrest/aggregator/controllers/sender"
	"github.com/paycrest/aggregator/routers/middleware"
	u "github.com/paycrest/aggregator/utils"
)

// RegisterRoutes add all routing list here automatically get main router
func RegisterRoutes(route *gin.Engine) {

	route.NoRoute(func(ctx *gin.Context) {
		u.APIResponse(ctx, http.StatusNotFound, "error", "Route Not Found", nil)
	})
	route.GET("/health", func(ctx *gin.Context) { ctx.JSON(http.StatusOK, gin.H{"live": "ok"}) })

	// Add all routes
	authRoutes(route)
	senderRoutes(route)
	providerRoutes(route)

	ctrl := controllers.NewController()

	v1 := route.Group("/v1/")

	v1.GET(
		"currencies",
		ctrl.GetFiatCurrencies,
	)
	v1.GET(
		"institutions/:currency_code",
		ctrl.GetInstitutionsByCurrency,
	)
	v1.GET("tokens", ctrl.GetSupportedTokens)
	v1.GET("rates/:token/:amount/:fiat", ctrl.GetTokenRate)
	v1.GET("pubkey", ctrl.GetAggregatorPublicKey)
	v1.POST("verify-account", ctrl.VerifyAccount)
	v1.GET("orders/:chain_id/:id", ctrl.GetProviderOrderStatus)

	// Reindex transaction endpoint
	v1.GET("reindex/:network/:tx_hash_or_address", ctrl.IndexTransaction)

	// Index provider address endpoint
	v1.POST("index-provider-address", ctrl.IndexProviderAddress)

	// Etherscan queue monitoring endpoint
	v1.GET("etherscan/stats", ctrl.GetEtherscanQueueStats)

	// KYB route
	v1.POST("slack-interaction", middleware.SlackVerificationMiddleware, ctrl.SlackInteractionHandler)
	v1.POST("kyb-submission", middleware.JWTMiddleware, ctrl.HandleKYBSubmission)
	v1.GET("kyb-submission", middleware.JWTMiddleware, ctrl.GetKYBDocuments)

	// KYC routes
	v1.POST("kyc", ctrl.RequestIDVerification)
	v1.GET("kyc/:wallet_address", ctrl.GetIDVerificationStatus)
	v1.POST("kyc/webhook", ctrl.KYCWebhook)

	// Insight webhook route
	v1.POST("insight/webhook", ctrl.InsightWebhook)
}

func authRoutes(route *gin.Engine) {
	authCtrl := accounts.NewAuthController()
	var profileCtrl accounts.ProfileController

	v1 := route.Group("/v1/")
	v1.POST("auth/register", middleware.OnlyWebMiddleware, middleware.TurnstileMiddleware(), authCtrl.Register)
	v1.POST("auth/login", middleware.OnlyWebMiddleware, middleware.TurnstileMiddleware(), authCtrl.Login)
	v1.POST("auth/confirm-account", middleware.OnlyWebMiddleware, authCtrl.ConfirmEmail)
	v1.POST("auth/resend-token", middleware.OnlyWebMiddleware, authCtrl.ResendVerificationToken)
	v1.POST("auth/refresh", middleware.OnlyWebMiddleware, authCtrl.RefreshJWT)
	v1.POST("auth/reset-password-token", middleware.OnlyWebMiddleware, authCtrl.ResetPasswordToken)
	v1.PATCH("auth/reset-password", middleware.OnlyWebMiddleware, authCtrl.ResetPassword)
	v1.PATCH("auth/change-password", middleware.JWTMiddleware, authCtrl.ChangePassword)
	v1.DELETE("auth/delete-account", middleware.JWTMiddleware, authCtrl.DeleteAccount)

	v1.GET(
		"settings/provider",
		middleware.OnlyWebMiddleware,
		middleware.JWTMiddleware,
		middleware.OnlyProviderMiddleware,
		profileCtrl.GetProviderProfile,
	)
	v1.PATCH(
		"settings/provider",
		middleware.OnlyWebMiddleware,
		middleware.JWTMiddleware,
		middleware.OnlyProviderMiddleware,
		profileCtrl.UpdateProviderProfile,
	)
	v1.GET(
		"settings/sender",
		middleware.OnlyWebMiddleware,
		middleware.JWTMiddleware,
		middleware.OnlySenderMiddleware,
		profileCtrl.GetSenderProfile,
	)
	v1.PATCH(
		"settings/sender",
		middleware.OnlyWebMiddleware,
		middleware.JWTMiddleware,
		middleware.OnlySenderMiddleware,
		profileCtrl.UpdateSenderProfile,
	)
}

func senderRoutes(route *gin.Engine) {
	senderCtrl := sender.NewSenderController()

	v1 := route.Group("/v1/sender/")
	v1.Use(middleware.DynamicAuthMiddleware)
	v1.Use(middleware.OnlySenderMiddleware)

	v1.POST("orders", senderCtrl.InitiatePaymentOrder)
	v1.GET("orders/:id", senderCtrl.GetPaymentOrderByID)
	v1.GET("orders", senderCtrl.GetPaymentOrders)
	v1.POST("orders/:id/validate", senderCtrl.ValidateOrder)
	v1.GET("stats", senderCtrl.Stats)
}

func providerRoutes(route *gin.Engine) {
	providerCtrl := provider.NewProviderController()

	v1 := route.Group("/v1/provider/")
	v1.Use(middleware.DynamicAuthMiddleware)
	v1.Use(middleware.OnlyProviderMiddleware)

	v1.GET("orders", providerCtrl.GetPaymentOrders)
	v1.POST("orders/:id/accept", providerCtrl.AcceptOrder)
	v1.POST("orders/:id/decline", providerCtrl.DeclineOrder)
	v1.POST("orders/:id/fulfill", providerCtrl.FulfillOrder)
	v1.POST("orders/:id/cancel", providerCtrl.CancelOrder)
	v1.POST("balances", providerCtrl.UpdateProviderBalance)
	v1.GET("rates/:token/:fiat", providerCtrl.GetMarketRate)
	v1.GET("stats", providerCtrl.Stats)
	v1.GET("node-info", providerCtrl.NodeInfo)
}
