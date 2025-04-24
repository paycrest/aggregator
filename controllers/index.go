package controllers

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/linkedaddress"
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	"github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/providerprofile"
	tokenEnt "github.com/paycrest/aggregator/ent/token"
	svc "github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/kyc"
	orderSvc "github.com/paycrest/aggregator/services/order"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	u "github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"

	"github.com/gin-gonic/gin"
)

var cryptoConf = config.CryptoConfig()
var serverConf = config.ServerConfig()
var identityConf = config.IdentityConfig()

// Controller is the default controller for other endpoints
type Controller struct {
	orderService          types.OrderService
	priorityQueueService  *svc.PriorityQueueService
	receiveAddressService *svc.ReceiveAddressService
	kycService            kyc.KYCProvider
}

// NewController creates a new instance of AuthController with injected services
func NewController() *Controller {
	return &Controller{
		orderService:          orderSvc.NewOrderEVM(),
		priorityQueueService:  svc.NewPriorityQueueService(),
		receiveAddressService: svc.NewReceiveAddressService(),
		kycService:            kyc.NewSmileIDService(),
	}
}

// GetFiatCurrencies controller fetches the supported fiat currencies
func (ctrl *Controller) GetFiatCurrencies(ctx *gin.Context) {
	// fetch stored fiat currencies.
	fiatcurrencies, err := storage.Client.FiatCurrency.
		Query().
		Where(fiatcurrency.IsEnabledEQ(true)).
		All(ctx)
	if err != nil {
		logger.Errorf("Error: Failed to fetch fiat currencies: %v", err)

		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to fetch FiatCurrencies", fmt.Sprintf("%v", err))
		return
	}

	currencies := make([]types.SupportedCurrencies, 0, len(fiatcurrencies))
	for _, currency := range fiatcurrencies {
		currencies = append(currencies, types.SupportedCurrencies{
			Code:       currency.Code,
			Name:       currency.Name,
			ShortName:  currency.ShortName,
			Decimals:   int8(currency.Decimals),
			Symbol:     currency.Symbol,
			MarketRate: currency.MarketRate,
		})
	}

	u.APIResponse(ctx, http.StatusOK, "success", "OK", currencies)
}

// GetInstitutionsByCurrency controller fetches the supported institutions for a given currency
func (ctrl *Controller) GetInstitutionsByCurrency(ctx *gin.Context) {
	// Get currency code from the URL
	currencyCode := ctx.Param("currency_code")

	institutions, err := storage.Client.Institution.
		Query().
		Where(institution.HasFiatCurrencyWith(
			fiatcurrency.CodeEQ(strings.ToUpper(currencyCode)),
		)).
		All(ctx)
	if err != nil {
		logger.Errorf("Error: Failed to fetch institutions: %v", err)
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to fetch institutions", nil)
		return
	}

	response := make([]types.SupportedInstitutions, 0, len(institutions))
	for _, institution := range institutions {
		response = append(response, types.SupportedInstitutions{
			Code: institution.Code,
			Name: institution.Name,
			Type: institution.Type,
		})
	}

	u.APIResponse(ctx, http.StatusOK, "success", "OK", response)
}

// GetTokenRate controller fetches the current rate of the cryptocurrency token against the fiat currency
func (ctrl *Controller) GetTokenRate(ctx *gin.Context) {
	// Parse path parameters
	token, err := storage.Client.Token.
		Query().
		Where(
			tokenEnt.SymbolEQ(strings.ToUpper(ctx.Param("token"))),
			tokenEnt.IsEnabledEQ(true),
		).
		First(ctx)
	if err != nil {
		logger.Errorf("Error: Failed to fetch token rate: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch token rate", nil)
		return
	}

	if token == nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("Token %s is not supported", strings.ToUpper(ctx.Param("token"))), nil)
		return
	}

	currency, err := storage.Client.FiatCurrency.
		Query().
		Where(
			fiatcurrency.IsEnabledEQ(true),
			fiatcurrency.CodeEQ(strings.ToUpper(ctx.Param("fiat"))),
		).
		Only(ctx)
	if err != nil {
		logger.Errorf("Error: Failed to fetch token rate: %v", err)
		u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("Fiat currency %s is not supported", strings.ToUpper(ctx.Param("fiat"))), nil)
		return
	}

	if !strings.EqualFold(token.BaseCurrency, currency.Code) && !strings.EqualFold(token.BaseCurrency, "USD") {
		u.APIResponse(ctx, http.StatusBadRequest, "error", fmt.Sprintf("%s can only be converted to %s", token.Symbol, token.BaseCurrency), nil)
		return
	}

	tokenAmount, err := decimal.NewFromString(ctx.Param("amount"))
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid amount", nil)
		return
	}

	var rateResponse decimal.Decimal
	if !strings.EqualFold(token.BaseCurrency, currency.Code) {
		rateResponse = currency.MarketRate

		// get providerID from query params
		providerID := ctx.Query("provider_id")
		if providerID != "" {
			// get the provider from the bucket
			provider, err := storage.Client.ProviderProfile.
				Query().
				Where(providerprofile.IDEQ(providerID)).
				Only(ctx)
			if err != nil {
				if ent.IsNotFound(err) {
					u.APIResponse(ctx, http.StatusBadRequest, "error", "Provider not found", nil)
					return
				} else {
					u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch provider profile", nil)
					return
				}
			}

			rateResponse, err = ctrl.priorityQueueService.GetProviderRate(ctx, provider, token.Symbol, currency.Code)
			if err != nil {
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch provider rate", nil)
				return
			}

		} else {
			// Get redis keys for provision buckets
			keys, _, err := storage.RedisClient.Scan(ctx, uint64(0), "bucket_"+currency.Code+"_*_*", 100).Result()
			if err != nil {
				u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch rates", nil)
				return
			}

			highestMaxAmount := decimal.NewFromInt(0)

			// Scan through the buckets to find a matching rate
			for _, key := range keys {
				bucketData := strings.Split(key, "_")
				minAmount, _ := decimal.NewFromString(bucketData[2])
				maxAmount, _ := decimal.NewFromString(bucketData[3])

				for index := 0; ; index++ {
					// Get the topmost provider in the priority queue of the bucket
					providerData, err := storage.RedisClient.LIndex(ctx, key, int64(index)).Result()
					if err != nil {
						break
					}
					parts := strings.Split(providerData, ":")
					if len(parts) != 5 {
						logger.WithFields(logger.Fields{
							"Error": fmt.Sprintf("%v", err),
							"ProviderData": providerData,
							"Token": token.Symbol,
							"Currency": currency.Code,
							"MinAmount": minAmount,
							"MaxAmount": maxAmount,
						}).Errorf("GetTokenRate.InvalidProviderData: %v", providerData)
						continue
					}

					// Skip entry if token doesn't match
					if parts[1] != token.Symbol {
						continue
					}

					// Skip entry if order amount is not within provider's min and max order amount
					minOrderAmount, err := decimal.NewFromString(parts[3])
					if err != nil {
						continue
					}

					maxOrderAmount, err := decimal.NewFromString(parts[4])
					if err != nil {
						continue
					}

					if tokenAmount.LessThan(minOrderAmount) || tokenAmount.GreaterThan(maxOrderAmount) {
						continue
					}

					// Get fiat equivalent of the token amount
					rate, _ := decimal.NewFromString(parts[2])
					fiatAmount := tokenAmount.Mul(rate)

					// Check if fiat amount is within the bucket range and set the rate
					if fiatAmount.GreaterThanOrEqual(minAmount) && fiatAmount.LessThanOrEqual(maxAmount) {
						rateResponse = rate
						break
					} else if maxAmount.GreaterThan(highestMaxAmount) {
						// Get the highest max amount
						highestMaxAmount = maxAmount
						rateResponse = rate
					}
				}
			}
		}
	} else {
		rateResponse = decimal.NewFromInt(1)
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Rate fetched successfully", rateResponse)
}

// GetSupportedTokens controller fetches supported cryptocurrency tokens
func (ctrl *Controller) GetSupportedTokens(ctx *gin.Context) {
	// Get network filter from query parameter
	networkFilter := ctx.Query("network")

	// Build query
	query := storage.Client.Token.
		Query().
		Where(tokenEnt.IsEnabled(true)).
		WithNetwork()

	// Apply network filter if provided
	if networkFilter != "" {
		query = query.Where(tokenEnt.HasNetworkWith(
			network.Identifier(strings.ToLower(networkFilter)),
		))
	}

	// Execute query
	tokens, err := query.All(ctx)
	if err != nil {
		logger.Errorf("Error: Failed to fetch tokens: error: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch tokens", nil)
		return
	}

	// Transform tokens for response
	response := make([]types.SupportedTokenResponse, 0, len(tokens))
	for _, t := range tokens {
		response = append(response, types.SupportedTokenResponse{
			Symbol:          t.Symbol,
			ContractAddress: t.ContractAddress,
			Decimals:        t.Decimals,
			BaseCurrency:    t.BaseCurrency,
			Network:         t.Edges.Network.Identifier,
		})
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Tokens retrieved successfully", response)
}

// GetAggregatorPublicKey controller expose Aggregator Public Key
func (ctrl *Controller) GetAggregatorPublicKey(ctx *gin.Context) {
	u.APIResponse(ctx, http.StatusOK, "success", "OK", cryptoConf.AggregatorPublicKey)
}

// VerifyAccount controller verifies an account of a given institution
func (ctrl *Controller) VerifyAccount(ctx *gin.Context) {
	var payload types.VerifyAccountRequest

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Institution": payload.Institution,
			"AccountIdentifier": payload.AccountIdentifier,
		}).Errorf("Failed to validate payload when verifying account")
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	accountInstitution, err := storage.Client.Institution.
		Query().
		Where(institution.CodeEQ(payload.Institution)).
		WithFiatCurrency(
			func(fq *ent.FiatCurrencyQuery) {
				fq.Where(fiatcurrency.IsEnabledEQ(true))
			},
		).
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Institution": payload.Institution,
			"AccountIdentifier": payload.AccountIdentifier,
		}).Errorf("Failed to validate payload when verifying account")
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", []types.ErrorData{{
			Field:   "Institution",
			Message: "Institution is not supported",
		}})
		return
	}

	// Skip account verification for mobile money institutions
	if accountInstitution.Type == institution.TypeMobileMoney {
		u.APIResponse(ctx, http.StatusOK, "success", "Account name was fetched successfully", "OK")
		return
	}

	providers, err := storage.Client.ProviderProfile.
		Query().
		Where(
			providerprofile.HasCurrenciesWith(
				fiatcurrency.CodeEQ(accountInstitution.Edges.FiatCurrency.Code),
			),
			providerprofile.HostIdentifierNotNil(),
			providerprofile.IsActiveEQ(true),
			providerprofile.IsAvailableEQ(true),
			providerprofile.VisibilityModeEQ(providerprofile.VisibilityModePublic),
		).
		All(ctx)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to verify account", fmt.Sprintf("%v", err))
		return
	}

	var res fastshot.Response
	var data map[string]interface{}
	for _, provider := range providers {
		res, err = fastshot.NewClient(provider.HostIdentifier).
			Config().SetTimeout(30 * time.Second).
			Build().POST("/verify_account").
			Body().AsJSON(payload).
			Send()
		if err != nil {
			continue
		}

		data, err = u.ParseJSONResponse(res.RawResponse)
		if err != nil {
			continue
		}
	}

	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Institution": payload.Institution,
			"AccountIdentifier": payload.AccountIdentifier,
		}).Errorf("Failed to verify account")
		u.APIResponse(ctx, http.StatusServiceUnavailable, "error", "Failed to verify account", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Account name was fetched successfully", data["data"].(string))
}

// GetLockPaymentOrderStatus controller fetches a payment order status by ID
func (ctrl *Controller) GetLockPaymentOrderStatus(ctx *gin.Context) {
	// Get order and chain ID from the URL
	orderID := ctx.Param("id")
	chainID, err := strconv.ParseInt(ctx.Param("chain_id"), 10, 64)
	if err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid chain ID", nil)
		return
	}

	// Fetch related payment orders from the database
	orders, err := storage.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.GatewayIDEQ(orderID),
			lockpaymentorder.HasTokenWith(
				tokenEnt.HasNetworkWith(
					network.ChainIDEQ(chainID),
				),
			),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithTransactions().
		All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"OrderID": orderID,
			"ChainID": chainID,
		}).Errorf("Failed to fetch locked order status")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch order status", nil)
		return
	}

	var settlements []types.LockPaymentOrderSplitOrder
	var receipts []types.LockPaymentOrderTxReceipt
	var settlePercent decimal.Decimal
	var totalAmount decimal.Decimal

	for _, order := range orders {
		for _, transaction := range order.Edges.Transactions {
			if u.ContainsString([]string{"order_settled", "order_created", "order_refunded"}, transaction.Status.String()) {
				var status lockpaymentorder.Status
				if transaction.Status.String() == "order_created" {
					status = lockpaymentorder.StatusPending
				} else {
					status = lockpaymentorder.Status(strings.TrimPrefix(transaction.Status.String(), "order_"))
				}
				receipts = append(receipts, types.LockPaymentOrderTxReceipt{
					Status:    status,
					TxHash:    transaction.TxHash,
					Timestamp: transaction.CreatedAt,
				})
			}
		}

		settlements = append(settlements, types.LockPaymentOrderSplitOrder{
			SplitOrderID: order.ID,
			Amount:       order.Amount,
			Rate:         order.Rate,
			OrderPercent: order.OrderPercent,
		})

		settlePercent = settlePercent.Add(order.OrderPercent)
		totalAmount = totalAmount.Add(order.Amount)
	}

	// Sort receipts by latest timestamp
	slices.SortStableFunc(receipts, func(a, b types.LockPaymentOrderTxReceipt) int {
		return b.Timestamp.Compare(a.Timestamp)
	})

	if (len(orders) == 0) || (len(receipts) == 0) {
		u.APIResponse(ctx, http.StatusNotFound, "error", "Order not found", nil)
		return
	}

	status := orders[0].Status
	if status == lockpaymentorder.StatusCancelled {
		status = lockpaymentorder.StatusProcessing
	}

	response := &types.LockPaymentOrderStatusResponse{
		OrderID:       orders[0].GatewayID,
		Amount:        totalAmount,
		Token:         orders[0].Edges.Token.Symbol,
		Network:       orders[0].Edges.Token.Edges.Network.Identifier,
		SettlePercent: settlePercent,
		Status:        status,
		TxHash:        receipts[0].TxHash,
		Settlements:   settlements,
		TxReceipts:    receipts,
		UpdatedAt:     orders[0].UpdatedAt,
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Order status fetched successfully", response)
}

// CreateLinkedAddress controller creates a new linked address
func (ctrl *Controller) CreateLinkedAddress(ctx *gin.Context) {
	var payload types.NewLinkedAddressRequest

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Institution": payload.Institution,
			"AccountIdentifier": payload.AccountIdentifier,
		}).Errorf("Failed to validate payload when creating linked address")
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	ownerAddress, _ := ctx.Get("owner_address")

	// Generate smart account
	address, salt, err := ctrl.receiveAddressService.CreateSmartAddress(ctx, nil, nil)
	if err != nil {
		logger.Errorf("Error: Failed to create linked address: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to create linked address", nil)
		return
	}

	// Create a new linked address
	linkedAddress, err := storage.Client.LinkedAddress.
		Create().
		SetAddress(address).
		SetSalt(salt).
		SetInstitution(payload.Institution).
		SetAccountIdentifier(payload.AccountIdentifier).
		SetAccountName(payload.AccountName).
		SetOwnerAddress(ownerAddress.(string)).
		Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Institution": payload.Institution,
			"OwnerAddress": ownerAddress,
			"Address": address,
		}).Errorf("Failed to set linked address")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to create linked address", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Linked address created successfully", &types.NewLinkedAddressResponse{
		LinkedAddress:     linkedAddress.Address,
		Institution:       linkedAddress.Institution,
		AccountIdentifier: linkedAddress.AccountIdentifier,
		AccountName:       linkedAddress.AccountName,
		UpdatedAt:         linkedAddress.UpdatedAt,
		CreatedAt:         linkedAddress.CreatedAt,
	})
}

// GetLinkedAddress controller fetches a linked address
func (ctrl *Controller) GetLinkedAddress(ctx *gin.Context) {
	// Get owner address from the URL
	owner_address := ctx.Query("owner_address")

	linkedAddress, err := storage.Client.LinkedAddress.
		Query().
		Where(
			linkedaddress.OwnerAddressEQ(owner_address),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusNotFound, "error", "Linked address not found", nil)
			return
		} else {
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
				"OwnerAddress": owner_address,
			}).Errorf("Failed to fetch linked address")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch linked address", nil)
			return
		}
	}

	institution, err := storage.Client.Institution.
		Query().
		Where(institution.CodeEQ(linkedAddress.Institution)).
		WithFiatCurrency().
		Only(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"OwnerAddress": owner_address,
			"LinkedAddressInstitution": linkedAddress.Institution,
		}).Errorf("Failed to fetch linked address")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch linked address", nil)
		return
	}

	ownerAddressFromAuth, _ := ctx.Get("owner_address")

	response := &types.LinkedAddressResponse{
		LinkedAddress: linkedAddress.Address,
		Currency:      institution.Edges.FiatCurrency.Code,
	}

	if ownerAddressFromAuth != nil {
		response.AccountIdentifier = linkedAddress.AccountIdentifier
		response.AccountName = linkedAddress.AccountName
		response.Institution = institution.Name
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Linked address fetched successfully", response)
}

// GetLinkedAddressTransactions controller fetches transactions for a linked address
func (ctrl *Controller) GetLinkedAddressTransactions(ctx *gin.Context) {
	// Get linked address from the URL
	linked_address := ctx.Param("linked_address")

	linkedAddress, err := storage.Client.LinkedAddress.
		Query().
		Where(
			linkedaddress.AddressEQ(linked_address),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusNotFound, "error", "Linked address not found", nil)
			return
		} else {
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
				"LinkedAddress": linked_address,
			}).Errorf("Failed to fetch linked address")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch linked address", nil)
			return
		}
	}

	// Get page and pageSize query params
	page, offset, pageSize := u.Paginate(ctx)

	// Fetch related transactions from the database
	paymentOrderQuery := linkedAddress.QueryPaymentOrders()

	count, err := paymentOrderQuery.Count(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"LinkedAddress": linked_address,
			"LinkedAddressID": linkedAddress.ID,
			"LinkedAddressOwnerAddress": linkedAddress.OwnerAddress,
		}).Errorf("Failed to count payment orders for linked address")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch transactions", nil)
		return
	}

	paymentOrders, err := paymentOrderQuery.
		Limit(pageSize).
		Offset(offset).
		WithRecipient().
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		All(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"LinkedAddress": linked_address,
			"LinkedAddressID": linkedAddress.ID,
			"LinkedAddressOwnerAddress": linkedAddress.OwnerAddress,
		}).Errorf("Failed to fetch fetch payment orders for linked address")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch transactions", nil)
		return
	}

	orders := make([]types.LinkedAddressTransaction, 0, len(paymentOrders))

	for _, paymentOrder := range paymentOrders {
		institution, err := storage.Client.Institution.
			Query().
			Where(institution.CodeEQ(paymentOrder.Edges.Recipient.Institution)).
			WithFiatCurrency().
			Only(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
				"LinkedAddress": linked_address,
				"LinkedAddressID": linkedAddress.ID,
				"LinkedAddressOwnerAddress": linkedAddress.OwnerAddress,
				"PaymentOrderID": paymentOrder.ID,
			}).Errorf("Failed to get institution for linked address")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch payment orders", nil)
			return
		}

		orders = append(orders, types.LinkedAddressTransaction{
			ID:      paymentOrder.ID,
			Amount:  paymentOrder.Amount,
			Token:   paymentOrder.Edges.Token.Symbol,
			Rate:    paymentOrder.Rate,
			Network: paymentOrder.Edges.Token.Edges.Network.Identifier,
			Recipient: types.LinkedAddressTransactionRecipient{
				Currency:          institution.Edges.FiatCurrency.Code,
				Institution:       institution.Name,
				AccountIdentifier: paymentOrder.Edges.Recipient.AccountIdentifier,
				AccountName:       paymentOrder.Edges.Recipient.AccountName,
			},
			FromAddress:   paymentOrder.FromAddress,
			ReturnAddress: paymentOrder.ReturnAddress,
			GatewayID:     paymentOrder.GatewayID,
			TxHash:        paymentOrder.TxHash,
			CreatedAt:     paymentOrder.CreatedAt,
			UpdatedAt:     paymentOrder.UpdatedAt,
			Status:        paymentOrder.Status,
		})
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Transactions fetched successfully", &types.LinkedAddressTransactionList{
		Page:         page,
		PageSize:     pageSize,
		TotalRecords: count,
		Transactions: orders,
	})

}

// RequestIDVerification controller requests identity verification details
func (ctrl *Controller) RequestIDVerification(ctx *gin.Context) {
	var payload kyc.NewIDVerificationRequest

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	response, err := ctrl.kycService.RequestVerification(ctx, payload)
	if err != nil {
		switch fmt.Sprintf("%v", err) {
			case "invalid signature", "invalid signature: signature is not in the correct format",
			"invalid signature: signature length is not correct",
			"invalid signature: invalid recovery ID":
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid signature", fmt.Sprintf("%v", err))
			return
		case "signature already used for identity verification":
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Signature already used for identity verification", nil)
			return
		case "this account has already been successfully verified":
			u.APIResponse(ctx, http.StatusBadRequest, "success", "Failed to request identity verification", fmt.Sprintf("%v", err))
			return
		case "failed to request identity verification: couldn't reach identity provider":
			u.APIResponse(ctx, http.StatusServiceUnavailable, "error", "Failed to request identity verification", "Couldn't reach identity provider")
			return
		default:
			logger.WithFields(logger.Fields{
				"Error": fmt.Sprintf("%v", err),
				"WalletAddress": payload.WalletAddress,
				"Nonce": payload.Nonce,
			}).Errorf("Failed to request identity verification")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to request identity verification", nil)
			return
		}
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Identity verification requested successfully", response)

}

// GetIDVerificationStatus controller fetches the status of an identity verification request
func (ctrl *Controller) GetIDVerificationStatus(ctx *gin.Context) {
	// Get wallet address from the URL
	walletAddress := ctx.Param("wallet_address")

	response, err := ctrl.kycService.CheckStatus(ctx, walletAddress)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"WalletAddress": walletAddress,
		}).Errorf("Failed to fetch identity verification status")
		if fmt.Sprintf("%v", err) == "no verification request found for this wallet address" {
			u.APIResponse(ctx, http.StatusNotFound, "error", "No verification request found for this wallet address", nil)
			return
		}
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch identity verification status", nil)
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "Identity verification status fetched successfully", response)
}

// KYCWebhook handles the webhook callback from Smile Identity
func (ctrl *Controller) KYCWebhook(ctx *gin.Context) {
	payload, err := ctx.GetRawData()
	if err != nil {
		logger.Errorf("Error: KYCWebhook: Failed to read webhook payload: %v", err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
		return
	}

	err = ctrl.kycService.HandleWebhook(ctx, payload)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
			"Payload": string(payload),
		}).Errorf("Failed to process webhook for kyc")
		if fmt.Sprintf("%v", err) == "invalid payload" {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
			return
		}
		if fmt.Sprintf("%v", err) == "invalid signature" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process webhook"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Webhook processed successfully"})
}
