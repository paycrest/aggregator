package controllers

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/beneficialowner"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/kybprofile"
	"github.com/paycrest/aggregator/ent/linkedaddress"
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	"github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/providerprofile"
	tokenEnt "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/user"
	svc "github.com/paycrest/aggregator/services"
	kycErrors "github.com/paycrest/aggregator/services/kyc/errors"
	"github.com/paycrest/aggregator/services/kyc/smile"
	orderSvc "github.com/paycrest/aggregator/services/order"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	u "github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"

	"github.com/ethereum/go-ethereum/crypto"
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
	kycService            types.KYCProvider
	slackService          *svc.SlackService
	emailService          *svc.EmailService
	cache                 map[string]bool
	processedActions      map[string]bool
	actionMutex           sync.RWMutex
}

// NewController creates a new instance of AuthController with injected services
func NewController() *Controller {
	return &Controller{
		orderService:          orderSvc.NewOrderEVM(),
		priorityQueueService:  svc.NewPriorityQueueService(),
		receiveAddressService: svc.NewReceiveAddressService(),
		kycService:            smile.NewSmileIDService(),
		slackService:          svc.NewSlackService(serverConf.SlackWebhookURL),
		emailService:          svc.NewEmailService(svc.SENDGRID_MAIL_PROVIDER),
		cache:                 make(map[string]bool),
		processedActions:      make(map[string]bool),
	}
}

type FormSubmission struct {
	SubmissionID string                 `json:"submissionID"`
	Answers      map[string]interface{} `json:"answers"`
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
							"Error":        fmt.Sprintf("%v", err),
							"ProviderData": providerData,
							"Token":        token.Symbol,
							"Currency":     currency.Code,
							"MinAmount":    minAmount,
							"MaxAmount":    maxAmount,
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
			"Error":             fmt.Sprintf("%v", err),
			"Institution":       payload.Institution,
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
			"Error":             fmt.Sprintf("%v", err),
			"Institution":       payload.Institution,
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
			"Error":             fmt.Sprintf("%v", err),
			"Institution":       payload.Institution,
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
			"Error":   fmt.Sprintf("%v", err),
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
			"Error":             fmt.Sprintf("%v", err),
			"Institution":       payload.Institution,
			"AccountIdentifier": payload.AccountIdentifier,
		}).Errorf("Failed to validate payload when creating linked address")
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	ownerAddress, _ := ctx.Get("owner_address")

	// Generate smart account
	address, err := ctrl.receiveAddressService.CreateSmartAddress(ctx, "")
	if err != nil {
		logger.Errorf("Error: Failed to create linked address: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to create linked address", nil)
		return
	}

	// Create a new linked address
	linkedAddress, err := storage.Client.LinkedAddress.
		Create().
		SetAddress(address).
		SetInstitution(payload.Institution).
		SetAccountIdentifier(payload.AccountIdentifier).
		SetAccountName(payload.AccountName).
		SetOwnerAddress(ownerAddress.(string)).
		Save(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":        fmt.Sprintf("%v", err),
			"Institution":  payload.Institution,
			"OwnerAddress": ownerAddress,
			"Address":      address,
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
				"Error":        fmt.Sprintf("%v", err),
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
			"Error":                    fmt.Sprintf("%v", err),
			"OwnerAddress":             owner_address,
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
				"Error":         fmt.Sprintf("%v", err),
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
			"Error":                     fmt.Sprintf("%v", err),
			"LinkedAddress":             linked_address,
			"LinkedAddressID":           linkedAddress.ID,
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
			"Error":                     fmt.Sprintf("%v", err),
			"LinkedAddress":             linked_address,
			"LinkedAddressID":           linkedAddress.ID,
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
				"Error":                     fmt.Sprintf("%v", err),
				"LinkedAddress":             linked_address,
				"LinkedAddressID":           linkedAddress.ID,
				"LinkedAddressOwnerAddress": linkedAddress.OwnerAddress,
				"PaymentOrderID":            paymentOrder.ID,
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

// verifyWalletSignature verifies the Ethereum signature for wallet verification
func (ctrl *Controller) verifyWalletSignature(walletAddress, signature, nonce string) error {
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature: signature is not in the correct format")
	}
	if len(sig) != 65 {
		return fmt.Errorf("invalid signature: signature length is not correct")
	}
	if sig[64] != 27 && sig[64] != 28 {
		return fmt.Errorf("invalid signature: invalid recovery ID")
	}
	sig[64] -= 27

	message := fmt.Sprintf("I accept the KYC Policy and hereby request an identity verification check for %s with nonce %s", walletAddress, nonce)
	prefix := "\x19Ethereum Signed Message:\n" + fmt.Sprint(len(message))
	hash := crypto.Keccak256Hash([]byte(prefix + message))

	sigPublicKeyECDSA, err := crypto.SigToPub(hash.Bytes(), sig)
	if err != nil {
		return fmt.Errorf("invalid signature")
	}
	recoveredAddress := crypto.PubkeyToAddress(*sigPublicKeyECDSA)
	if !strings.EqualFold(recoveredAddress.Hex(), walletAddress) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// RequestIDVerification controller requests identity verification details
func (ctrl *Controller) RequestIDVerification(ctx *gin.Context) {
	var payload types.VerificationRequest

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error",
			"Failed to validate payload", u.GetErrorData(err))
		return
	}

	// Verify signature before proceeding
	if err := ctrl.verifyWalletSignature(payload.WalletAddress, payload.Signature, payload.Nonce); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid signature", fmt.Sprintf("%v", err))
		return
	}

	response, err := ctrl.kycService.RequestVerification(ctx, payload)
	if err != nil {
		switch e := err.(type) {
		case kycErrors.ErrSignatureAlreadyUsed:
			u.APIResponse(ctx, http.StatusBadRequest, "error", "Signature already used for identity verification", nil)
			return
		case kycErrors.ErrAlreadyVerified:
			u.APIResponse(ctx, http.StatusBadRequest, "success", "Failed to request identity verification", e.Error())
			return
		case kycErrors.ErrProviderUnreachable:
			logger.WithFields(logger.Fields{
				"Error":         fmt.Sprintf("%v", e.Err),
				"WalletAddress": payload.WalletAddress,
				"Nonce":         payload.Nonce,
			}).Errorf("Failed to reach identity provider")
			u.APIResponse(ctx, http.StatusServiceUnavailable, "error", "Failed to request identity verification", "Couldn't reach identity provider")
			return
		case kycErrors.ErrProviderResponse:
			logger.WithFields(logger.Fields{
				"Error":         fmt.Sprintf("%v", e.Err),
				"WalletAddress": payload.WalletAddress,
				"Nonce":         payload.Nonce,
			}).Errorf("Invalid response from identity provider")
			u.APIResponse(ctx, http.StatusBadGateway, "error", "Failed to request identity verification", e.Error())
			return
		case kycErrors.ErrDatabase:
			logger.WithFields(logger.Fields{
				"Error":         fmt.Sprintf("%v", e.Err),
				"WalletAddress": payload.WalletAddress,
				"Nonce":         payload.Nonce,
			}).Errorf("Database error during identity verification")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to request identity verification", nil)
			return
		default:
			logger.WithFields(logger.Fields{
				"Error":         fmt.Sprintf("%v", err),
				"WalletAddress": payload.WalletAddress,
				"Nonce":         payload.Nonce,
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
		switch err.(type) {
		case kycErrors.ErrNotFound:
			u.APIResponse(ctx, http.StatusNotFound, "error", "No verification request found for this wallet address", nil)
			return
		default:
			logger.WithFields(logger.Fields{
				"Error":         fmt.Sprintf("%v", err),
				"WalletAddress": walletAddress,
			}).Errorf("Failed to fetch identity verification status")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to fetch identity verification status", nil)
			return
		}
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
			"Error":   fmt.Sprintf("%v", err),
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

// SlackInteractionHandler handles Slack interaction requests
func (ctrl *Controller) SlackInteractionHandler(ctx *gin.Context) {
	startTime := time.Now()

	// Parse form-encoded payload
	payloadStr := ctx.PostForm("payload")
	if payloadStr == "" {
		body, err := ctx.GetRawData()
		if err != nil {
			logger.Errorf("Missing payload and failed to read raw body: %v", err)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing payload"})
			return
		}
		payloadStr = string(body)
	}

	// Parse JSON payload
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
		logger.Errorf("Error parsing Slack interaction payload: %v", err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Error parsing payload"})
		return
	}

	// Handle modal trigger (button clicks)
	if payload["type"] == "block_actions" {
		actions, ok := payload["actions"].([]interface{})
		if !ok || len(actions) == 0 {
			logger.Errorf("Invalid or empty actions in Slack payload: %v", payload)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid actions"})
			return
		}

		action, ok := actions[0].(map[string]interface{})
		if !ok {
			logger.Errorf("Invalid action format: %v", actions[0])
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action format"})
			return
		}

		actionID, ok := action["action_id"].(string)
		if !ok {
			logger.Errorf("Missing or invalid action_id")
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing action_id"})
			return
		}

		var kybProfileID string
		if strings.Contains(actionID, "_") {
			kybProfileID = actionID[strings.Index(actionID, "_")+1:]
		} else {
			logger.Errorf("Invalid action_id format: %s", actionID)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action_id format"})
			return
		}

		// Parse KYB Profile ID as UUID
		kybProfileUUID, err := uuid.Parse(kybProfileID)
		if err != nil {
			logger.Errorf("Invalid KYB Profile ID format: %s, error: %v", kybProfileID, err)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid KYB Profile ID format"})
			return
		}

		// Fetch KYB submission details from database
		kybProfile, err := storage.Client.KYBProfile.
			Query().
			Where(kybprofile.IDEQ(kybProfileUUID)).
			WithUser().
			WithBeneficialOwners().
			Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				logger.Errorf("KYB Profile not found: %s", kybProfileID)
				ctx.JSON(http.StatusNotFound, gin.H{"error": "KYB Profile not found"})
				return
			}
			logger.Errorf("Failed to fetch KYB Profile %s: %v", kybProfileID, err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch KYB Profile"})
			return
		}

		// Extract user details
		var firstName, email string
		if kybProfile.Edges.User != nil {
			firstName = kybProfile.Edges.User.FirstName
			email = kybProfile.Edges.User.Email
		} else {
			logger.Errorf("KYB Profile %s has no associated user", kybProfileID)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "KYB Profile has no associated user"})
			return
		}

		if email == "" {
			logger.Errorf("Missing email for KYB Profile %s", kybProfileID)
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing email"})
			return
		}
		if firstName == "" {
			logger.Warnf("Missing firstName for KYB Profile %s, using default", kybProfileID)
			firstName = "User"
		}

		// Handle reject button - only open modal
		if strings.HasPrefix(actionID, "reject_") {
			logger.Infof("Reject button clicked for KYB Profile %s, action: %+v", kybProfileID, action)
			triggerID, ok := payload["trigger_id"].(string)
			if !ok {
				logger.Errorf("Missing trigger_id for modal, KYB Profile ID: %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing trigger_id"})
				return
			}

			modal := map[string]interface{}{
				"trigger_id": triggerID,
				"view": map[string]interface{}{
					"type":             "modal",
					"callback_id":      "reject_modal_" + kybProfileID,
					"private_metadata": fmt.Sprintf(`{"email":"%s","kyb_profile_id":"%s","firstName":"%s"}`, email, kybProfileID, firstName),
					"title": map[string]interface{}{
						"type": "plain_text",
						"text": "Reject KYB Submission",
					},
					"submit": map[string]interface{}{
						"type": "plain_text",
						"text": "Submit",
					},
					"blocks": []map[string]interface{}{
						{
							"type":     "input",
							"block_id": "reason_block",
							"element": map[string]interface{}{
								"type":      "static_select",
								"action_id": "reason_select",
								"placeholder": map[string]interface{}{
									"type": "plain_text",
									"text": "Select a reason",
								},
								"options": []map[string]interface{}{
									{
										"text": map[string]interface{}{
											"type": "plain_text",
											"text": "Incomplete or falsified documentation",
										},
										"value": "Incomplete or falsified documentation",
									},
									{
										"text": map[string]interface{}{
											"type": "plain_text",
											"text": "Unverifiable business identity",
										},
										"value": "Unverifiable business identity",
									},
									{
										"text": map[string]interface{}{
											"type": "plain_text",
											"text": "Sanctions or watchlist hits",
										},
										"value": "Sanctions or watchlist hits",
									},
									{
										"text": map[string]interface{}{
											"type": "plain_text",
											"text": "Inability to identify beneficial owners (UBOs)",
										},
										"value": "Inability to identify beneficial owners (UBOs)",
									},
									{
										"text": map[string]interface{}{
											"type": "plain_text",
											"text": "Inconsistent business details across documents",
										},
										"value": "Inconsistent business details across documents",
									},
								},
							},
							"label": map[string]interface{}{
								"type": "plain_text",
								"text": "Reason for Rejection",
							},
						},
					},
				},
			}

			jsonPayload, err := json.Marshal(modal)
			if err != nil {
				logger.Errorf("Failed to marshal modal payload for KYB Profile %s: %v", kybProfileID, err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create modal"})
				return
			}

			client := &http.Client{}
			req, err := http.NewRequest("POST", "https://slack.com/api/views.open", bytes.NewBuffer(jsonPayload))
			if err != nil {
				logger.Errorf("Failed to create Slack API request for KYB Profile %s: %v", kybProfileID, err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create modal request"})
				return
			}
			req.Header.Set("Content-Type", "application/json")
			cnfg := config.AuthConfig()
			if cnfg.SlackBotToken == "" {
				logger.Errorf("Slack bot token not configured for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Slack bot token not configured"})
				return
			}
			req.Header.Set("Authorization", "Bearer "+cnfg.SlackBotToken)

			resp, err := client.Do(req)
			if err != nil {
				logger.Errorf("Failed to open Slack modal for KYB Profile %s: %v", kybProfileID, err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open modal"})
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				logger.Errorf("Slack API responded with status %d for KYB Profile %s: %s", resp.StatusCode, kybProfileID, string(body))
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open modal"})
				return
			}

			ctx.JSON(http.StatusOK, gin.H{})
			return
		}

		if strings.HasPrefix(actionID, "approve_") {
			if ctrl.isActionProcessed(kybProfileID, "approve") || ctrl.isActionProcessed(kybProfileID, "reject") {
				logger.Warnf("Action already processed for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusOK, gin.H{"text": "This submission has already been processed."})
				return
			}

			// Mark as processed immediately
			ctrl.markActionProcessed(kybProfileID, "approve")

			// Respond immediately to Slack to remove loading state
			responseURL, _ := payload["response_url"].(string)
			if responseURL != "" {
				go func() {
					message := map[string]interface{}{
						"replace_original": true,
						"text":             fmt.Sprintf("✅ *APPROVED* - KYB submission for %s (%s) from %s has been approved.", firstName, email, kybProfile.CompanyName),
					}
					jsonPayload, _ := json.Marshal(message)
					http.Post(responseURL, "application/json", bytes.NewBuffer(jsonPayload))
				}()
			}

			// Send immediate response to Slack
			ctx.JSON(http.StatusOK, gin.H{"text": "Approving submission..."})

			// Update User KYB status
			_, err := storage.Client.User.
				Update().
				Where(user.IDEQ(kybProfile.Edges.User.ID)).
				SetKybVerificationStatus(user.KybVerificationStatusApproved).
				Save(ctx)
			if err != nil {
				logger.Errorf("Failed to approve KYB for user %s (KYB Profile %s): %v", email, kybProfileID, err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user KYB status"})
				return
			}

			// Update KYB Profile status (assuming you have a status field)
			_, err = storage.Client.KYBProfile.
				UpdateOne(kybProfile).
				Save(ctx)
			if err != nil {
				logger.Errorf("Failed to update KYB Profile status %s: %v", kybProfileID, err)
			}

			// Send approval email
			resp, err := ctrl.emailService.SendKYBApprovalEmail(email, firstName)
			if err != nil {
				logger.Errorf("Failed to send KYB approval email to %s (KYB Profile %s): %v, response: %+v", email, kybProfileID, err, resp)
			} else {
				logger.Infof("KYB approval email sent successfully to %s (KYB Profile %s), message ID: %s", email, kybProfileID, resp.Id)
			}

			// Send Slack feedback notification
			err = ctrl.slackService.SendActionFeedbackNotification(firstName, email, kybProfileID, "approve", "")
			if err != nil {
				logger.Warnf("Failed to send Slack feedback notification for KYB Profile %s: %v", kybProfileID, err)
			}

			logger.Infof("Processed Slack approve interaction in %v", time.Since(startTime))
			return
		}

		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Unknown action"})
		return
	}

	// Handle modal submission
	if payload["type"] == "view_submission" {
		view, ok := payload["view"].(map[string]interface{})
		if !ok {
			logger.Errorf("Invalid view format in payload")
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid view format"})
			return
		}
		callbackID, ok := view["callback_id"].(string)
		if !ok {
			logger.Errorf("Missing callback_id in view")
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing callback_id"})
			return
		}

		if strings.HasPrefix(callbackID, "reject_modal_") {
			kybProfileID := callbackID[len("reject_modal_"):]

			// Prevent modal if already processed
			if ctrl.isActionProcessed(kybProfileID, "approve") || ctrl.isActionProcessed(kybProfileID, "reject") {
				logger.Warnf("Action already processed for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusOK, gin.H{"text": "This submission has already been processed."})
				return
			}

			// Mark as processed immediately
			ctrl.markActionProcessed(kybProfileID, "reject")

			// Extract selected reason
			state, ok := view["state"].(map[string]interface{})
			if !ok {
				logger.Errorf("Invalid state in view for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state"})
				return
			}
			values, ok := state["values"].(map[string]interface{})
			if !ok {
				logger.Errorf("Invalid values in state for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid values"})
				return
			}
			reasonBlock, ok := values["reason_block"].(map[string]interface{})
			if !ok {
				logger.Errorf("Invalid reason_block in values for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid reason_block"})
				return
			}
			reasonSelect, ok := reasonBlock["reason_select"].(map[string]interface{})
			if !ok {
				logger.Errorf("Invalid reason_select in reason_block for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid reason_select"})
				return
			}
			selectedReason, ok := reasonSelect["selected_option"].(map[string]interface{})
			if !ok {
				logger.Errorf("No reason selected for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "No reason selected"})
				return
			}
			reasonForDecline, ok := selectedReason["value"].(string)
			if !ok {
				logger.Errorf("Invalid reason value for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid reason value"})
				return
			}

			// Extract email and firstName from private_metadata
			privateMetadata, ok := view["private_metadata"].(string)
			if !ok {
				logger.Errorf("Missing private_metadata in view for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing private_metadata"})
				return
			}
			var metadata map[string]interface{}
			if err := json.Unmarshal([]byte(privateMetadata), &metadata); err != nil {
				logger.Errorf("Error parsing private_metadata for KYB Profile %s: %v", kybProfileID, err)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid metadata"})
				return
			}
			email, ok := metadata["email"].(string)
			if !ok || email == "" {
				logger.Errorf("Missing email in private_metadata for KYB Profile %s", kybProfileID)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing email in metadata"})
				return
			}
			firstName, ok := metadata["firstName"].(string)
			if !ok {
				logger.Warnf("Missing firstName in private_metadata for KYB Profile %s; using default", kybProfileID)
				firstName = "User"
			}

			// Parse KYB Profile ID for database operations
			kybProfileUUID, err := uuid.Parse(kybProfileID)
			if err != nil {
				logger.Errorf("Invalid KYB Profile ID format for rejection: %s, error: %v", kybProfileID, err)
				ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid KYB Profile ID format"})
				return
			}

			// Update User KYB status
			_, err = storage.Client.User.
				Update().
				Where(user.EmailEQ(email)).
				SetKybVerificationStatus(user.KybVerificationStatusRejected).
				Save(ctx)
			if err != nil {
				logger.Errorf("Failed to reject KYB for user %s (KYB Profile %s): %v", email, kybProfileID, err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user KYB status"})
				return
			}

			// Update KYB Profile status (assuming you have a status field)
			_, err = storage.Client.KYBProfile.
				Update().
				Where(kybprofile.IDEQ(kybProfileUUID)).
				Save(ctx)
			if err != nil {
				logger.Errorf("Failed to update KYB Profile status %s: %v", kybProfileID, err)
			}

			// Send rejection email
			resp, err := ctrl.emailService.SendKYBRejectionEmail(email, firstName, reasonForDecline)
			if err != nil {
				logger.Errorf("Failed to send KYB rejection email to %s (KYB Profile %s): %v, response: %+v", email, kybProfileID, err, resp)
			} else {
				logger.Infof("KYB rejection email sent successfully to %s (KYB Profile %s), message ID: %s", email, kybProfileID, resp.Id)
			}

			// Send Slack feedback notification
			err = ctrl.slackService.SendActionFeedbackNotification(firstName, email, kybProfileID, "reject", reasonForDecline)
			if err != nil {
				logger.Warnf("Failed to send Slack feedback notification for KYB Profile %s: %v", kybProfileID, err)
			}

			logger.Infof("Processed Slack modal submission for rejection in %v", time.Since(startTime))
			return
		}

		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Unknown callback_id"})
		return
	}
	ctx.JSON(http.StatusBadRequest, gin.H{"error": "Unknown payload type"})
}

// isActionProcessed checks if an action has already been processed
func (ctrl *Controller) isActionProcessed(submissionID, actionType string) bool {
	ctrl.actionMutex.RLock()
	defer ctrl.actionMutex.RUnlock()
	key := fmt.Sprintf("%s_%s", submissionID, actionType)
	return ctrl.processedActions[key]
}

// markActionProcessed marks an action as processed
func (ctrl *Controller) markActionProcessed(submissionID, actionType string) {
	ctrl.actionMutex.Lock()
	defer ctrl.actionMutex.Unlock()
	key := fmt.Sprintf("%s_%s", submissionID, actionType)
	ctrl.processedActions[key] = true
}

// HandleKYBSubmission handles the POST request for KYB submission
func (ctrl *Controller) HandleKYBSubmission(ctx *gin.Context) {
	var input types.KYBSubmissionInput
	if err := ctx.ShouldBindJSON(&input); err != nil {
		logger.WithFields(logger.Fields{
			"Error": fmt.Sprintf("%v", err),
		}).Errorf("Error: Failed to bind KYB submission input")
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Invalid input", err.Error())
		return
	}

	// Get user ID from the context
	userIDValue, exists := ctx.Get("user_id")
	if !exists {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "User not authenticated", nil)
		return
	}

	// Validate user ID
	userID, err := uuid.Parse(userIDValue.(string))
	if err != nil {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid user ID", nil)
		return
	}

	// Fetch user record
	userRecord, err := storage.Client.User.
		Query().
		Where(user.IDEQ(userID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			u.APIResponse(ctx, http.StatusNotFound, "error", "User not found", nil)
			return
		}
		logger.WithFields(logger.Fields{
			"Error":  fmt.Sprintf("%v", err),
			"UserID": userID,
		}).Error("Error: Failed to query user")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to process request", nil)
		return
	}

	// Check if user already has a KYB submission
	existingSubmission, err := storage.Client.KYBProfile.
		Query().
		Where(kybprofile.HasUserWith(user.IDEQ(userRecord.ID))).
		Exist(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":  fmt.Sprintf("%v", err),
			"UserID": userID,
		}).Errorf("Error: Failed to check existing KYB submission")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to process request", nil)
		return
	}

	if existingSubmission {
		u.APIResponse(ctx, http.StatusConflict, "error", "KYB submission already submitted for this user", nil)
		return
	}

	// --- Begin Transaction ---
	tx, err := storage.Client.Tx(ctx)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":  fmt.Sprintf("%v", err),
			"UserID": userID,
		}).Errorf("Error: Failed to start transaction")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to process request", nil)
		return
	}
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()

	kybBuilder := tx.KYBProfile.
		Create().
		SetMobileNumber(input.MobileNumber).
		SetCompanyName(input.CompanyName).
		SetRegisteredBusinessAddress(input.RegisteredBusinessAddress).
		SetCertificateOfIncorporationURL(input.CertificateOfIncorporationUrl).
		SetArticlesOfIncorporationURL(input.ArticlesOfIncorporationUrl).
		SetProofOfBusinessAddressURL(input.ProofOfBusinessAddressUrl).
		SetUserID(userRecord.ID)

	if input.BusinessLicenseUrl != nil {
		kybBuilder.SetBusinessLicenseURL(*input.BusinessLicenseUrl)
	}
	if input.AmlPolicyUrl != nil {
		kybBuilder.SetAmlPolicyURL(*input.AmlPolicyUrl)
	}
	if input.KycPolicyUrl != nil {
		kybBuilder.SetKycPolicyURL(*input.KycPolicyUrl)
	}

	kybSubmission, err := kybBuilder.Save(ctx)
	if err != nil {
		tx.Rollback()
		logger.WithFields(logger.Fields{
			"Error":  fmt.Sprintf("%v", err),
			"UserID": userID,
		}).Errorf("Error: Failed to save KYB submission: %v", err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to save KYB submission", nil)
		return
	}

	for _, owner := range input.BeneficialOwners {
		_, err := tx.BeneficialOwner.
			Create().
			SetFullName(owner.FullName).
			SetResidentialAddress(owner.ResidentialAddress).
			SetProofOfResidentialAddressURL(owner.ProofOfResidentialAddressUrl).
			SetGovernmentIssuedIDURL(owner.GovernmentIssuedIdUrl).
			SetDateOfBirth(owner.DateOfBirth).
			SetOwnershipPercentage(owner.OwnershipPercentage).
			SetGovernmentIssuedIDType(beneficialowner.GovernmentIssuedIDType(owner.GovernmentIssuedIdType)).
			SetKybProfileID(kybSubmission.ID).
			Save(ctx)
		if err != nil {
			tx.Rollback()
			logger.WithFields(logger.Fields{
				"Error":  fmt.Sprintf("%v", err),
				"UserID": userID,
			}).Errorf("Error: Failed to save beneficial owner")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to save beneficial owner", nil)
			return
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		logger.WithFields(logger.Fields{
			"Error":  fmt.Sprintf("%v", err),
			"UserID": userID,
		}).Errorf("Error: Failed to commit transaction")
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to process request", nil)
		return
	}

	// ✅ Send Slack notification (outside transaction)
	err = ctrl.slackService.SendSubmissionNotification(userRecord.FirstName, userRecord.Email, kybSubmission.ID.String())
	if err != nil {
		logger.Errorf("Webhook log: Error sending Slack notification for submission %s: %v", kybSubmission.ID, err)
		u.APIResponse(ctx, http.StatusInternalServerError, "error", "Error sending Slack notification", nil)
		return
	}

	u.APIResponse(ctx, http.StatusCreated, "success", "KYB submission submitted successfully", gin.H{
		"submission_id": kybSubmission.ID,
	})
}

// UpdateKYCWalletAddress moves the KYC record to a new wallet address
func (ctrl *Controller) UpdateKYCWalletAddress(ctx *gin.Context) {
	var payload types.UpdateKYCWalletAddressRequest

	// Extract secret key from header
	payload.SecretKey = ctx.GetHeader("X-Secret-Key")
	if payload.SecretKey == "" {
		u.APIResponse(ctx, http.StatusUnauthorized, "error", "Missing secret key", nil)
		return
	}

	// Bind and validate JSON payload
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "Failed to validate payload", u.GetErrorData(err))
		return
	}

	// Basic payload validation
	if payload.OldWalletAddress == "" || payload.NewWalletAddress == "" {
		u.APIResponse(ctx, http.StatusBadRequest, "error", "OldWalletAddress and NewWalletAddress are required", nil)
		return
	}

	// Call service with request context
	response, err := ctrl.kycService.UpdateKYCWalletAddress(ctx.Request.Context(), payload)
	if err != nil {
		switch err {
		case kycErrors.ErrInvalidSecretKey:
			u.APIResponse(ctx, http.StatusUnauthorized, "error", "Invalid secret key", nil)
		case kycErrors.ErrKYCNotFound:
			u.APIResponse(ctx, http.StatusNotFound, "error", "No verification request found for this wallet address", nil)
		case kycErrors.ErrNotVerified:
			u.APIResponse(ctx, http.StatusBadRequest, "error", "This account has not been verified", nil)
		case kycErrors.ErrAlreadyVerified:
			u.APIResponse(ctx, http.StatusBadRequest, "error", "New wallet address is already verified", nil)
		case kycErrors.ErrDatabase:
			loger.WithFields(loger.Fields{
				"Error":            fmt.Sprintf("%v", err),
				"OldWalletAddress": payload.OldWalletAddress,
				"NewWalletAddress": payload.NewWalletAddress,
			}).Error("Database error during KYC wallet address update")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update KYC wallet address", nil)
		default:
			loger.WithFields(loger.Fields{
				"Error":            fmt.Sprintf("%v", err),
				"OldWalletAddress": payload.OldWalletAddress,
				"NewWalletAddress": payload.NewWalletAddress,
			}).Error("Failed to update KYC wallet address")
			u.APIResponse(ctx, http.StatusInternalServerError, "error", "Failed to update KYC wallet address", nil)
		}
		return
	}

	u.APIResponse(ctx, http.StatusOK, "success", "KYC wallet address updated successfully", response)
}
