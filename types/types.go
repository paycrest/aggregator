package types

import (
	"context"
	"math/big"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/lockorderfulfillment"
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/transactionlog"
	"github.com/paycrest/aggregator/ent/user"
	"github.com/shopspring/decimal"
)

// RPCClient is an interface for interacting with the blockchain.
type RPCClient interface {
	FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
	SuggestGasPrice(ctx context.Context) (*big.Int, error)
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
	EstimateGas(ctx context.Context, call ethereum.CallMsg) (gas uint64, err error)
	SubscribeFilterLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error)
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	Commit() common.Hash
}

// Custom type that implements RPCClient
type ethRPC struct {
	*ethclient.Client
}

// Implements Commit() method
func (e *ethRPC) Commit() common.Hash {
	return common.Hash{} // no-op
}

// Helper function to create client
func NewEthClient(endpoint string) (RPCClient, error) {

	ethClient, err := ethclient.Dial(endpoint)
	if err != nil {
		return nil, err
	}

	return &ethRPC{ethClient}, nil
}

// TokenTransferEvent represents a token transfer event.
type TokenTransferEvent struct {
	BlockNumber int64
	TxHash      string
	From        string
	To          string
	Value       decimal.Decimal
}

// OrderCreatedEvent represents an order created event.
type OrderCreatedEvent struct {
	BlockNumber int64
	TxHash      string
	Token       string
	Amount      decimal.Decimal
	ProtocolFee decimal.Decimal
	OrderId     string
	Rate        decimal.Decimal
	MessageHash string
	Sender      string
}

// OrderSettledEvent represents a order settled event.
type OrderSettledEvent struct {
	BlockNumber       int64
	TxHash            string
	SplitOrderId      string
	OrderId           string
	LiquidityProvider string
	SettlePercent     decimal.Decimal
}

// OrderRefundedEvent represents a order refunded event.
type OrderRefundedEvent struct {
	BlockNumber int64
	TxHash      string
	Fee         decimal.Decimal
	OrderId     string
}

// OrderService provides an interface for the OrderService
type OrderService interface {
	CreateOrder(ctx context.Context, orderID uuid.UUID) error
	RefundOrder(ctx context.Context, network *ent.Network, orderID string) error
	SettleOrder(ctx context.Context, orderID uuid.UUID) error
}

// Indexer provides an interface for indexing blockchain data to the database.
type Indexer interface {
	IndexTransfer(ctx context.Context, token *ent.Token, address string, fromBlock int64, toBlock int64, txHash string) error
	IndexOrderCreated(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64, txHash string) error
	IndexOrderSettled(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64, txHash string) error
	IndexOrderRefunded(ctx context.Context, network *ent.Network, address string, fromBlock int64, toBlock int64, txHash string) error
}

// KYCProvider defines the interface for KYC verification providers
type KYCProvider interface {
	RequestVerification(ctx context.Context, req VerificationRequest) (*VerificationResponse, error)
	CheckStatus(ctx context.Context, walletAddress string) (*VerificationStatus, error)
	HandleWebhook(ctx context.Context, payload []byte) error
}

// CreateOrderParams is the parameters for the create order payload
type CreateOrderParams struct {
	Token              common.Address
	Amount             *big.Int
	Rate               *big.Int
	SenderFeeRecipient common.Address
	SenderFee          *big.Int
	RefundAddress      common.Address
	MessageHash        string
}

// VerificationRequest represents a generic KYC verification request
type VerificationRequest struct {
	WalletAddress string `json:"walletAddress"`
	Signature     string `json:"signature"`
	Nonce         string `json:"nonce"`
}

// VerificationResponse represents a generic KYC verification response
type VerificationResponse struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// VerificationStatus represents the status of a KYC verification
type VerificationStatus struct {
	URL    string `json:"url"`
	Status string `json:"status"`
}

// RegisterPayload is the payload for the register endpoint
type RegisterPayload struct {
	FirstName  string   `json:"firstName" binding:"required"`
	LastName   string   `json:"lastName" binding:"required"`
	Email      string   `json:"email" binding:"required,email"`
	Password   string   `json:"password" binding:"required,min=6,max=20"`
	Currencies []string `json:"currencies"`
	Scopes     []string `json:"scopes" binding:"required,dive,oneof=sender provider"`
}

// RegisterResponse is the response for the register endpoint
type RegisterResponse struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	FirstName string    `json:"firstName"`
	LastName  string    `json:"lastName"`
	Email     string    `json:"email"`
}

// LockOrderResponse is the response for the lock payment order model
type LockOrderResponse struct {
	ID                uuid.UUID               `json:"id"`
	Amount            decimal.Decimal         `json:"amount"`
	Token             string                  `json:"token"`
	Institution       string                  `json:"institution"`
	AccountIdentifier string                  `json:"accountIdentifier"`
	AccountName       string                  `json:"accountName"`
	Status            lockpaymentorder.Status `json:"status"`
	UpdatedAt         time.Time               `json:"updatedAt"`
}

// AcceptOrderResponse is the response for the accept order endpoint
type AcceptOrderResponse struct {
	ID                uuid.UUID              `json:"id"`
	Amount            decimal.Decimal        `json:"amount"`
	Institution       string                 `json:"institution"`
	AccountIdentifier string                 `json:"accountIdentifier"`
	AccountName       string                 `json:"accountName"`
	Memo              string                 `json:"memo"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// FulfillLockOrderPayload is the payload for the fulfill order endpoint
type FulfillLockOrderPayload struct {
	PSP              string                                `json:"psp" binding:"required"`
	TxID             string                                `json:"txId" binding:"required"`
	ValidationStatus lockorderfulfillment.ValidationStatus `json:"validationStatus"`
	ValidationError  string                                `json:"validationError"`
}

// CancelLockOrderPayload is the payload for the cancel order endpoint
type CancelLockOrderPayload struct {
	Reason string `json:"reason" binding:"required"`
}

// LoginPayload is the payload for the login endpoint
type LoginPayload struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6,max=20"`
}

// LoginResponse is the response for the login endpoint
type LoginResponse struct {
	AccessToken  string   `json:"accessToken"`
	RefreshToken string   `json:"refreshToken"`
	Scopes       []string `json:"scopes"`
}

// RefreshJWTPayload is the payload for the refresh endpoint
type RefreshJWTPayload struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

// SenderOrderAddressPayload defines the sender setting for an address
type SenderOrderAddressPayload struct {
	Network       string `json:"network" binding:"required"`
	FeeAddress    string `json:"feeAddress" binding:"required"`
	RefundAddress string `json:"refundAddress" binding:"required"`
}

// SenderOrderTokenPayload defines the sender setting for a token
type SenderOrderTokenPayload struct {
	Symbol     string                      `json:"symbol" binding:"required"`
	FeePercent decimal.Decimal             `json:"feePercent" binding:"required"`
	Addresses  []SenderOrderAddressPayload `json:"addresses"`
}

// SenderProfilePayload is the payload for the sender profile endpoint
type SenderProfilePayload struct {
	WebhookURL      string                    `json:"webhookURL"`
	DomainWhitelist []string                  `json:"domainWhitelist"`
	Tokens          []SenderOrderTokenPayload `json:"tokens"`
}

// ProviderOrderTokenPayload defines the provider setting for a token
type ProviderOrderTokenPayload struct {
	Currency               string                                `json:"currency" binding:"required"`
	Symbol                 string                                `json:"symbol" binding:"required"`
	ConversionRateType     providerordertoken.ConversionRateType `json:"conversionRateType" binding:"required,oneof=fixed floating"`
	FixedConversionRate    decimal.Decimal                       `json:"fixedConversionRate" binding:"required,gt=0"`
	FloatingConversionRate decimal.Decimal                       `json:"floatingConversionRate" binding:"required"`
	MaxOrderAmount         decimal.Decimal                       `json:"maxOrderAmount" binding:"required,gt=0"`
	MinOrderAmount         decimal.Decimal                       `json:"minOrderAmount" binding:"required,gt=0"`
	RateSlippage           decimal.Decimal                       `json:"rateSlippage" binding:"gte=0.1"`
	Address                string                                `json:"address" binding:"required"`
	Network                string                                `json:"network" binding:"required"`
}

// ProviderProfilePayload is the payload for the provider profile endpoint
type ProviderProfilePayload struct {
	TradingName    string                      `json:"tradingName"`
	Currencies     []string                    `json:"currencies"`
	HostIdentifier string                      `json:"hostIdentifier"`
	IsAvailable    bool                        `json:"isAvailable"`
	IsActive       bool                        `json:"isActive"`
	Tokens         []ProviderOrderTokenPayload `json:"tokens"`
	VisibilityMode string                      `json:"visibilityMode"`
}

// ProviderProfileResponse is the response for the provider profile endpoint
type ProviderProfileResponse struct {
	ID                    string                      `json:"id"`
	FirstName             string                      `json:"firstName"`
	LastName              string                      `json:"lastName"`
	Email                 string                      `json:"email"`
	TradingName           string                      `json:"tradingName"`
	Currencies            []string                    `json:"currencies"`
	HostIdentifier        string                      `json:"hostIdentifier"`
	IsAvailable           bool                        `json:"isAvailable"`
	Tokens                []ProviderOrderTokenPayload `json:"tokens"`
	APIKey                APIKeyResponse              `json:"apiKey"`
	IsActive              bool                        `json:"isActive"`
	VisibilityMode        string                      `json:"visibilityMode"`
	KYBVerificationStatus user.KybVerificationStatus  `json:"kybVerificationStatus"`
}

// SenderOrderTokenResponse defines the provider setting for a token
type SenderOrderTokenResponse struct {
	Symbol        string          `json:"symbol" binding:"required"`
	FeePercent    decimal.Decimal `json:"feePercent" binding:"required"`
	Network       string          `json:"network" binding:"required"`
	FeeAddress    string          `json:"feeAddress" binding:"required"`
	RefundAddress string          `json:"refundAddress" binding:"required"`
}

// SenderProfileResponse is the response for the sender profile endpoint
type SenderProfileResponse struct {
	ID                    uuid.UUID                  `json:"id"`
	FirstName             string                     `json:"firstName"`
	LastName              string                     `json:"lastName"`
	Email                 string                     `json:"email"`
	WebhookURL            string                     `json:"webhookUrl"`
	DomainWhitelist       []string                   `json:"domainWhitelist"`
	Tokens                []SenderOrderTokenResponse `json:"tokens"`
	APIKey                APIKeyResponse             `json:"apiKey"`
	ProviderID            string                     `json:"providerId"`
	ProviderCurrencies    []string                   `json:"providerCurrencies"`
	IsActive              bool                       `json:"isActive"`
	KYBVerificationStatus user.KybVerificationStatus `json:"kybVerificationStatus"`
}

// RefreshResponse is the response for the refresh endpoint
type RefreshResponse struct {
	AccessToken string `json:"accessToken"`
}

// APIKeyResponse is the response type for an API key
type APIKeyResponse struct {
	ID     uuid.UUID `json:"id"`
	Secret string    `json:"secret"`
}

// ERC20Transfer is the Transfer event of an ERC20 smart contract
type ERC20Transfer struct {
	From  common.Address
	To    common.Address
	Value *big.Int
}

// LockPaymentOrderFields is the fields for a lock payment order
type LockPaymentOrderFields struct {
	ID                uuid.UUID
	Token             *ent.Token
	Network           *ent.Network
	GatewayID         string
	Amount            decimal.Decimal
	Rate              decimal.Decimal
	BlockNumber       int64
	TxHash            string
	Institution       string
	AccountIdentifier string
	AccountName       string
	ProviderID        string
	Memo              string
	Metadata          map[string]interface{}
	ProvisionBucket   *ent.ProvisionBucket
	UpdatedAt         time.Time
	CreatedAt         time.Time
}

// TransactionLog
type TransactionLog struct {
	ID        uuid.UUID             `json:"id" binding:"required"`
	GatewayId string                `json:"gateway_id"`
	Status    transactionlog.Status `json:"status" binding:"required"`
	TxHash    string                `json:"tx_hash" binding:"required"`
	CreatedAt time.Time             `json:"created_at" binding:"required"`
}

// LockPaymentOrderResponse is the response for a lock payment order
type LockPaymentOrderResponse struct {
	ID                  uuid.UUID               `json:"id"`
	Token               string                  `json:"token"`
	GatewayID           string                  `json:"gatewayId"`
	Amount              decimal.Decimal         `json:"amount"`
	Rate                decimal.Decimal         `json:"rate"`
	BlockNumber         int64                   `json:"blockNumber"`
	TxHash              string                  `json:"txHash"`
	Institution         string                  `json:"institution"`
	AccountIdentifier   string                  `json:"accountIdentifier"`
	AccountName         string                  `json:"accountName"`
	ProviderID          string                  `json:"providerId"`
	Memo                string                  `json:"memo"`
	Network             string                  `json:"network"`
	Status              lockpaymentorder.Status `json:"status"`
	UpdatedAt           time.Time               `json:"updatedAt"`
	CreatedAt           time.Time               `json:"createdAt"`
	Transactions        []TransactionLog        `json:"transactionLogs"`
	CancellationReasons []string                `json:"cancellationReasons"`
}

type LockPaymentOrderTxReceipt struct {
	Status    lockpaymentorder.Status `json:"status"`
	TxHash    string                  `json:"txHash"`
	Timestamp time.Time               `json:"timestamp"`
}

type LockPaymentOrderSplitOrder struct {
	SplitOrderID uuid.UUID       `json:"splitOrderId"`
	Amount       decimal.Decimal `json:"amount"`
	Rate         decimal.Decimal `json:"rate"`
	OrderPercent decimal.Decimal `json:"orderPercent"`
}

type LockPaymentOrderStatusResponse struct {
	OrderID       string                       `json:"orderId"`
	Amount        decimal.Decimal              `json:"amount"`
	Token         string                       `json:"token"`
	Network       string                       `json:"network"`
	SettlePercent decimal.Decimal              `json:"settlePercent"`
	Status        lockpaymentorder.Status      `json:"status"`
	TxHash        string                       `json:"txHash"`
	Settlements   []LockPaymentOrderSplitOrder `json:"settlements"`
	TxReceipts    []LockPaymentOrderTxReceipt  `json:"txReceipts"`
	UpdatedAt     time.Time                    `json:"updatedAt"`
}

// PaymentOrderRecipient describes a payment order recipient
type PaymentOrderRecipient struct {
	Institution       string                 `json:"institution" binding:"required"`
	AccountIdentifier string                 `json:"accountIdentifier" binding:"required"`
	AccountName       string                 `json:"accountName" binding:"required"`
	Memo              string                 `json:"memo" binding:"required"`
	ProviderID        string                 `json:"providerId"`
	Metadata          map[string]interface{} `json:"metadata"`
	Currency          string                 `json:"currency"`
	Nonce             string                 `json:"nonce"`
}

// NewPaymentOrderPayload is the payload for the create payment order endpoint
type NewPaymentOrderPayload struct {
	Amount        decimal.Decimal       `json:"amount" binding:"required"`
	Token         string                `json:"token" binding:"required"`
	Rate          decimal.Decimal       `json:"rate" binding:"required"`
	Network       string                `json:"network" binding:"required"`
	Recipient     PaymentOrderRecipient `json:"recipient" binding:"required"`
	Reference     string                `json:"reference"`
	ReturnAddress string                `json:"returnAddress"`
	FeePercent    decimal.Decimal       `json:"feePercent"`
	FeeAddress    string                `json:"feeAddress"`
}

// ReceiveAddressResponse is the response type for a receive address
type ReceiveAddressResponse struct {
	ID             uuid.UUID       `json:"id"`
	Amount         decimal.Decimal `json:"amount"`
	Token          string          `json:"token"`
	Network        string          `json:"network"`
	ReceiveAddress string          `json:"receiveAddress"`
	ValidUntil     time.Time       `json:"validUntil"`
	SenderFee      decimal.Decimal `json:"senderFee"`
	TransactionFee decimal.Decimal `json:"transactionFee"`
	Reference      string          `json:"reference"`
}

// PaymentOrderResponse is the response type for a payment order
type PaymentOrderResponse struct {
	ID             uuid.UUID             `json:"id"`
	Amount         decimal.Decimal       `json:"amount"`
	AmountPaid     decimal.Decimal       `json:"amountPaid"`
	AmountReturned decimal.Decimal       `json:"amountReturned"`
	Token          string                `json:"token"`
	SenderFee      decimal.Decimal       `json:"senderFee"`
	TransactionFee decimal.Decimal       `json:"transactionFee"`
	Rate           decimal.Decimal       `json:"rate"`
	Network        string                `json:"network"`
	GatewayID      string                `json:"gatewayId"`
	Recipient      PaymentOrderRecipient `json:"recipient"`
	FromAddress    string                `json:"fromAddress"`
	ReturnAddress  string                `json:"returnAddress"`
	ReceiveAddress string                `json:"receiveAddress"`
	FeeAddress     string                `json:"feeAddress"`
	Reference      string                `json:"reference"`
	CreatedAt      time.Time             `json:"createdAt"`
	UpdatedAt      time.Time             `json:"updatedAt"`
	TxHash         string                `json:"txHash"`
	Status         paymentorder.Status   `json:"status"`
	Transactions   []TransactionLog      `json:"transactionLogs"`
}

// PaymentOrderWebhookData is the data type for a payment order webhook
type PaymentOrderWebhookData struct {
	ID             uuid.UUID             `json:"id"`
	Amount         decimal.Decimal       `json:"amount"`
	AmountPaid     decimal.Decimal       `json:"amountPaid"`
	AmountReturned decimal.Decimal       `json:"amountReturned"`
	PercentSettled decimal.Decimal       `json:"percentSettled"`
	SenderFee      decimal.Decimal       `json:"senderFee"`
	NetworkFee     decimal.Decimal       `json:"networkFee"`
	Rate           decimal.Decimal       `json:"rate"`
	Network        string                `json:"network"`
	GatewayID      string                `json:"gatewayId"`
	SenderID       uuid.UUID             `json:"senderId"`
	Recipient      PaymentOrderRecipient `json:"recipient"`
	FromAddress    string                `json:"fromAddress"`
	ReturnAddress  string                `json:"returnAddress"`
	Reference      string                `json:"reference"`
	UpdatedAt      time.Time             `json:"updatedAt"`
	CreatedAt      time.Time             `json:"createdAt"`
	TxHash         string                `json:"txHash"`
	Status         paymentorder.Status   `json:"status"`
}

// PaymentOrderWebhookPayload is the request type for a payment order webhook
type PaymentOrderWebhookPayload struct {
	Event string                  `json:"event"`
	Data  PaymentOrderWebhookData `json:"data"`
}

// ConfirmEmailPayload is the payload for the confirmEmail endpoint
type ConfirmEmailPayload struct {
	Token string `json:"token" binding:"required"`
	Email string `json:"email" binding:"required,email"`
}

// SendEmailPayload is content of a email request.
type SendEmailPayload struct {
	FromAddress string
	ToAddress   string
	Subject     string
	Body        string
	HTMLBody    string
	DynamicData map[string]interface{}
}

// SendEmailResponse is the response for a sent email
type SendEmailResponse struct {
	Response string `json:"response"`
	Id       string `json:"id"`
}

// MarketRateResponse is the response for the market rate endpoint
type MarketRateResponse struct {
	MarketRate  decimal.Decimal `json:"marketRate"`
	MinimumRate decimal.Decimal `json:"minimumRate"`
	MaximumRate decimal.Decimal `json:"maximumRate"`
}

type ResendTokenPayload struct {
	Scope string `json:"scope" binding:"required,oneof=emailVerification resetPassword"`
	Email string `json:"email" binding:"required,email"`
}

type SupportedInstitutions struct {
	Name string           `json:"name"`
	Code string           `json:"code"`
	Type institution.Type `json:"type"`
}

// SupportedCurrencies is the supported currencies response struct.
type SupportedCurrencies struct {
	Code       string          `json:"code"`
	Name       string          `json:"name"`
	ShortName  string          `json:"shortName"`
	Decimals   int8            `json:"decimals"`
	Symbol     string          `json:"symbol"`
	MarketRate decimal.Decimal `json:"marketRate"`
}

// Response is the struct for an API response
type Response struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

// ErrorData is the struct for error data i.e when Status is "error"
type ErrorData struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Payload for reset password request
type ResetPasswordPayload struct {
	Password   string `json:"password" binding:"required,min=6,max=20"`
	ResetToken string `json:"resetToken" binding:"required"`
}

// Payload for reset password token endpoint
type ResetPasswordTokenPayload struct {
	Email string `json:"email" binding:"required,email"`
}

// ProviderLockOrderList is the struct for a list of provider lock orders
type ProviderLockOrderList struct {
	TotalRecords int                        `json:"total"`
	Page         int                        `json:"page"`
	PageSize     int                        `json:"pageSize"`
	Orders       []LockPaymentOrderResponse `json:"orders"`
}

// SenderOrderList is the struct for a list of sender payment orders
type SenderPaymentOrderList struct {
	TotalRecords int                    `json:"total"`
	Page         int                    `json:"page"`
	PageSize     int                    `json:"pageSize"`
	Orders       []PaymentOrderResponse `json:"orders"`
}

// ChangePasswordPayload is the payload for the change password endpoint
type ChangePasswordPayload struct {
	OldPassword string `json:"oldPassword" binding:"required,min=6,max=20"`
	NewPassword string `json:"newPassword" binding:"required,min=6,max=20"`
}

// SenderStatsResponse is the response for the sender stats endpoint
type SenderStatsResponse struct {
	TotalOrders      int             `json:"totalOrders"`
	TotalOrderVolume decimal.Decimal `json:"totalOrderVolume"`
	TotalFeeEarnings decimal.Decimal `json:"totalFeeEarnings"`
}

// ProviderStatsResponse is the response for the provider stats endpoint
type ProviderStatsResponse struct {
	TotalOrders       int             `json:"totalOrders"`
	TotalFiatVolume   decimal.Decimal `json:"totalFiatVolume"`
	TotalCryptoVolume decimal.Decimal `json:"totalCryptoVolume"`
}

// VerifyAccountRequest is the request for account verification of an institution
type VerifyAccountRequest struct {
	Institution       string `json:"institution" binding:"required"`
	AccountIdentifier string `json:"accountIdentifier" binding:"required"`
}

// NewLinkedAddressRequest is the request for linking a new address
type NewLinkedAddressRequest struct {
	Institution       string `json:"institution" binding:"required"`
	AccountIdentifier string `json:"accountIdentifier" binding:"required"`
	AccountName       string `json:"accountName" binding:"required"`
}

// NewLinkedAddressResponse is the response for linking a new address
type NewLinkedAddressResponse struct {
	LinkedAddress     string    `json:"linkedAddress"`
	Institution       string    `json:"institution"`
	AccountIdentifier string    `json:"accountIdentifier"`
	AccountName       string    `json:"accountName"`
	UpdatedAt         time.Time `json:"updatedAt"`
	CreatedAt         time.Time `json:"createdAt"`
}

// LinkedAddressResponse is the response for a linked address
type LinkedAddressResponse struct {
	LinkedAddress     string `json:"linkedAddress"`
	Currency          string `json:"currency"`
	Institution       string `json:"institution"`
	AccountIdentifier string `json:"accountIdentifier"`
	AccountName       string `json:"accountName"`
}

// LinkedAddressTransactionRecipient is the struct for a linked address transaction recipient
type LinkedAddressTransactionRecipient struct {
	Currency          string `json:"currency"`
	Institution       string `json:"institution"`
	AccountIdentifier string `json:"accountIdentifier"`
	AccountName       string `json:"accountName"`
}

// LinkedAddressTransaction is the struct for a linked address transaction
type LinkedAddressTransaction struct {
	ID            uuid.UUID                         `json:"id"`
	Amount        decimal.Decimal                   `json:"amount"`
	Token         string                            `json:"token"`
	Rate          decimal.Decimal                   `json:"rate"`
	Network       string                            `json:"network"`
	GatewayID     string                            `json:"gatewayId"`
	Recipient     LinkedAddressTransactionRecipient `json:"recipient"`
	FromAddress   string                            `json:"fromAddress"`
	ReturnAddress string                            `json:"returnAddress"`
	CreatedAt     time.Time                         `json:"createdAt"`
	UpdatedAt     time.Time                         `json:"updatedAt"`
	TxHash        string                            `json:"txHash"`
	Status        paymentorder.Status               `json:"status"`
	Transactions  []TransactionLog                  `json:"transactionLogs"`
}

// LinkedAddressTransactionList is the struct for a list of linked address transactions
type LinkedAddressTransactionList struct {
	TotalRecords int                        `json:"total"`
	Page         int                        `json:"page"`
	PageSize     int                        `json:"pageSize"`
	Transactions []LinkedAddressTransaction `json:"transactions"`
}

// SupportedTokenResponse represents the structure for supported tokens
type SupportedTokenResponse struct {
	Symbol          string `json:"symbol"`
	ContractAddress string `json:"contractAddress"`
	Decimals        int8   `json:"decimals"`
	BaseCurrency    string `json:"baseCurrency"`
	Network         string `json:"network"`
}

// KYBSubmissionInput represents the input structure for KYB form submission
type KYBSubmissionInput struct {
	MobileNumber                  string                 `json:"mobileNumber" binding:"required"`
	CompanyName                   string                 `json:"companyName" binding:"required"`
	RegisteredBusinessAddress     string                 `json:"registeredBusinessAddress" binding:"required"`
	CertificateOfIncorporationUrl string                 `json:"certificateOfIncorporationUrl" binding:"required"`
	ArticlesOfIncorporationUrl    string                 `json:"articlesOfIncorporationUrl" binding:"required"`
	BusinessLicenseUrl            *string                `json:"businessLicenseUrl"`
	ProofOfBusinessAddressUrl     string                 `json:"proofOfBusinessAddressUrl" binding:"required"`
	ProofOfResidentialAddressUrl  string                 `json:"proofOfResidentialAddressUrl" binding:"required"`
	AmlPolicyUrl                  *string                `json:"amlPolicyUrl"`
	KycPolicyUrl                  *string                `json:"kycPolicyUrl"`
	BeneficialOwners              []BeneficialOwnerInput `json:"beneficialOwners" binding:"required,dive"`
}

// BeneficialOwnerInput represents the input structure for a beneficial owner
type BeneficialOwnerInput struct {
	FullName                     string  `json:"fullName" binding:"required"`
	ResidentialAddress           string  `json:"residentialAddress" binding:"required"`
	ProofOfResidentialAddressUrl string  `json:"proofOfResidentialAddressUrl" binding:"required"`
	GovernmentIssuedIdUrl        string  `json:"governmentIssuedIdUrl" binding:"required"`
	DateOfBirth                  string  `json:"dateOfBirth" binding:"required"`
	OwnershipPercentage          float64 `json:"ownershipPercentage" binding:"required,gt=0,lte=100"`
	GovernmentIssuedIdType       string  `json:"governmentIssuedIdType" binding:"required,oneof=passport drivers_license national_id"`
}

// IndexTransactionRequest represents the request payload for indexing a specific transaction
type IndexTransactionRequest struct {
	TxHash  string `json:"txHash" binding:"required"`
	ChainID int64  `json:"chainId" binding:"required"`
}

// IndexTransactionResponse represents the response for the index transaction endpoint
type IndexTransactionResponse struct {
	Events struct {
		Transfer      int `json:"Transfer"`
		OrderCreated  int `json:"OrderCreated"`
		OrderSettled  int `json:"OrderSettled"`
		OrderRefunded int `json:"OrderRefunded"`
	} `json:"events"`
}

// ThirdwebWebhookPayload represents the structure of thirdweb insight webhook payload
type ThirdwebWebhookPayload struct {
	Data      []ThirdwebWebhookEvent `json:"data"`
	Timestamp int64                  `json:"timestamp"`
	Topic     string                 `json:"topic"`
}

// ThirdwebWebhookEvent represents a single event in the webhook payload
type ThirdwebWebhookEvent struct {
	Data   ThirdwebEventData `json:"data"`
	Status string            `json:"status"`
	Type   string            `json:"type"`
	ID     string            `json:"id"`
}

// ThirdwebEventData represents the event data structure
type ThirdwebEventData struct {
	ChainID          string               `json:"chain_id"`
	BlockNumber      int64                `json:"block_number"`
	BlockHash        string               `json:"block_hash"`
	BlockTimestamp   int64                `json:"block_timestamp"`
	TransactionHash  string               `json:"transaction_hash"`
	TransactionIndex int                  `json:"transaction_index"`
	LogIndex         int                  `json:"log_index"`
	Address          string               `json:"address"`
	Data             string               `json:"data"`
	Topics           []string             `json:"topics"`
	Decoded          ThirdwebDecodedEvent `json:"decoded"`
}

// ThirdwebDecodedEvent represents the decoded event parameters
type ThirdwebDecodedEvent struct {
	Name             string                 `json:"name"`
	IndexedParams    map[string]interface{} `json:"indexed_params"`
	NonIndexedParams map[string]interface{} `json:"non_indexed_params"`
}

// WebhookSignatureVerification represents the result of signature verification
type WebhookSignatureVerification struct {
	IsValid   bool
	WebhookID string
	Secret    string
}
