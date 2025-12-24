package order

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/contracts"
	db "github.com/paycrest/aggregator/storage"
	"github.com/shopspring/decimal"

	"github.com/paycrest/aggregator/ent/fiatcurrency"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/paymentorderfulfillment"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	tokenent "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
)

// OrderEVM provides functionality related to onchain interactions for payment orders
type OrderEVM struct {
	priorityQueue *services.PriorityQueueService
	engineService *services.EngineService
}

// NewOrderEVM creates a new instance of OrderEVM.
func NewOrderEVM() types.OrderService {
	priorityQueue := services.NewPriorityQueueService()

	return &OrderEVM{
		priorityQueue: priorityQueue,
		engineService: services.NewEngineService(),
	}
}

var (
	serverConf = config.ServerConfig()
	cryptoConf = config.CryptoConfig()
)

// CreateOrder creates a new payment order on-chain.
func (s *OrderEVM) CreateOrder(ctx context.Context, orderID uuid.UUID) error {
	var err error
	orderIDPrefix := strings.Split(orderID.String(), "-")[0]

	// Fetch payment order from db
	order, err := db.Client.PaymentOrder.
		Query().
		Where(paymentorder.IDEQ(orderID)).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithSenderProfile().
		Only(ctx)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.fetchOrder: %w", orderIDPrefix, err)
	}

	if order.ReceiveAddress == "" {
		return fmt.Errorf("%s - CreateOrder.missingReceiveAddress: payment order has no receive address", orderIDPrefix)
	}
	address := order.ReceiveAddress

	if order.MessageHash != "" {
		return nil
	}

	// Create createOrder data
	encryptedOrderRecipient, err := cryptoUtils.EncryptOrderRecipient(order)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.encryptOrderRecipient: %w", orderIDPrefix, err)
	}

	// Save the encrypted order recipient to the message hash field
	_, err = order.Update().
		SetMessageHash(encryptedOrderRecipient).
		SetStatus(paymentorder.StatusPending).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.updateMessageHash: %w", orderIDPrefix, err)
	}

	_, err = order.Update().
		SetStatus(paymentorder.StatusInitiated).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.updateStatus: %w", orderIDPrefix, err)
	}

	createOrderData, err := s.createOrderCallData(order, encryptedOrderRecipient)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.createOrderCallData: %w", orderIDPrefix, err)
	}

	// Create approve data for gateway contract
	approveGatewayData, err := s.approveCallData(
		ethcommon.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
		utils.ToSubunit(order.Amount.Add(order.SenderFee), order.Edges.Token.Decimals),
	)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.approveCallData: %w", orderIDPrefix, err)
	}

	// Create order
	txPayload := []map[string]interface{}{
		{
			"to":    order.Edges.Token.ContractAddress,
			"data":  fmt.Sprintf("0x%x", approveGatewayData),
			"value": "0",
		},
		{
			"to":    order.Edges.Token.Edges.Network.GatewayContractAddress,
			"data":  fmt.Sprintf("0x%x", createOrderData),
			"value": "0",
		},
	}

	_, err = s.engineService.SendTransactionBatch(ctx, order.Edges.Token.Edges.Network.ChainID, address, txPayload)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.sendTransactionBatch: %w", orderIDPrefix, err)
	}

	return nil
}

// RefundOrder refunds sender on canceled lock order
func (s *OrderEVM) RefundOrder(ctx context.Context, network *ent.Network, orderID string) error {
	orderIDPrefix := strings.Split(orderID, "-")[0]

	// Fetch payment order from db
	lockOrder, err := db.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.GatewayIDEQ(orderID),
			paymentorder.StatusNEQ(paymentorder.StatusValidated),
			paymentorder.StatusNEQ(paymentorder.StatusRefunded),
			paymentorder.StatusNEQ(paymentorder.StatusSettled),
			paymentorder.StatusNEQ(paymentorder.StatusProcessing),
			paymentorder.HasTokenWith(
				tokenent.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		First(ctx)
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.fetchLockOrder: %w", orderIDPrefix, err)
	}

	// Create refundOrder data
	fee := utils.ToSubunit(decimal.NewFromInt(0), lockOrder.Edges.Token.Decimals)
	refundOrderData, err := s.refundCallData(fee, lockOrder.GatewayID)
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.refundCallData: %w", orderIDPrefix, err)
	}

	// Refund order
	txPayload := map[string]interface{}{
		"to":    lockOrder.Edges.Token.Edges.Network.GatewayContractAddress,
		"data":  fmt.Sprintf("0x%x", refundOrderData),
		"value": "0",
	}

	_, err = s.engineService.SendTransactionBatch(ctx, lockOrder.Edges.Token.Edges.Network.ChainID, cryptoConf.AggregatorAccountEVM, []map[string]interface{}{txPayload})
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.sendTransaction: %w", orderIDPrefix, err)
	}

	return nil
}

// SettleOrder settles a payment order on-chain.
func (s *OrderEVM) SettleOrder(ctx context.Context, orderID uuid.UUID) error {
	var err error

	orderIDPrefix := strings.Split(orderID.String(), "-")[0]

	// Fetch payment order from db
	order, err := db.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.IDEQ(orderID),
			paymentorder.StatusEQ(paymentorder.StatusValidated),
			paymentorder.HasFulfillmentsWith(
				paymentorderfulfillment.ValidationStatusEQ(paymentorderfulfillment.ValidationStatusSuccess),
			),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithProvider().
		Only(ctx)
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.fetchOrder: %w", orderIDPrefix, err)
	}

	// Create settleOrder data
	settleOrderData, err := s.settleCallData(ctx, order)
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.settleCallData: %w", orderIDPrefix, err)
	}

	// Settle order
	txPayload := map[string]interface{}{
		"to":    order.Edges.Token.Edges.Network.GatewayContractAddress,
		"data":  fmt.Sprintf("0x%x", settleOrderData),
		"value": "0",
	}

	_, err = s.engineService.SendTransactionBatch(ctx, order.Edges.Token.Edges.Network.ChainID, cryptoConf.AggregatorAccountEVM, []map[string]interface{}{txPayload})
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.sendTransaction: %w", orderIDPrefix, err)
	}

	return nil
}

// approveCallData creates the data for the ERC20 approve method
func (s *OrderEVM) approveCallData(spender ethcommon.Address, amount *big.Int) ([]byte, error) {
	// Create ABI
	erc20ABI, err := abi.JSON(strings.NewReader(contracts.ERC20TokenMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse erc20 ABI: %w", err)
	}

	// Create calldata
	calldata, err := erc20ABI.Pack("approve", spender, amount)
	if err != nil {
		return nil, fmt.Errorf("failed to pack approve ABI: %w", err)
	}

	return calldata, nil
}

// createOrderCallData creates the data for the createOrder method
func (s *OrderEVM) createOrderCallData(order *ent.PaymentOrder, encryptedOrderRecipient string) ([]byte, error) {
	// Define params
	params := &types.CreateOrderParams{
		Token:              ethcommon.HexToAddress(order.Edges.Token.ContractAddress),
		Amount:             utils.ToSubunit(order.Amount, order.Edges.Token.Decimals),
		Rate:               order.Rate.Mul(decimal.NewFromInt(100)).BigInt(),
		SenderFeeRecipient: ethcommon.HexToAddress(order.FeeAddress),
		SenderFee:          utils.ToSubunit(order.SenderFee, order.Edges.Token.Decimals),
		RefundAddress:      ethcommon.HexToAddress(order.ReturnAddress),
		MessageHash:        encryptedOrderRecipient,
	}

	// Create ABI
	gatewayABI, err := abi.JSON(strings.NewReader(contracts.GatewayMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse GatewayOrder ABI: %w", err)
	}

	// Generate call data
	data, err := gatewayABI.Pack(
		"createOrder",
		params.Token,
		params.Amount,
		params.Rate,
		params.SenderFeeRecipient,
		params.SenderFee,
		params.RefundAddress,
		params.MessageHash,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack createOrder ABI: %w", err)
	}

	return data, nil
}

// settleCallData creates the data for the settle method in the gateway contract
func (s *OrderEVM) settleCallData(ctx context.Context, order *ent.PaymentOrder) ([]byte, error) {
	gatewayABI, err := abi.JSON(strings.NewReader(contracts.GatewayMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse GatewayOrder ABI: %w", err)
	}

	institution, err := utils.GetInstitutionByCode(ctx, order.Institution, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get institution: %w", err)
	}

	// Fetch provider address from db
	token, err := db.Client.ProviderOrderToken.
		Query().
		Where(
			providerordertoken.NetworkEQ(order.Edges.Token.Edges.Network.Identifier),
			providerordertoken.HasProviderWith(
				providerprofile.IDEQ(order.Edges.Provider.ID),
			),
			providerordertoken.HasTokenWith(
				tokenent.IDEQ(order.Edges.Token.ID),
			),
			providerordertoken.HasCurrencyWith(
				fiatcurrency.CodeEQ(institution.Edges.FiatCurrency.Code),
			),
			providerordertoken.AddressNEQ(""),
		).
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch provider order token: %w", err)
	}

	orderPercent, _ := order.OrderPercent.
		Mul(decimal.NewFromInt(1000)). // convert percent to BPS
		Float64()

	orderID, err := hex.DecodeString(order.GatewayID[2:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode orderID: %w", err)
	}

	splitOrderID := strings.ReplaceAll(order.ID.String(), "-", "")

	// Generate calldata for settlement
	data, err := gatewayABI.Pack(
		"settle",
		utils.StringToByte32(splitOrderID),
		utils.StringToByte32(string(orderID)),
		ethcommon.HexToAddress(token.Address),
		uint64(orderPercent),
		uint64(0), // rebatePercent - default to 0 for now
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack settle ABI: %w", err)
	}

	return data, nil
}

// refundCallData creates the data for the refund method
func (s *OrderEVM) refundCallData(fee *big.Int, orderId string) ([]byte, error) {
	gatewayABI, err := abi.JSON(strings.NewReader(contracts.GatewayMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse GatewayOrder ABI: %w", err)
	}

	decodedOrderID, err := hex.DecodeString(orderId[2:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode orderId: %w", err)
	}

	// Generate calldata for refund, orderID, and label should be byte32
	data, err := gatewayABI.Pack(
		"refund",
		fee,
		utils.StringToByte32(string(decodedOrderID)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack refund ABI: %w", err)
	}

	return data, nil
}
