package order

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/contracts"
	db "github.com/paycrest/aggregator/storage"
	"github.com/shopspring/decimal"

	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/lockorderfulfillment"
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
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

var serverConf = config.ServerConfig()
var cryptoConf = config.CryptoConfig()

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
		WithRecipient().
		WithReceiveAddress().
		WithLinkedAddress().
		Only(ctx)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.fetchOrder: %w", orderIDPrefix, err)
	}

	var address string
	if order.Edges.ReceiveAddress != nil {
		address = order.Edges.ReceiveAddress.Address
	} else if order.Edges.LinkedAddress != nil {
		address = order.Edges.LinkedAddress.Address

		// Update the rate
		institution, err := db.Client.Institution.
			Query().
			Where(institution.CodeEQ(order.Edges.Recipient.Institution)).
			WithFiatCurrency().
			Only(ctx)
		if err != nil {
			return fmt.Errorf("%s - CreateOrder.fetchInstitution: %w", orderIDPrefix, err)
		}

		rate, err := utils.GetTokenRateFromQueue(order.Edges.Token.Symbol, order.Amount, institution.Edges.FiatCurrency.Code, institution.Edges.FiatCurrency.MarketRate)
		if err != nil {
			return fmt.Errorf("%s - CreateOrder.getRate: %w", orderIDPrefix, err)
		}

		if rate != order.Rate {
			// Update order rate
			order.Rate = rate

			// Refresh order from db
			order, err = db.Client.PaymentOrder.
				Query().
				Where(paymentorder.IDEQ(orderID)).
				WithToken(func(tq *ent.TokenQuery) {
					tq.WithNetwork()
				}).
				WithSenderProfile().
				WithRecipient().
				WithReceiveAddress().
				WithLinkedAddress().
				Only(ctx)
			if err != nil {
				return fmt.Errorf("%s - CreateOrder.refreshOrder: %w", orderIDPrefix, err)
			}
		}
	}

	// Create createOrder data
	encryptedOrderRecipient, err := cryptoUtils.EncryptOrderRecipient(order.Edges.Recipient)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.encryptOrderRecipient: %w", orderIDPrefix, err)
	}

	createOrderData, err := s.createOrderCallData(order, encryptedOrderRecipient)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.createOrderCallData: %w", orderIDPrefix, err)
	}

	// Create approve data for gateway contract
	approveGatewayData, err := s.approveCallData(
		ethcommon.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
		utils.ToSubunit(order.Amount.Add(order.ProtocolFee).Add(order.SenderFee), order.Edges.Token.Decimals),
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

	queueId, err := s.engineService.SendTransactionBatch(ctx, order.Edges.Token.Edges.Network.ChainID, address, txPayload)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.sendTransactionBatch: %w", orderIDPrefix, err)
	}

	// Wait for createOrder tx to be mined
	result, err := s.engineService.WaitForTransactionMined(ctx, queueId, 5*time.Minute)
	if err != nil {
		return fmt.Errorf("CreateOrder.waitForTransactionMined: %w", err)
	}

	txHash := result["transactionHash"].(string)
	blockNumber, err := strconv.ParseInt(result["confirmedAtBlockNumber"].(string), 10, 64)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.parseBlockNumber: %w", orderIDPrefix, err)
	}

	// Update payment order with tx hash and block number
	_, err = order.Update().
		SetTxHash(txHash).
		SetBlockNumber(blockNumber).
		SetStatus(paymentorder.StatusProcessing).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.updateTxHash: %w", orderIDPrefix, err)
	}

	_, err = order.Update().
		SetStatus(paymentorder.StatusInitiated).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.updateTxHash: %w", orderIDPrefix, err)
	}

	return nil
}

// RefundOrder refunds sender on canceled lock order
func (s *OrderEVM) RefundOrder(ctx context.Context, network *ent.Network, orderID string) error {
	orderIDPrefix := strings.Split(orderID, "-")[0]

	// Fetch lock order from db
	lockOrder, err := db.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.GatewayIDEQ(orderID),
			lockpaymentorder.HasTokenWith(
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

	queueId, err := s.engineService.SendTransactionBatch(ctx, lockOrder.Edges.Token.Edges.Network.ChainID, cryptoConf.AggregatorSmartAccount, []map[string]interface{}{txPayload})
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.sendTransaction: %w", orderIDPrefix, err)
	}

	// Wait for refundOrder tx to be mined
	result, err := s.engineService.WaitForTransactionMined(ctx, queueId, 5*time.Minute)
	if err != nil {
		if strings.Contains(err.Error(), "OrderRefunded") {
			_, err = lockOrder.Update().
				SetStatus(lockpaymentorder.StatusRefunded).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("%s - RefundOrder.updateStatus: %w", orderIDPrefix, err)
			}
			return nil
		}

		if strings.Contains(err.Error(), "OrderRefunded") {
			_, err = lockOrder.Update().
				SetStatus(lockpaymentorder.StatusRefunded).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("%s - RefundOrder.updateStatus: %w", orderIDPrefix, err)
			}
			return nil
		}

		return fmt.Errorf("RefundOrder.waitForTransactionMined: %w", err)
	}

	txHash := result["transactionHash"].(string)
	blockNumber, err := strconv.ParseInt(result["confirmedAtBlockNumber"].(string), 10, 64)
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.parseBlockNumber: %w", orderIDPrefix, err)
	}

	// Update lock order with tx hash and block number
	_, err = lockOrder.Update().
		SetTxHash(txHash).
		SetBlockNumber(blockNumber).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.updateTxHash: %w", orderIDPrefix, err)
	}

	return nil
}

// SettleOrder settles a payment order on-chain.
func (s *OrderEVM) SettleOrder(ctx context.Context, orderID uuid.UUID) error {
	var err error

	orderIDPrefix := strings.Split(orderID.String(), "-")[0]

	// Fetch payment order from db
	order, err := db.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.IDEQ(orderID),
			lockpaymentorder.StatusEQ(lockpaymentorder.StatusValidated),
			lockpaymentorder.HasFulfillmentsWith(
				lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusSuccess),
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

	queueId, err := s.engineService.SendTransactionBatch(ctx, order.Edges.Token.Edges.Network.ChainID, cryptoConf.AggregatorSmartAccount, []map[string]interface{}{txPayload})
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.sendTransaction: %w", orderIDPrefix, err)
	}

	// Wait for settleOrder tx to be mined
	result, err := s.engineService.WaitForTransactionMined(ctx, queueId, 5*time.Minute)
	if err != nil {
		if strings.Contains(err.Error(), "OrderSettled") {
			_, err = order.Update().
				SetStatus(lockpaymentorder.StatusSettled).
				Save(ctx)
		}
		return fmt.Errorf("SettleOrder.waitForTransactionMined: %w", err)
	}

	txHash := result["transactionHash"].(string)
	blockNumber, err := strconv.ParseInt(result["confirmedAtBlockNumber"].(string), 10, 64)
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.parseBlockNumber: %w", orderIDPrefix, err)
	}

	// Update lock order with tx hash and block number
	_, err = order.Update().
		SetTxHash(txHash).
		SetBlockNumber(blockNumber).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.updateTxHash: %w", orderIDPrefix, err)
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

// transferCallData creates the data for the ERC20 token transfer method
func (s *OrderEVM) transferCallData(recipient ethcommon.Address, amount *big.Int) ([]byte, error) {
	// Create ABI
	erc20ABI, err := abi.JSON(strings.NewReader(contracts.ERC20TokenMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse erc20 ABI: %w", err)
	}

	// Create calldata
	calldata, err := erc20ABI.Pack("transfer", recipient, amount)
	if err != nil {
		return nil, fmt.Errorf("failed to pack transfer ABI: %w", err)
	}

	return calldata, nil
}

// createOrderCallData creates the data for the createOrder method
func (s *OrderEVM) createOrderCallData(order *ent.PaymentOrder, encryptedOrderRecipient string) ([]byte, error) {
	amountWithProtocolFee := order.Amount.Add(order.ProtocolFee)

	// Define params
	params := &types.CreateOrderParams{
		Token:              ethcommon.HexToAddress(order.Edges.Token.ContractAddress),
		Amount:             utils.ToSubunit(amountWithProtocolFee, order.Edges.Token.Decimals),
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
func (s *OrderEVM) settleCallData(ctx context.Context, order *ent.LockPaymentOrder) ([]byte, error) {
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

// executeBatchRefundCallData creates the refund calldata for the execute batch method in the smart account.
func (s *OrderEVM) executeBatchRefundCallData(order *ent.LockPaymentOrder) ([]byte, error) {
	var err error
	var client types.RPCClient

	// Connect to RPC endpoint
	retryErr := utils.Retry(3, 1*time.Second, func() error {
		client, err = types.NewEthClient(order.Edges.Token.Edges.Network.RPCEndpoint)
		return err
	})
	if retryErr != nil {
		return nil, retryErr
	}

	// Fetch onchain order details
	instance, err := contracts.NewGateway(ethcommon.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress), client.(bind.ContractBackend))
	if err != nil {
		return nil, err
	}

	orderID, err := hex.DecodeString(order.GatewayID[2:])
	if err != nil {
		return nil, err
	}

	orderInfo, err := instance.GetOrderInfo(nil, utils.StringToByte32(string(orderID)))
	if err != nil {
		return nil, err
	}

	// Create approve data for gateway contract
	approveGatewayData, err := s.approveCallData(
		ethcommon.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
		orderInfo.Amount,
	)
	if err != nil {
		return nil, fmt.Errorf("executeBatchRefundCallData.approveOrderContract: %w", err)
	}

	// Create refund data
	fee := utils.ToSubunit(decimal.NewFromInt(0), order.Edges.Token.Decimals)
	refundData, err := s.refundCallData(fee, order.GatewayID)
	if err != nil {
		return nil, fmt.Errorf("executeBatchRefundCallData.refundData: %w", err)
	}

	simpleAccountABI, err := abi.JSON(strings.NewReader(contracts.SimpleAccountMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("executeBatchRefundCallData.simpleAccountABI: %w", err)
	}

	contractAddresses := []ethcommon.Address{
		ethcommon.HexToAddress(order.Edges.Token.ContractAddress),
		ethcommon.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
	}

	data := [][]byte{approveGatewayData, refundData}

	executeBatchRefundCallData, err := simpleAccountABI.Pack(
		"executeBatch",
		contractAddresses,
		data,
	)
	if err != nil {
		return nil, fmt.Errorf("executeBatchRefundCallData: %w", err)
	}

	return executeBatchRefundCallData, nil
}

// executeBatchSettleCallData creates the settle calldata for the execute batch method in the smart account.
func (s *OrderEVM) executeBatchSettleCallData(ctx context.Context, order *ent.LockPaymentOrder) ([]byte, error) {
	// Create approve data for gateway contract
	approveGatewayData, err := s.approveCallData(
		ethcommon.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
		utils.ToSubunit(order.Amount, order.Edges.Token.Decimals),
	)
	if err != nil {
		return nil, fmt.Errorf("approveOrderContract: %w", err)
	}

	contractAddresses := []ethcommon.Address{
		ethcommon.HexToAddress(order.Edges.Token.ContractAddress),
	}

	data := [][]byte{approveGatewayData}

	// Create settle data
	settleData, err := s.settleCallData(ctx, order)
	if err != nil {
		return nil, fmt.Errorf("settleData: %w", err)
	}

	simpleAccountABI, err := abi.JSON(strings.NewReader(contracts.SimpleAccountMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("simpleAccountABI: %w", err)
	}

	contractAddresses = append(
		contractAddresses,
		ethcommon.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
	)
	data = append(data, settleData)

	executeBatchSettleCallData, err := simpleAccountABI.Pack(
		"executeBatch",
		contractAddresses,
		data,
	)
	if err != nil {
		return nil, fmt.Errorf("executeBatchSettledCallData: %w", err)
	}

	return executeBatchSettleCallData, nil
}

// executeBatchTransferCallData creates the transfer calldata for the execute batch method in the smart account.
func (s *OrderEVM) executeBatchTransferCallData(order *ent.PaymentOrder, to ethcommon.Address, amount *big.Int) ([]byte, error) {
	// Fetch paymaster account
	paymasterAccount, err := utils.GetPaymasterAccount(order.Edges.Token.Edges.Network.ChainID)
	if err != nil {
		return nil, fmt.Errorf("failed to get paymaster account: %w", err)
	}

	if serverConf.Environment != "staging" && serverConf.Environment != "production" {
		time.Sleep(5 * time.Second)
	}

	// Create approve data for paymaster contract
	approvePaymasterData, err := s.approveCallData(
		ethcommon.HexToAddress(paymasterAccount),
		big.NewInt(0).Add(amount, order.Edges.Token.Edges.Network.Fee.BigInt()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create paymaster approve calldata : %w", err)
	}

	// Create transfer data
	transferData, err := s.transferCallData(to, amount)
	if err != nil {
		return nil, fmt.Errorf("failed to create transfer calldata: %w", err)
	}

	simpleAccountABI, err := abi.JSON(strings.NewReader(contracts.SimpleAccountMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse smart account ABI: %w", err)
	}

	executeBatchCallData, err := simpleAccountABI.Pack(
		"executeBatch",
		[]ethcommon.Address{
			ethcommon.HexToAddress(order.Edges.Token.ContractAddress),
			ethcommon.HexToAddress(order.Edges.Token.ContractAddress),
		},
		[][]byte{approvePaymasterData, transferData},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack execute ABI: %w", err)
	}

	return executeBatchCallData, nil
}

// executeBatchCreateOrderCallData creates the calldata for the execute batch method in the smart account.
func (s *OrderEVM) executeBatchCreateOrderCallData(order *ent.PaymentOrder) ([]byte, error) {
	orderAmountWithFees := order.Amount.Add(order.ProtocolFee).Add(order.SenderFee)

	// Create approve data for gateway contract
	approveGatewayData, err := s.approveCallData(
		ethcommon.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
		utils.ToSubunit(orderAmountWithFees.Mul(decimal.NewFromInt(2)), order.Edges.Token.Decimals),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gateway approve calldata: %w", err)
	}

	// Create createOrder data
	encryptedOrderRecipient, err := cryptoUtils.EncryptOrderRecipient(order.Edges.Recipient)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt order recipient: %w", err)
	}

	createOrderData, err := s.createOrderCallData(order, encryptedOrderRecipient)
	if err != nil {
		return nil, fmt.Errorf("failed to create createOrder calldata: %w", err)
	}

	// Initialize calls array with gateway approve and create order
	addresses := []ethcommon.Address{
		ethcommon.HexToAddress(order.Edges.Token.ContractAddress),
		ethcommon.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
	}
	calls := [][]byte{approveGatewayData, createOrderData}

	simpleAccountABI, err := abi.JSON(strings.NewReader(contracts.SimpleAccountMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse smart account ABI: %w", err)
	}

	executeBatchCreateOrderCallData, err := simpleAccountABI.Pack(
		"executeBatch",
		addresses,
		calls,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack execute ABI: %w", err)
	}

	return executeBatchCreateOrderCallData, nil
}
