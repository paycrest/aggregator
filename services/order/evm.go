package order

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/services/contracts"
	db "github.com/paycrest/aggregator/storage"
	"github.com/shopspring/decimal"

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

// OrderEVM provides functionality related to on-chain interactions for payment orders
type OrderEVM struct{}

// NewOrderEVM creates a new instance of OrderEVM.
func NewOrderEVM() types.OrderService {
	return &OrderEVM{}
}

var serverConf = config.ServerConfig()
var cryptoConf = config.CryptoConfig()

// CreateOrder creates a new payment order on-chain.
func (s *OrderEVM) CreateOrder(ctx context.Context, client types.RPCClient, orderID uuid.UUID) error {
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

	var salt []byte
	var address string
	if order.Edges.ReceiveAddress != nil {
		salt = order.Edges.ReceiveAddress.Salt
		address = order.Edges.ReceiveAddress.Address
	} else if order.Edges.LinkedAddress != nil {
		salt = order.Edges.LinkedAddress.Salt
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

	saltDecrypted, err := cryptoUtils.DecryptPlain(salt)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.DecryptPlain: %w", orderIDPrefix, err)
	}

	// Initialize user operation with defaults
	userOperation, err := utils.InitializeUserOperation(
		ctx, nil, order.Edges.Token.Edges.Network.RPCEndpoint, address, string(saltDecrypted),
	)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.InitializeUserOperation: %w", orderIDPrefix, err)
	}

	// Create calldata
	calldata, err := s.executeBatchCreateOrderCallData(order)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.executeBatchCreateOrderCallData: %w", orderIDPrefix, err)
	}
	userOperation.CallData = calldata

	// Sponsor user operation.
	// This will populate the following fields in userOperation: PaymasterAndData, PreVerificationGas, VerificationGasLimit, CallGasLimit
	if serverConf.Environment != "production" {
		err = utils.SponsorUserOperation(userOperation, "erc20", order.Edges.Token.ContractAddress, order.Edges.Token.Edges.Network.ChainID)
	} else {
		err = utils.SponsorUserOperation(userOperation, "sponsored", "", order.Edges.Token.Edges.Network.ChainID)
	}
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.SponsorUserOperation: %w", orderIDPrefix, err)
	}

	// Sign user operation
	err = utils.SignUserOperation(userOperation, order.Edges.Token.Edges.Network.ChainID)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.SignUserOperation: %w", orderIDPrefix, err)
	}

	// Send user operation
	txHash, gatewayOrderId, blockNumber, err := utils.SendUserOperation(userOperation, order.Edges.Token.Edges.Network.ChainID)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.SendUserOperation: %w", orderIDPrefix, err)
	}

	// Update payment order with txHash
	_, err = order.Update().
		SetTxHash(txHash).
		SetBlockNumber(blockNumber).
		SetGatewayID(gatewayOrderId).
		SetRate(order.Rate).
		SetStatus(paymentorder.StatusPending).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.updateTxHash: %w", orderIDPrefix, err)
	}

	// Refetch payment order
	paymentOrder, err := db.Client.PaymentOrder.
		Query().
		Where(paymentorder.IDEQ(orderID)).
		WithSenderProfile().
		Only(ctx)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.refetchOrder: %w", orderIDPrefix, err)
	}

	// Send webhook notifcation to sender
	err = utils.SendPaymentOrderWebhook(ctx, paymentOrder)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.webhook: %w", orderIDPrefix, err)
	}

	return nil
}

// RefundOrder refunds sender on canceled lock order
func (s *OrderEVM) RefundOrder(ctx context.Context, client types.RPCClient, network *ent.Network, orderID string) error {
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

	// Get default userOperation
	userOperation, err := utils.InitializeUserOperation(
		ctx, nil, lockOrder.Edges.Token.Edges.Network.RPCEndpoint, cryptoConf.AggregatorSmartAccount, cryptoConf.AggregatorSmartAccountSalt,
	)
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.initializeUserOperation: %w", orderIDPrefix, err)
	}

	// Create calldata
	calldata, err := s.executeBatchRefundCallData(lockOrder)
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.executeBatchRefundCallData: %w", orderIDPrefix, err)
	}
	userOperation.CallData = calldata

	// Sponsor user operation.
	// This will populate the following fields in userOperation: PaymasterAndData, PreVerificationGas, VerificationGasLimit, CallGasLimit
	if serverConf.Environment != "production" {
		err = utils.SponsorUserOperation(userOperation, "erc20", lockOrder.Edges.Token.ContractAddress, lockOrder.Edges.Token.Edges.Network.ChainID)
	} else {
		err = utils.SponsorUserOperation(userOperation, "sponsored", "", lockOrder.Edges.Token.Edges.Network.ChainID)
	}
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.sponsorUserOperation: %w", orderIDPrefix, err)
	}

	// Sign user operation
	_ = utils.SignUserOperation(userOperation, lockOrder.Edges.Token.Edges.Network.ChainID)

	// Send user operation
	txHash, _, blockNumber, err := utils.SendUserOperation(userOperation, lockOrder.Edges.Token.Edges.Network.ChainID)
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.sendUserOperation: %w", orderIDPrefix, err)
	}

	// Update status of all lock orders with same order_id
	_, err = db.Client.LockPaymentOrder.
		Update().
		Where(lockpaymentorder.GatewayIDEQ(lockOrder.GatewayID)).
		SetTxHash(txHash).
		SetBlockNumber(blockNumber).
		SetStatus(lockpaymentorder.StatusRefunded).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.updateTxHash(%v): %w", orderIDPrefix, txHash, err)
	}

	return nil
}

// SettleOrder settles a payment order on-chain.
func (s *OrderEVM) SettleOrder(ctx context.Context, client types.RPCClient, orderID uuid.UUID) error {
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

	// Get default userOperation
	userOperation, err := utils.InitializeUserOperation(
		ctx, nil, order.Edges.Token.Edges.Network.RPCEndpoint, cryptoConf.AggregatorSmartAccount, cryptoConf.AggregatorSmartAccountSalt,
	)
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.initializeUserOperation: %w", orderIDPrefix, err)
	}

	// Create calldata
	calldata, err := s.executeBatchSettleCallData(ctx, order)
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.executeBatchSettleCallData: %w", orderIDPrefix, err)
	}
	userOperation.CallData = calldata

	// Sponsor user operation.
	// This will populate the following fields in userOperation: PaymasterAndData, PreVerificationGas, VerificationGasLimit, CallGasLimit
	if serverConf.Environment != "production" {
		err = utils.SponsorUserOperation(userOperation, "erc20", order.Edges.Token.ContractAddress, order.Edges.Token.Edges.Network.ChainID)
	} else {
		err = utils.SponsorUserOperation(userOperation, "sponsored", "", order.Edges.Token.Edges.Network.ChainID)
	}
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.sponsorUserOperation: %w", orderIDPrefix, err)
	}

	// Sign user operation
	_ = utils.SignUserOperation(userOperation, order.Edges.Token.Edges.Network.ChainID)

	// Send user operation
	txHash, _, blockNumber, err := utils.SendUserOperation(userOperation, order.Edges.Token.Edges.Network.ChainID)
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.sendUserOperation: %w", orderIDPrefix, err)
	}

	// Update status of lock order
	_, err = order.Update().
		SetTxHash(txHash).
		SetBlockNumber(blockNumber).
		SetStatus(lockpaymentorder.StatusSettled).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.updateTxHash: %w", orderIDPrefix, err)
	}

	return nil
}

// executeBatchTransferCallData creates the transfer calldata for the execute batch method in the smart account.
func (s *OrderEVM) executeBatchTransferCallData(order *ent.PaymentOrder, to common.Address, amount *big.Int) ([]byte, error) {
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
		common.HexToAddress(paymasterAccount),
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
		[]common.Address{
			common.HexToAddress(order.Edges.Token.ContractAddress),
			common.HexToAddress(order.Edges.Token.ContractAddress),
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
		common.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
		utils.ToSubunit(orderAmountWithFees.Mul(decimal.NewFromInt(2)), order.Edges.Token.Decimals),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gateway approve calldata: %w", err)
	}

	// Fetch paymaster account
	paymasterAccount, err := utils.GetPaymasterAccount(order.Edges.Token.Edges.Network.ChainID)
	if err != nil {
		return nil, fmt.Errorf("failed to get paymaster account: %w", err)
	}

	if serverConf.Environment != "production" {
		time.Sleep(5 * time.Second)
	}

	// Create approve data for paymaster contract
	approvePaymasterData, err := s.approveCallData(
		common.HexToAddress(paymasterAccount),
		utils.ToSubunit(orderAmountWithFees.Add(order.Edges.Token.Edges.Network.Fee), order.Edges.Token.Decimals),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create paymaster approve calldata : %w", err)
	}

	// Create createOrder data
	createOrderData, err := s.createOrderCallData(order)
	if err != nil {
		return nil, fmt.Errorf("failed to create createOrder calldata: %w", err)
	}

	simpleAccountABI, err := abi.JSON(strings.NewReader(contracts.SimpleAccountMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse smart account ABI: %w", err)
	}

	executeBatchCreateOrderCallData, err := simpleAccountABI.Pack(
		"executeBatch",
		[]common.Address{
			common.HexToAddress(order.Edges.Token.ContractAddress),
			common.HexToAddress(order.Edges.Token.ContractAddress),
			common.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
		},
		[][]byte{approvePaymasterData, approveGatewayData, createOrderData},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack execute ABI: %w", err)
	}

	return executeBatchCreateOrderCallData, nil
}

// approveCallData creates the data for the ERC20 approve method
func (s *OrderEVM) approveCallData(spender common.Address, amount *big.Int) ([]byte, error) {
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
func (s *OrderEVM) transferCallData(recipient common.Address, amount *big.Int) ([]byte, error) {
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

// // executeCallData creates the data for the execute method in the smart account.
// func (s *OrderEVM) executeCallData(dest common.Address, value *big.Int, data []byte) ([]byte, error) {
// 	simpleAccountABI, err := abi.JSON(strings.NewReader(contracts.SimpleAccountMetaData.ABI))
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse smart account ABI: %w", err)
// 	}

// 	executeCallData, err := simpleAccountABI.Pack(
// 		"execute",
// 		dest,
// 		value,
// 		data,
// 	)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to pack execute ABI: %w", err)
// 	}

// 	return executeCallData, nil
// }

// createOrderCallData creates the data for the createOrder method
func (s *OrderEVM) createOrderCallData(order *ent.PaymentOrder) ([]byte, error) {
	// Encrypt recipient details
	encryptedOrderRecipient, err := s.encryptOrderRecipient(order.Edges.Recipient)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt recipient details: %w", err)
	}

	amountWithProtocolFee := order.Amount.Add(order.ProtocolFee)

	// Define params
	params := &types.CreateOrderParams{
		Token:              common.HexToAddress(order.Edges.Token.ContractAddress),
		Amount:             utils.ToSubunit(amountWithProtocolFee, order.Edges.Token.Decimals),
		Rate:               order.Rate.Mul(decimal.NewFromInt(100)).BigInt(),
		SenderFeeRecipient: common.HexToAddress(order.FeeAddress),
		SenderFee:          utils.ToSubunit(order.SenderFee, order.Edges.Token.Decimals),
		RefundAddress:      common.HexToAddress(order.ReturnAddress),
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
	instance, err := contracts.NewGateway(common.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress), client.(bind.ContractBackend))
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
		common.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
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

	contractAddresses := []common.Address{
		common.HexToAddress(order.Edges.Token.ContractAddress),
		common.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
	}

	data := [][]byte{approveGatewayData, refundData}

	if serverConf.Environment != "production" {
		paymasterAccount, err := utils.GetPaymasterAccount(order.Edges.Token.Edges.Network.ChainID)
		if err != nil {
			return nil, fmt.Errorf("failed to get paymaster account: %w", err)
		}
		time.Sleep(5 * time.Second)

		refundAmount := utils.FromSubunit(orderInfo.Amount, order.Edges.Token.Decimals).Add(order.Edges.Token.Edges.Network.Fee)

		// Create approve data for paymaster contract
		approvePaymasterData, err := s.approveCallData(
			common.HexToAddress(paymasterAccount),
			utils.ToSubunit(refundAmount, order.Edges.Token.Decimals),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create paymaster approve calldata : %w", err)
		}

		contractAddresses = append(
			[]common.Address{common.HexToAddress(order.Edges.Token.ContractAddress)},
			contractAddresses...,
		)
		data = append(
			[][]byte{approvePaymasterData},
			data...,
		)
	}

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

// executeBatchSettleCallData creates the settle calldata for the execute batch method in the smart account.
func (s *OrderEVM) executeBatchSettleCallData(ctx context.Context, order *ent.LockPaymentOrder) ([]byte, error) {
	// Create approve data for gateway contract
	approveGatewayData, err := s.approveCallData(
		common.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
		utils.ToSubunit(order.Amount, order.Edges.Token.Decimals),
	)
	if err != nil {
		return nil, fmt.Errorf("approveOrderContract: %w", err)
	}

	contractAddresses := []common.Address{
		common.HexToAddress(order.Edges.Token.ContractAddress),
	}

	data := [][]byte{approveGatewayData}

	if serverConf.Environment != "production" {
		// Fetch paymaster account
		paymasterAccount, err := utils.GetPaymasterAccount(order.Edges.Token.Edges.Network.ChainID)
		if err != nil {
			return nil, fmt.Errorf("failed to get paymaster account: %w", err)
		}
		time.Sleep(5 * time.Second)

		// Create approve data for paymaster contract
		approvePaymasterData, err := s.approveCallData(
			common.HexToAddress(paymasterAccount),
			utils.ToSubunit(order.Amount.Add(order.Edges.Token.Edges.Network.Fee), order.Edges.Token.Decimals),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create paymaster approve calldata : %w", err)
		}

		contractAddresses = append(
			contractAddresses,
			common.HexToAddress(order.Edges.Token.ContractAddress),
		)
		data = append(data, approvePaymasterData)
	}

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
		common.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
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

// settleCallData creates the data for the settle method in the gateway contract
func (s *OrderEVM) settleCallData(ctx context.Context, order *ent.LockPaymentOrder) ([]byte, error) {
	gatewayABI, err := abi.JSON(strings.NewReader(contracts.GatewayMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse GatewayOrder ABI: %w", err)
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
		common.HexToAddress(token.Address),
		uint64(orderPercent),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack settle ABI: %w", err)
	}

	return data, nil
}

// encryptOrderRecipient encrypts the recipient details
func (s *OrderEVM) encryptOrderRecipient(recipient *ent.PaymentOrderRecipient) (string, error) {
	// Generate a cryptographically secure random nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	message := struct {
		Nonce             string
		AccountIdentifier string
		AccountName       string
		Institution       string
		ProviderID        string
		Memo              string
	}{
		base64.StdEncoding.EncodeToString(nonce), recipient.AccountIdentifier, recipient.AccountName, recipient.Institution, recipient.ProviderID, recipient.Memo,
	}

	// Encrypt with the public key of the aggregator
	messageCipher, err := cryptoUtils.PublicKeyEncryptJSON(message, cryptoConf.AggregatorPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt message: %w", err)
	}

	return base64.StdEncoding.EncodeToString(messageCipher), nil
}
