package order

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
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
	orderTypes "github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
)

// OrderEVM provides functionality related to onchain interactions for payment orders
type OrderEVM struct {
	priorityQueue *services.PriorityQueueService
	nonceManager  *utils.NonceManager
}

// NewOrderEVM creates a new instance of OrderEVM.
func NewOrderEVM() orderTypes.OrderService {
	return &OrderEVM{
		priorityQueue: services.NewPriorityQueueService(),
		nonceManager:  utils.DefaultNonceManager,
	}
}

var (
	serverConf = config.ServerConfig()
	cryptoConf = config.CryptoConfig()
)

// CreateOrder creates a new payment order on-chain via EIP-7702 keeper-sponsored transaction.
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
		WithSenderProfile(func(sq *ent.SenderProfileQuery) {
			sq.WithAPIKey()
		}).
		Only(ctx)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.fetchOrder: %w", orderIDPrefix, err)
	}

	if order.ReceiveAddress == "" {
		return fmt.Errorf("%s - CreateOrder.missingReceiveAddress: payment order has no receive address", orderIDPrefix)
	}

	if order.MessageHash != "" {
		return nil
	}

	// Create createOrder data
	if order.Metadata == nil {
		order.Metadata = map[string]interface{}{}
	}
	if order.Edges.SenderProfile == nil || order.Edges.SenderProfile.Edges.APIKey == nil {
		return fmt.Errorf("%s - CreateOrder.missingAPIKey: sender profile API key not found", orderIDPrefix)
	}
	order.Metadata["apiKey"] = order.Edges.SenderProfile.Edges.APIKey.ID.String()
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

	// Decrypt the receive address private key from salt
	saltDecrypted, err := cryptoUtils.DecryptPlain(order.ReceiveAddressSalt)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.decryptSalt: %w", orderIDPrefix, err)
	}
	userKey, err := crypto.HexToECDSA(string(saltDecrypted))
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.parseKey: %w", orderIDPrefix, err)
	}
	userAddr := crypto.PubkeyToAddress(userKey.PublicKey)

	// Connect to RPC
	network := order.Edges.Token.Edges.Network
	client, err := ethclient.Dial(network.RPCEndpoint)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.dialRPC: %w", orderIDPrefix, err)
	}
	defer client.Close()

	chainID := big.NewInt(network.ChainID)
	delegationContract := ethcommon.HexToAddress(network.DelegationContractAddress)

	// This account is a controlled address so delegation will not be set at this point
	// Check delegation status
	// alreadyDelegated, err := utils.CheckDelegation(client, userAddr, delegationContract)
	// if err != nil {
	// 	return fmt.Errorf("%s - CreateOrder.checkDelegation: %w", orderIDPrefix, err)
	// }

	// Sign 7702 authorization
	// This is a fresh wallet so nonce can be 0 instead of making another client call
	auth, err := utils.SignAuthorization7702(userKey, chainID, delegationContract, 0)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.signAuth: %w", orderIDPrefix, err)
	}
	authList := []types.SetCodeAuthorization{auth}

	// Build batch calls: approve + createOrder
	gatewayAddr := ethcommon.HexToAddress(network.GatewayContractAddress)
	orderAmount := utils.ToSubunit(order.Amount.Add(order.SenderFee), order.Edges.Token.Decimals)
	tokenAddr := ethcommon.HexToAddress(order.Edges.Token.ContractAddress)

	approveData, err := s.approveCallData(gatewayAddr, orderAmount)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.approveCallData: %w", orderIDPrefix, err)
	}

	createOrderData, err := s.createOrderCallData(order, encryptedOrderRecipient)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.createOrderCallData: %w", orderIDPrefix, err)
	}

	calls := []utils.Call7702{
		{To: tokenAddr, Value: big.NewInt(0), Data: approveData},
		{To: gatewayAddr, Value: big.NewInt(0), Data: createOrderData},
	}

	// Fresh wallet — batch nonce is always 0
	var batchNonce uint64

	batchSig, err := utils.SignBatch7702(userKey, userAddr, batchNonce, calls)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.signBatch: %w", orderIDPrefix, err)
	}

	batchData, err := utils.PackExecute(calls, batchSig)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.packExecute: %w", orderIDPrefix, err)
	}

	// Send via aggregator key with automatic nonce management
	aggregatorKey, err := crypto.HexToECDSA(cryptoConf.AggregatorEVMPrivateKey)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.parseAggregatorKey: %w", orderIDPrefix, err)
	}
	aggregatorAddr := crypto.PubkeyToAddress(aggregatorKey.PublicKey)

	var receipt *types.Receipt
	err = s.nonceManager.SubmitWithNonce(ctx, client, network.ChainID, aggregatorAddr, func(nonce uint64) error {
		var txErr error
		receipt, txErr = utils.SendKeeperTx(ctx, client, aggregatorKey, nonce, userAddr, batchData, authList, chainID)
		if txErr != nil {
			return fmt.Errorf("%s - CreateOrder.sendTx: %w", orderIDPrefix, txErr)
		}
		if receipt.Status == 0 {
			return fmt.Errorf("%s - CreateOrder: tx reverted in block %s", orderIDPrefix, receipt.BlockNumber.String())
		}
		return nil
	})
	if err != nil {
		return err
	}

	_, err = order.Update().
		SetStatus(paymentorder.StatusDeposited).
		SetTxHash(receipt.TxHash.Hex()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.updateStatus: %w", orderIDPrefix, err)
	}

	return nil
}

// RefundOrder refunds sender on canceled lock order
func (s *OrderEVM) RefundOrder(ctx context.Context, network *ent.Network, orderID string) error {
	orderIDPrefix := strings.Split(orderID, "-")[0]

	lockOrder, err := db.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.GatewayIDEQ(orderID),
			paymentorder.StatusNEQ(paymentorder.StatusValidated),
			paymentorder.StatusNEQ(paymentorder.StatusRefunded),
			paymentorder.StatusNEQ(paymentorder.StatusSettled),
			paymentorder.StatusNEQ(paymentorder.StatusFulfilling),
			paymentorder.StatusNEQ(paymentorder.StatusSettling),
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

	fee := utils.ToSubunit(decimal.NewFromInt(0), lockOrder.Edges.Token.Decimals)
	refundOrderData, err := s.refundCallData(fee, lockOrder.GatewayID)
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.refundCallData: %w", orderIDPrefix, err)
	}

	aggregatorKey, err := crypto.HexToECDSA(cryptoConf.AggregatorEVMPrivateKey)
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.parseAggregatorKey: %w", orderIDPrefix, err)
	}
	aggregatorAddr := crypto.PubkeyToAddress(aggregatorKey.PublicKey)

	client, err := ethclient.Dial(lockOrder.Edges.Token.Edges.Network.RPCEndpoint)
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.dialRPC: %w", orderIDPrefix, err)
	}
	defer client.Close()

	gatewayAddr := ethcommon.HexToAddress(lockOrder.Edges.Token.Edges.Network.GatewayContractAddress)
	chainID := big.NewInt(lockOrder.Edges.Token.Edges.Network.ChainID)

	var receipt *types.Receipt
	err = s.nonceManager.SubmitWithNonce(ctx, client, lockOrder.Edges.Token.Edges.Network.ChainID, aggregatorAddr, func(nonce uint64) error {
		var txErr error
		receipt, txErr = utils.SendKeeperTx(ctx, client, aggregatorKey, nonce, gatewayAddr, refundOrderData, nil, chainID)
		if txErr != nil {
			return fmt.Errorf("%s - RefundOrder.sendTx: %w", orderIDPrefix, txErr)
		}
		if receipt.Status == 0 {
			return fmt.Errorf("%s - RefundOrder: tx reverted in block %s", orderIDPrefix, receipt.BlockNumber.String())
		}
		return nil
	})
	if err != nil {
		return err
	}

	// TODO: revisit — call IndexGateway with tx hash instead of setting it directly
	_, err = db.Client.PaymentOrder.
		UpdateOneID(lockOrder.ID).
		SetStatus(paymentorder.StatusRefunding).
		SetTxHash(receipt.TxHash.Hex()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.updateStatus: %w", orderIDPrefix, err)
	}

	return nil
}

// SettleOrder settles a payment order on-chain.
func (s *OrderEVM) SettleOrder(ctx context.Context, orderID uuid.UUID) error {
	orderIDPrefix := strings.Split(orderID.String(), "-")[0]

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

	settleOrderData, err := s.settleCallData(ctx, order)
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.settleCallData: %w", orderIDPrefix, err)
	}

	aggregatorKey, err := crypto.HexToECDSA(cryptoConf.AggregatorEVMPrivateKey)
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.parseAggregatorKey: %w", orderIDPrefix, err)
	}
	aggregatorAddr := crypto.PubkeyToAddress(aggregatorKey.PublicKey)

	client, err := ethclient.Dial(order.Edges.Token.Edges.Network.RPCEndpoint)
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.dialRPC: %w", orderIDPrefix, err)
	}
	defer client.Close()

	gatewayAddr := ethcommon.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress)
	chainID := big.NewInt(order.Edges.Token.Edges.Network.ChainID)

	var receipt *types.Receipt
	err = s.nonceManager.SubmitWithNonce(ctx, client, order.Edges.Token.Edges.Network.ChainID, aggregatorAddr, func(nonce uint64) error {
		var txErr error
		receipt, txErr = utils.SendKeeperTx(ctx, client, aggregatorKey, nonce, gatewayAddr, settleOrderData, nil, chainID)
		if txErr != nil {
			return fmt.Errorf("%s - SettleOrder.sendTx: %w", orderIDPrefix, txErr)
		}
		if receipt.Status == 0 {
			return fmt.Errorf("%s - SettleOrder: tx reverted in block %s", orderIDPrefix, receipt.BlockNumber.String())
		}
		return nil
	})
	if err != nil {
		return err
	}

	// TODO: revisit — call IndexGateway with tx hash instead of setting it directly
	_, err = db.Client.PaymentOrder.
		UpdateOneID(order.ID).
		SetStatus(paymentorder.StatusSettling).
		SetTxHash(receipt.TxHash.Hex()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.updateStatus: %w", orderIDPrefix, err)
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
	params := &orderTypes.CreateOrderParams{
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
			providerordertoken.SettlementAddressNEQ(""),
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
		ethcommon.HexToAddress(token.SettlementAddress),
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
