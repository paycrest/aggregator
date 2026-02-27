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
	engineService *services.EngineService
	nonceManager  *utils.NonceManager
}

// NewOrderEVM creates a new instance of OrderEVM.
func NewOrderEVM() orderTypes.OrderService {
	return &OrderEVM{
		priorityQueue: services.NewPriorityQueueService(),
		engineService: services.NewEngineService(),
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

	network := order.Edges.Token.Edges.Network
	gatewayAddr := ethcommon.HexToAddress(network.GatewayContractAddress)
	orderAmount := utils.ToSubunit(order.Amount.Add(order.SenderFee), order.Edges.Token.Decimals)
	tokenAddr := ethcommon.HexToAddress(order.Edges.Token.ContractAddress)

	switch order.WalletType {
	case paymentorder.WalletTypeSmartWallet:
		_, err = s.createOrderForSmartWallet(ctx, orderIDPrefix, order, network, encryptedOrderRecipient, gatewayAddr, orderAmount)
	case paymentorder.WalletTypeEoa7702:
		// @todo will decide how to handle the response later
		_, err = s.createOrderFor7702(ctx, orderIDPrefix, order, network, encryptedOrderRecipient, gatewayAddr, tokenAddr, orderAmount)
	default:
		return fmt.Errorf("%s - CreateOrder: unsupported wallet_type %s", orderIDPrefix, order.WalletType)
	}
	if err != nil {
		return err
	}

	_, err = order.Update().SetStatus(paymentorder.StatusDeposited).Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.updateStatus: %w", orderIDPrefix, err)
	}
	return nil
}

// createOrderForSmartWallet submits approve + createOrder via Thirdweb Engine (fire-and-forget). Returns a result map for future use; no tx hash/block number persisted.
func (s *OrderEVM) createOrderForSmartWallet(ctx context.Context, orderIDPrefix string, order *ent.PaymentOrder, network *ent.Network, encryptedOrderRecipient string, gatewayAddr ethcommon.Address, orderAmount *big.Int) (map[string]interface{}, error) {
	if s.engineService == nil {
		return nil, fmt.Errorf("%s - CreateOrder: engine service required for smart_wallet", orderIDPrefix)
	}
	approveData, err := s.approveCallData(gatewayAddr, orderAmount)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.approveCallData: %w", orderIDPrefix, err)
	}
	createOrderData, err := s.createOrderCallData(order, encryptedOrderRecipient)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.createOrderCallData: %w", orderIDPrefix, err)
	}
	txPayload := []map[string]interface{}{
		{"to": order.Edges.Token.ContractAddress, "data": "0x" + hex.EncodeToString(approveData), "value": "0x0"},
		{"to": network.GatewayContractAddress, "data": "0x" + hex.EncodeToString(createOrderData), "value": "0x0"},
	}
	_, err = s.engineService.SendTransactionBatch(ctx, network.ChainID, order.ReceiveAddress, txPayload)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.sendBatch: %w", orderIDPrefix, err)
	}
	return nil, nil
}

// createOrderFor7702 submits approve + createOrder via EIP-7702 keeper tx; returns result map with transactionHash and blockNumber when present (for future use).
func (s *OrderEVM) createOrderFor7702(ctx context.Context, orderIDPrefix string, order *ent.PaymentOrder, network *ent.Network, encryptedOrderRecipient string, gatewayAddr, tokenAddr ethcommon.Address, orderAmount *big.Int) (map[string]interface{}, error) {
	if len(order.ReceiveAddressSalt) == 0 {
		return nil, fmt.Errorf("%s - CreateOrder: receive address salt is empty", orderIDPrefix)
	}
	saltDecrypted, err := cryptoUtils.DecryptPlain(order.ReceiveAddressSalt)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.decryptSalt: %w", orderIDPrefix, err)
	}
	userKey, err := crypto.HexToECDSA(string(saltDecrypted))
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.parseKey: %w", orderIDPrefix, err)
	}
	userAddr := crypto.PubkeyToAddress(userKey.PublicKey)

	client, err := ethclient.Dial(network.RPCEndpoint)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.dialRPC: %w", orderIDPrefix, err)
	}
	defer client.Close()

	chainID := big.NewInt(network.ChainID)
	delegationContract := ethcommon.HexToAddress(network.DelegationContractAddress)
	alreadyDelegated, err := utils.CheckDelegation(client, userAddr, delegationContract)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.checkDelegation: %w", orderIDPrefix, err)
	}

	var authList []types.SetCodeAuthorization
	if !alreadyDelegated {
		authNonce, err := client.PendingNonceAt(ctx, userAddr)
		if err != nil {
			return nil, fmt.Errorf("%s - CreateOrder.pendingNonce: %w", orderIDPrefix, err)
		}
		auth, err := utils.SignAuthorization7702(userKey, chainID, delegationContract, authNonce)
		if err != nil {
			return nil, fmt.Errorf("%s - CreateOrder.signAuth: %w", orderIDPrefix, err)
		}
		authList = []types.SetCodeAuthorization{auth}
	}

	approveData, err := s.approveCallData(gatewayAddr, orderAmount)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.approveCallData: %w", orderIDPrefix, err)
	}
	createOrderData, err := s.createOrderCallData(order, encryptedOrderRecipient)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.createOrderCallData: %w", orderIDPrefix, err)
	}
	calls := []utils.Call7702{
		{To: tokenAddr, Value: big.NewInt(0), Data: approveData},
		{To: gatewayAddr, Value: big.NewInt(0), Data: createOrderData},
	}

	var batchNonce uint64
	if alreadyDelegated {
		batchNonce, err = utils.ReadBatchNonce(client, userAddr)
		if err != nil {
			return nil, fmt.Errorf("%s - CreateOrder.readBatchNonce: %w", orderIDPrefix, err)
		}
	}
	batchSig, err := utils.SignBatch7702(userKey, userAddr, batchNonce, calls)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.signBatch: %w", orderIDPrefix, err)
	}
	batchData, err := utils.PackExecute(calls, batchSig)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.packExecute: %w", orderIDPrefix, err)
	}

	aggregatorKey, err := crypto.HexToECDSA(cryptoConf.AggregatorEVMPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%s - CreateOrder.parseAggregatorKey: %w", orderIDPrefix, err)
	}
	aggregatorAddr := crypto.PubkeyToAddress(aggregatorKey.PublicKey)

	var receipt *types.Receipt
	err = s.nonceManager.SubmitWithNonce(ctx, client, network.ChainID, aggregatorAddr, func(nonce uint64) error {
		var txErr error
		receipt, txErr = utils.SendKeeperTx(ctx, client, aggregatorKey, nonce, userAddr, batchData, authList, chainID)
		if txErr != nil {
			return fmt.Errorf("%s - CreateOrder.sendTx: %w", orderIDPrefix, txErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if receipt.Status == 0 {
		return nil, fmt.Errorf("%s - CreateOrder: tx reverted in block %s", orderIDPrefix, receipt.BlockNumber.String())
	}
	return map[string]interface{}{
		"transactionHash": receipt.TxHash.Hex(),
		"blockNumber":     receipt.BlockNumber.Int64(),
	}, nil
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

	lockNetwork := lockOrder.Edges.Token.Edges.Network
	switch lockOrder.WalletType {
	case paymentorder.WalletTypeSmartWallet:
		_, err = s.refundOrderForSmartWallet(ctx, orderIDPrefix, lockOrder, lockNetwork, refundOrderData)
	case paymentorder.WalletTypeEoa7702:
		// @todo will decide how to handle the response later
		_, err = s.refundOrderFor7702(ctx, orderIDPrefix, lockOrder, lockNetwork, refundOrderData)
	default:
		return fmt.Errorf("%s - RefundOrder: unsupported wallet_type %s", orderIDPrefix, lockOrder.WalletType)
	}
	if err != nil {
		return err
	}

	_, err = db.Client.PaymentOrder.UpdateOneID(lockOrder.ID).SetStatus(paymentorder.StatusRefunding).Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.updateStatus: %w", orderIDPrefix, err)
	}
	return nil
}

// refundOrderForSmartWallet submits gateway refund via Thirdweb Engine (fire-and-forget). Returns result map for future use.
func (s *OrderEVM) refundOrderForSmartWallet(ctx context.Context, orderIDPrefix string, lockOrder *ent.PaymentOrder, lockNetwork *ent.Network, refundOrderData []byte) (map[string]interface{}, error) {
	if s.engineService == nil {
		return nil, fmt.Errorf("%s - RefundOrder: engine service required for smart_wallet", orderIDPrefix)
	}
	fromAddress := cryptoConf.AggregatorAccountEVM
	if fromAddress == "" {
		return nil, fmt.Errorf("%s - RefundOrder: AGGREGATOR_ACCOUNT_EVM not set", orderIDPrefix)
	}
	txPayload := []map[string]interface{}{
		{"to": lockNetwork.GatewayContractAddress, "data": "0x" + hex.EncodeToString(refundOrderData), "value": "0x0"},
	}
	_, err := s.engineService.SendTransactionBatch(ctx, lockNetwork.ChainID, fromAddress, txPayload)
	if err != nil {
		return nil, fmt.Errorf("%s - RefundOrder.sendBatch: %w", orderIDPrefix, err)
	}
	return nil, nil
}

// refundOrderFor7702 submits gateway refund via keeper tx; returns result map with transactionHash and blockNumber when present (for future use).
func (s *OrderEVM) refundOrderFor7702(ctx context.Context, orderIDPrefix string, lockOrder *ent.PaymentOrder, lockNetwork *ent.Network, refundOrderData []byte) (map[string]interface{}, error) {
	aggregatorKey, err := crypto.HexToECDSA(cryptoConf.AggregatorEVMPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%s - RefundOrder.parseAggregatorKey: %w", orderIDPrefix, err)
	}
	aggregatorAddr := crypto.PubkeyToAddress(aggregatorKey.PublicKey)
	client, err := ethclient.Dial(lockNetwork.RPCEndpoint)
	if err != nil {
		return nil, fmt.Errorf("%s - RefundOrder.dialRPC: %w", orderIDPrefix, err)
	}
	defer client.Close()
	gatewayAddr := ethcommon.HexToAddress(lockNetwork.GatewayContractAddress)
	chainID := big.NewInt(lockNetwork.ChainID)

	var receipt *types.Receipt
	err = s.nonceManager.SubmitWithNonce(ctx, client, lockNetwork.ChainID, aggregatorAddr, func(nonce uint64) error {
		var txErr error
		receipt, txErr = utils.SendKeeperTx(ctx, client, aggregatorKey, nonce, gatewayAddr, refundOrderData, nil, chainID)
		if txErr != nil {
			return fmt.Errorf("%s - RefundOrder.sendTx: %w", orderIDPrefix, txErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if receipt.Status == 0 {
		return nil, fmt.Errorf("%s - RefundOrder: tx reverted in block %s", orderIDPrefix, receipt.BlockNumber.String())
	}
	return map[string]interface{}{
		"transactionHash": receipt.TxHash.Hex(),
		"blockNumber":     receipt.BlockNumber.Int64(),
	}, nil
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

	network := order.Edges.Token.Edges.Network
	switch order.WalletType {
	case paymentorder.WalletTypeSmartWallet:
		_, err = s.settleOrderForSmartWallet(ctx, orderIDPrefix, order, network, settleOrderData)
	case paymentorder.WalletTypeEoa7702:
		// @todo will decide how to handle the response later
		_, err = s.settleOrderFor7702(ctx, orderIDPrefix, order, network, settleOrderData)
	default:
		return fmt.Errorf("%s - SettleOrder: unsupported wallet_type %s", orderIDPrefix, order.WalletType)
	}
	if err != nil {
		return err
	}

	_, err = db.Client.PaymentOrder.UpdateOneID(order.ID).SetStatus(paymentorder.StatusSettling).Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.updateStatus: %w", orderIDPrefix, err)
	}
	return nil
}

// settleOrderForSmartWallet submits gateway settle via Thirdweb Engine (fire-and-forget). Returns result map for future use.
func (s *OrderEVM) settleOrderForSmartWallet(ctx context.Context, orderIDPrefix string, order *ent.PaymentOrder, network *ent.Network, settleOrderData []byte) (map[string]interface{}, error) {
	if s.engineService == nil {
		return nil, fmt.Errorf("%s - SettleOrder: engine service required for smart_wallet", orderIDPrefix)
	}
	fromAddress := cryptoConf.AggregatorAccountEVM
	if fromAddress == "" {
		return nil, fmt.Errorf("%s - SettleOrder: AGGREGATOR_ACCOUNT_EVM not set", orderIDPrefix)
	}
	txPayload := []map[string]interface{}{
		{"to": network.GatewayContractAddress, "data": "0x" + hex.EncodeToString(settleOrderData), "value": "0x0"},
	}
	_, err := s.engineService.SendTransactionBatch(ctx, network.ChainID, fromAddress, txPayload)
	if err != nil {
		return nil, fmt.Errorf("%s - SettleOrder.sendBatch: %w", orderIDPrefix, err)
	}
	return nil, nil
}

// settleOrderFor7702 submits gateway settle via keeper tx; returns result map with transactionHash and blockNumber when present (for future use).
func (s *OrderEVM) settleOrderFor7702(ctx context.Context, orderIDPrefix string, order *ent.PaymentOrder, network *ent.Network, settleOrderData []byte) (map[string]interface{}, error) {
	aggregatorKey, err := crypto.HexToECDSA(cryptoConf.AggregatorEVMPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%s - SettleOrder.parseAggregatorKey: %w", orderIDPrefix, err)
	}
	aggregatorAddr := crypto.PubkeyToAddress(aggregatorKey.PublicKey)
	client, err := ethclient.Dial(network.RPCEndpoint)
	if err != nil {
		return nil, fmt.Errorf("%s - SettleOrder.dialRPC: %w", orderIDPrefix, err)
	}
	defer client.Close()
	chainID := big.NewInt(network.ChainID)
	gatewayAddr := ethcommon.HexToAddress(network.GatewayContractAddress)

	var receipt *types.Receipt
	err = s.nonceManager.SubmitWithNonce(ctx, client, network.ChainID, aggregatorAddr, func(nonce uint64) error {
		var txErr error
		receipt, txErr = utils.SendKeeperTx(ctx, client, aggregatorKey, nonce, gatewayAddr, settleOrderData, nil, chainID)
		if txErr != nil {
			return fmt.Errorf("%s - SettleOrder.sendTx: %w", orderIDPrefix, txErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if receipt.Status == 0 {
		return nil, fmt.Errorf("%s - SettleOrder: tx reverted in block %s", orderIDPrefix, receipt.BlockNumber.String())
	}
	return map[string]interface{}{
		"transactionHash": receipt.TxHash.Hex(),
		"blockNumber":     receipt.BlockNumber.Int64(),
	}, nil
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
