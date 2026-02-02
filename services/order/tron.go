package order

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/services/contracts"
	"github.com/paycrest/tron-wallet/enums"
	"github.com/paycrest/tron-wallet/grpcClient"
	"github.com/paycrest/tron-wallet/grpcClient/proto/api"
	"github.com/paycrest/tron-wallet/grpcClient/proto/core"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/paycrest/aggregator/ent/fiatcurrency"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/paymentorderfulfillment"
	"github.com/paycrest/aggregator/ent/transactionlog"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	tokenent "github.com/paycrest/aggregator/ent/token"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/tron-wallet/util"
	"github.com/shopspring/decimal"

	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	tronWallet "github.com/paycrest/tron-wallet"
)

// OrderTron provides functionality related to on-chain interactions for payment orders
type OrderTron struct{}

// NewOrderTron creates a new instance of OrderTron.
func NewOrderTron() types.OrderService {
	return &OrderTron{}
}

// getNode returns the node to use based on the environment
func (s *OrderTron) getNode() enums.Node {
	if serverConf.Environment == "production" {
		return enums.MAIN_NODE
	} else {
		return enums.SHASTA_NODE
	}
}

// ProcessTransfer processes a transfer event for a given receive address and token.
func (s *OrderTron) ProcessTransfer(ctx context.Context, receiveAddress string, token *ent.Token) error {
	return nil
}

// CreateOrder creates a new payment order on-chain.
func (s *OrderTron) CreateOrder(ctx context.Context, orderID uuid.UUID) error {
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
		return fmt.Errorf("%s - Tron.CreateOrder.fetchOrder: %w", orderIDPrefix, err)
	}

	// Create wallet
	saltDecrypted, err := cryptoUtils.DecryptPlain(order.ReceiveAddressSalt)
	if err != nil {
		return fmt.Errorf("%s - Tron.CreateOrder.DecryptPlain: %w", orderIDPrefix, err)
	}

	wallet, err := tronWallet.CreateTronWallet(s.getNode(), string(saltDecrypted))
	if err != nil {
		return fmt.Errorf("%s - Tron.CreateOrder.CreateTronWallet: %w", orderIDPrefix, err)
	}

	// Transfer TRX from master wallet to receive address for gas
	masterWallet, err := cryptoUtils.GenerateTronAccountFromIndex(0)
	if err != nil {
		return fmt.Errorf("%s - Tron.CreateOrder.GenerateTronAccountFromIndex: %w", orderIDPrefix, err)
	}

	balance, err := wallet.Balance()
	if err != nil {
		balance = 0
	}

	if balance < 160000000 {
		_, err = masterWallet.Transfer(wallet.AddressBase58, 160000000)
		if err != nil {
			return fmt.Errorf("%s - Tron.CreateOrder.Transfer: %w", orderIDPrefix, err)
		}
		time.Sleep(5 * time.Second) // wait for wallet to be pre-funded with gas
	}

	// Normalize addresses
	gatewayContractAddress, err := util.Base58ToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress)
	if err != nil {
		return fmt.Errorf("%s - Tron.CreateOrder.Base58ToAddress: %w", orderIDPrefix, err)
	}

	senderAddress, err := util.Base58ToAddress(wallet.AddressBase58)
	if err != nil {
		return fmt.Errorf("%s - Tron.CreateOrder.Base58ToAddress: %w", orderIDPrefix, err)
	}

	tokenContractAddress, err := util.Base58ToAddress(order.Edges.Token.ContractAddress)
	if err != nil {
		return fmt.Errorf("%s - Tron.CreateOrder.Base58ToAddress: %w", orderIDPrefix, err)
	}

	// Approve gateway contract to spend token
	calldata, err := s.approveCallData(gatewayContractAddress, utils.ToSubunit(order.Amount, order.Edges.Token.Decimals))
	if err != nil {
		return fmt.Errorf("%s - Tron.CreateOrder.approveCallData: %w", orderIDPrefix, err)
	}

	ct := &core.TriggerSmartContract{
		OwnerAddress:    senderAddress.Bytes(),
		ContractAddress: tokenContractAddress.Bytes(),
		Data:            calldata,
	}
	_, err = s.sendTransaction(wallet, ct, 30000000)
	if err != nil {
		return fmt.Errorf("%s - Tron.CreateOrder.sendTransaction: %w", orderIDPrefix, err)
	}

	time.Sleep(5 * time.Second)

	// Create order in gateway contract
	calldata, err = s.createOrderCallData(order)
	if err != nil {
		return fmt.Errorf("%s - Tron.CreateOrder.createOrderCallData: %w", orderIDPrefix, err)
	}

	ct = &core.TriggerSmartContract{
		OwnerAddress:    senderAddress.Bytes(),
		ContractAddress: gatewayContractAddress.Bytes(),
		Data:            calldata,
	}
	txHash, err := s.sendTransaction(wallet, ct, 150000000)
	if err != nil {
		return fmt.Errorf("%s - Tron.CreateOrder.sendTransaction: %w", orderIDPrefix, err)
	}

	// Transfer network fee from receive address to master wallet
	_, err = wallet.TransferTRC20(
		&tronWallet.Token{
			ContractAddress: enums.ContractAddress(order.Edges.Token.ContractAddress),
		},
		masterWallet.AddressBase58,
		utils.ToSubunit(order.NetworkFee, order.Edges.Token.Decimals).Int64(),
		30000000,
	)
	if err != nil {
		return fmt.Errorf("%s - Tron.CreateOrder.TransferTRC20: %w", orderIDPrefix, err)
	}

	// Update payment order
	_, err = order.Update().
		SetBlockNumber(0). // LastIndexedBlock no longer exists, set to 0
		SetTxHash(txHash).
		SetStatus(paymentorder.StatusPending).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - Tron.CreateOrder.updateTxHash: %w", orderIDPrefix, err)
	}

	// Send webhook notifcation to sender
	err = utils.SendPaymentOrderWebhook(ctx, order)
	if err != nil {
		return fmt.Errorf("%s - Tron.CreateOrder.webhook: %w", orderIDPrefix, err)
	}

	return nil
}

// RefundOrder refunds sender on canceled lock order
func (s *OrderTron) RefundOrder(ctx context.Context, network *ent.Network, orderID string) error {
	orderIDPrefix := strings.Split(orderID, "-")[0]

	// Fetch lock order from db
	lockOrder, err := db.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.GatewayIDEQ(orderID),
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
		return fmt.Errorf("Tron.RefundOrder.fetchLockOrder: %w", err)
	}

	// Generate master wallet
	wallet, err := cryptoUtils.GenerateTronAccountFromIndex(0)
	if err != nil {
		return fmt.Errorf("%s - Tron.RefundOrder.GenerateTronAccountFromIndex: %w", orderIDPrefix, err)
	}

	// Normalize addresses
	gatewayContractAddress, err := util.Base58ToAddress(lockOrder.Edges.Token.Edges.Network.GatewayContractAddress)
	if err != nil {
		return fmt.Errorf("%s - Tron.RefundOrder.Base58ToAddress: %w", orderIDPrefix, err)
	}

	senderAddress, err := util.Base58ToAddress(wallet.AddressBase58)
	if err != nil {
		return fmt.Errorf("%s - Tron.RefundOrder.Base58ToAddress: %w", orderIDPrefix, err)
	}

	tokenContractAddress, err := util.Base58ToAddress(lockOrder.Edges.Token.ContractAddress)
	if err != nil {
		return fmt.Errorf("%s - Tron.RefundOrder.Base58ToAddress: %w", orderIDPrefix, err)
	}

	// Fetch onchain order details
	orderInfo, err := s.getOrderInfo(gatewayContractAddress, lockOrder.GatewayID)
	if err != nil {
		return fmt.Errorf("%s - Tron.RefundOrder.GetOrderInfo: %w", orderIDPrefix, err)
	}

	// Approve gateway contract to spend token
	calldata, err := s.approveCallData(
		gatewayContractAddress,
		orderInfo.Amount,
	)
	if err != nil {
		return fmt.Errorf("%s - Tron.RefundOrder.approveCallData: %w", orderIDPrefix, err)
	}

	ct := &core.TriggerSmartContract{
		OwnerAddress:    senderAddress.Bytes(),
		ContractAddress: tokenContractAddress.Bytes(),
		Data:            calldata,
	}
	_, err = s.sendTransaction(wallet, ct, 30000000)
	if err != nil {
		return fmt.Errorf("%s - Tron.RefundOrder.sendTransaction: %w", orderIDPrefix, err)
	}

	time.Sleep(5 * time.Second)

	// Refund order in gateway contract
	fee := utils.ToSubunit(decimal.NewFromInt(0), lockOrder.Edges.Token.Decimals)
	calldata, err = s.refundCallData(fee, lockOrder.GatewayID)
	if err != nil {
		return fmt.Errorf("%s - Tron.RefundOrder.refundCallData: %w", orderIDPrefix, err)
	}

	ct = &core.TriggerSmartContract{
		OwnerAddress:    senderAddress.Bytes(),
		ContractAddress: gatewayContractAddress.Bytes(),
		Data:            calldata,
	}
	txHash, err := s.sendTransaction(wallet, ct, 50000000)
	if err != nil {
		return fmt.Errorf("%s - Tron.RefundOrder.sendTransaction: %w", orderIDPrefix, err)
	}

	// Create order_refunding log (indexer will update to order_refunded when event is indexed)
	tx, err := db.Client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("%s - Tron.RefundOrder.tx: %w", orderIDPrefix, err)
	}
	transactionLog, err := tx.TransactionLog.
		Create().
		SetStatus(transactionlog.StatusOrderRefunding).
		SetGatewayID(lockOrder.GatewayID).
		SetTxHash(txHash).
		SetNetwork(lockOrder.Edges.Token.Edges.Network.Identifier).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("%s - Tron.RefundOrder.createLog: %w", orderIDPrefix, err)
	}
	_, err = tx.PaymentOrder.
		UpdateOneID(lockOrder.ID).
		SetTxHash(txHash).
		SetStatus(paymentorder.StatusRefunding).
		AddTransactions(transactionLog).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("%s - Tron.RefundOrder.updateStatus: %w", orderIDPrefix, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%s - Tron.RefundOrder.commit: %w", orderIDPrefix, err)
	}

	return nil
}

// SettleOrder settles a payment order on-chain.
func (s *OrderTron) SettleOrder(ctx context.Context, orderID uuid.UUID) error {
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
		return fmt.Errorf("%s - Tron.SettleOrder.fetchOrder: %w", orderIDPrefix, err)
	}

	// Generate master wallet
	wallet, err := cryptoUtils.GenerateTronAccountFromIndex(0)
	if err != nil {
		return fmt.Errorf("%s - Tron.SettleOrder.GenerateTronAccountFromIndex: %w", orderIDPrefix, err)
	}

	// Normalize addresses
	gatewayContractAddress, err := util.Base58ToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress)
	if err != nil {
		return fmt.Errorf("%s - Tron.SettleOrder.Base58ToAddress: %w", orderIDPrefix, err)
	}

	senderAddress, err := util.Base58ToAddress(wallet.AddressBase58)
	if err != nil {
		return fmt.Errorf("%s - Tron.SettleOrder.Base58ToAddress: %w", orderIDPrefix, err)
	}

	tokenContractAddress, err := util.Base58ToAddress(order.Edges.Token.ContractAddress)
	if err != nil {
		return fmt.Errorf("%s - Tron.SettleOrder.Base58ToAddress: %w", orderIDPrefix, err)
	}

	// Approve gateway contract to spend token
	calldata, err := s.approveCallData(
		gatewayContractAddress,
		utils.ToSubunit(order.Amount, order.Edges.Token.Decimals),
	)
	if err != nil {
		return fmt.Errorf("%s - Tron.SettleOrder.approveCallData: %w", orderIDPrefix, err)
	}

	ct := &core.TriggerSmartContract{
		OwnerAddress:    senderAddress.Bytes(),
		ContractAddress: tokenContractAddress.Bytes(),
		Data:            calldata,
	}
	_, err = s.sendTransaction(wallet, ct, 30000000)
	if err != nil {
		return fmt.Errorf("%s - Tron.SettleOrder.sendTransaction: %w", orderIDPrefix, err)
	}

	time.Sleep(5 * time.Second)

	// Settle order in gateway contract
	calldata, err = s.settleCallData(ctx, order)
	if err != nil {
		return fmt.Errorf("%s - Tron.SettleOrder.settleCallData: %w", orderIDPrefix, err)
	}

	ct = &core.TriggerSmartContract{
		OwnerAddress:    senderAddress.Bytes(),
		ContractAddress: gatewayContractAddress.Bytes(),
		Data:            calldata,
	}
	txHash, err := s.sendTransaction(wallet, ct, 60000000)
	if err != nil {
		return fmt.Errorf("%s - Tron.SettleOrder.sendTransaction: %w", orderIDPrefix, err)
	}

	// Update lock order
	_, err = order.Update().
		SetTxHash(txHash).
		SetStatus(paymentorder.StatusSettling).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - Tron.SettleOrder.updateTxHash: %w", orderIDPrefix, err)
	}

	return nil
}

// approveCallData creates the data for the ERC20 approve method
func (s *OrderTron) approveCallData(spender util.Address, amount *big.Int) ([]byte, error) {
	// Create ABI
	erc20ABI, err := abi.JSON(strings.NewReader(contracts.ERC20TokenMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse erc20 ABI: %w", err)
	}

	// Create calldata
	calldata, err := erc20ABI.Pack("approve", common.HexToAddress(spender.Hex()[4:]), amount)
	if err != nil {
		return nil, fmt.Errorf("failed to pack approve ABI: %w", err)
	}

	return calldata, nil
}

// createOrderCallData creates the data for the createOrder method
func (s *OrderTron) createOrderCallData(order *ent.PaymentOrder) ([]byte, error) {
	// Encrypt recipient details
	encryptedOrderRecipient, err := cryptoUtils.EncryptOrderRecipient(order)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt recipient details: %w", err)
	}

	refundAddressTron, _ := util.Base58ToAddress(order.RefundOrRecipientAddress)
	refundAddress := refundAddressTron.Hex()[4:]
	tokenContractAddressTron, _ := util.Base58ToAddress(order.Edges.Token.ContractAddress)
	senderFeeRecipientTron, _ := util.Base58ToAddress(order.FeeAddress)
	senderFeeRecipient := senderFeeRecipientTron.Hex()[4:]

	// Define params
	params := &types.CreateOrderParams{
		Token:              common.HexToAddress(tokenContractAddressTron.Hex()[4:]),
		Amount:             utils.ToSubunit(order.Amount, order.Edges.Token.Decimals),
		Rate:               order.Rate.Mul(decimal.NewFromInt(100)).BigInt(),
		SenderFeeRecipient: common.HexToAddress(senderFeeRecipient),
		SenderFee:          utils.ToSubunit(order.SenderFee, order.Edges.Token.Decimals),
		RefundAddress:      common.HexToAddress(refundAddress),
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

// refundCallData creates the data for the refund method
func (s *OrderTron) refundCallData(fee *big.Int, orderId string) ([]byte, error) {
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

// getOrderInfo gets the order info onchain
func (s *OrderTron) getOrderInfo(gatewayContractAddress util.Address, gatewayId string) (*contracts.IGatewayOrder, error) {
	gatewayABI, err := abi.JSON(strings.NewReader(contracts.GatewayMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse GatewayOrder ABI: %w", err)
	}

	orderID, err := hex.DecodeString(gatewayId[2:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode orderID: %w", err)
	}

	calldata, err := gatewayABI.Pack("getOrderInfo", utils.StringToByte32(string(orderID)))
	if err != nil {
		return nil, fmt.Errorf("failed to pack calldata: %w", err)
	}

	tx, err := s.callMethod(&core.TriggerSmartContract{
		ContractAddress: gatewayContractAddress.Bytes(),
		Data:            calldata,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to call method: %w", err)
	}

	result, err := gatewayABI.Unpack("getOrderInfo", tx.GetConstantResult()[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get order info: %w", err)
	}

	resultData := result[0].(struct {
		Sender             common.Address "json:\"sender\""
		Token              common.Address "json:\"token\""
		SenderFeeRecipient common.Address "json:\"senderFeeRecipient\""
		SenderFee          *big.Int       "json:\"senderFee\""
		ProtocolFee        *big.Int       "json:\"protocolFee\""
		IsFulfilled        bool           "json:\"isFulfilled\""
		IsRefunded         bool           "json:\"isRefunded\""
		RefundAddress      common.Address "json:\"refundAddress\""
		CurrentBPS         *big.Int       "json:\"currentBPS\""
		Amount             *big.Int       "json:\"amount\""
	})

	return &contracts.IGatewayOrder{
		Sender:             resultData.Sender,
		Token:              resultData.Token,
		SenderFeeRecipient: resultData.SenderFeeRecipient,
		SenderFee:          resultData.SenderFee,
		ProtocolFee:        resultData.ProtocolFee,
		IsFulfilled:        resultData.IsFulfilled,
		IsRefunded:         resultData.IsRefunded,
		RefundAddress:      resultData.RefundAddress,
		CurrentBPS:         resultData.CurrentBPS,
		Amount:             resultData.Amount,
	}, nil
}

// settleCallData creates the data for the settleOut method in the gateway contract
func (s *OrderTron) settleCallData(ctx context.Context, order *ent.PaymentOrder) ([]byte, error) {
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

	var providerAddress string
	providerAddressTron, _ := util.Base58ToAddress(token.SettlementAddress)
	providerAddress = providerAddressTron.Hex()[4:]

	if providerAddress == "" {
		return nil, fmt.Errorf("failed to fetch provider address: %w", err)
	}

	orderPercent, _ := order.OrderPercent.
		Mul(decimal.NewFromInt(1000)). // convert percent to BPS
		Float64()

	orderID, err := hex.DecodeString(order.GatewayID[2:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode orderID: %w", err)
	}

	splitOrderID := strings.ReplaceAll(order.ID.String(), "-", "")

	// Generate calldata for settlement (Gateway.settleOut)
	data, err := gatewayABI.Pack(
		"settleOut",
		utils.StringToByte32(splitOrderID),
		utils.StringToByte32(string(orderID)),
		common.HexToAddress(providerAddress),
		uint64(orderPercent),
		uint64(0), // rebatePercent - default to 0 for now
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack settleOut ABI: %w", err)
	}

	return data, nil
}

// signTransaction signs a transaction with a private key
func (s *OrderTron) signTransaction(transaction *api.TransactionExtention, privateKey *ecdsa.PrivateKey) (*api.TransactionExtention, error) {
	rawData, err := proto.Marshal(transaction.Transaction.GetRawData())
	if err != nil {
		return transaction, fmt.Errorf("proto marshal tx raw data error: %v", err)
	}

	h256h := sha256.New()
	h256h.Write(rawData)
	hash := h256h.Sum(nil)
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return transaction, fmt.Errorf("sign error: %v", err)
	}

	transaction.Transaction.Signature = append(transaction.Transaction.Signature, signature)
	return transaction, nil
}

// broadcastTransaction broadcasts a transaction to the Tron network
func (s *OrderTron) broadcastTransaction(node enums.Node, transaction *api.TransactionExtention) error {
	c, err := grpcClient.GetGrpcClient(node)
	if err != nil {
		return err
	}

	res, err := c.Broadcast(transaction.Transaction)
	if err != nil {
		return err
	}

	if !res.Result {
		return errors.New(res.Code.String())
	}

	return nil
}

// callMethod reads data from the Tron network
func (s *OrderTron) callMethod(ct *core.TriggerSmartContract) (*api.TransactionExtention, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if len(config.OrderConfig().TronProApiKey) > 0 {
		ctx = metadata.AppendToOutgoingContext(ctx, "TRON-PRO-API-KEY", config.OrderConfig().TronProApiKey)
	}
	defer cancel()

	g, err := grpcClient.GetGrpcClient(s.getNode())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to GRPC client: %w", err)
	}

	tx, err := g.Client.TriggerConstantContract(ctx, ct)
	if err != nil {
		return nil, err
	}

	if tx.Result.Code > 0 {
		return tx, fmt.Errorf("%s", string(tx.Result.Message))
	}

	return tx, nil
}

// sendTransaction sends a transaction to the Tron network
func (s *OrderTron) sendTransaction(wallet *tronWallet.TronWallet, ct *core.TriggerSmartContract, feeLimit int64) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if len(config.OrderConfig().TronProApiKey) > 0 {
		ctx = metadata.AppendToOutgoingContext(ctx, "TRON-PRO-API-KEY", config.OrderConfig().TronProApiKey)
	}
	defer cancel()

	g, err := grpcClient.GetGrpcClient(s.getNode())
	if err != nil {
		return "", fmt.Errorf("failed to connect to GRPC client: %w", err)
	}

	// Trigger smart contract
	tx, err := g.Client.TriggerContract(ctx, ct)
	if err != nil {
		return "", err
	}

	if tx.Result.Code > 0 {
		return "", fmt.Errorf("%s", string(tx.Result.Message))
	}
	if feeLimit > 0 {
		tx.Transaction.RawData.FeeLimit = feeLimit
		_ = g.UpdateHash(tx)
	}

	if tx.Result.Code > 0 {
		return "", fmt.Errorf("%s", string(tx.Result.Message))
	}

	// Sign and broadcast transaction
	privateKey, err := wallet.PrivateKeyRCDSA()
	if err != nil {
		return "", fmt.Errorf("failed to get private key: %w", err)
	}
	signedTx, err := s.signTransaction(tx, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	err = s.broadcastTransaction(wallet.Node, signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to broadcast transaction: %w", err)
	}

	return hexutil.Encode(tx.GetTxid())[2:], err
}
