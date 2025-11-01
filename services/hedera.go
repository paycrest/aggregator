package services

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/services/contracts"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

type HederaMirrorService struct {
	baseURL string
	rpcURL  string
}

// NewHederaMirrorService creates a new instance of HederaMirrorService
func NewHederaMirrorService() *HederaMirrorService {
	return &HederaMirrorService{
		baseURL: "https://mainnet.mirrornode.hedera.com/api/v1",
		rpcURL:  "https://mainnet.hashio.io/api",
	}
}

// CreateReceiveAddress returns the hardcoded Hedera receive address for payment orders
func (s *HederaMirrorService) CreateReceiveAddress() string {
	return config.HederaConfig().ReceiveAddress
}

// CreateGatewayOrder creates an order on the Hedera gateway contract
// This function handles the complete flow: approval + order creation
func (s *HederaMirrorService) CreateGatewayOrder(ctx context.Context, orderID, gatewayAddress string, orderData map[string]interface{}) error {
	logger.Infof("Creating gateway order %s on Hedera", orderID)

	// Setup client and wallet
	client, privateKey, walletAddress, chainID, err := s.setupClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to setup client: %w", err)
	}
	defer client.Close()

	// Extract and validate order parameters
	params, err := s.extractOrderParams(gatewayAddress, orderData)
	if err != nil {
		return fmt.Errorf("failed to extract order params: %w", err)
	}

	// Parse ABIs
	_, gatewayABI, err := s.parseABIs()
	if err != nil {
		return err
	}

	// Handle approval
	// if err := s.handleApproval(ctx, client, privateKey, chainID, walletAddress, params, erc20ABI); err != nil {
	// 	return fmt.Errorf("failed to handle approval: %w", err)
	// }

	logger.Infof("Approval successful for order: %s", orderID)
	logger.Infof("Hedera create order Params: %+v", params)

	// Create order transaction
	createOrderData, err := gatewayABI.Pack(
		"createOrder",
		params.tokenAddress,
		params.amountBigInt,
		params.rateBigInt,
		params.senderFeeRecipient,
		params.senderFeeBigInt,
		params.refundAddress,
		params.messageHash,
	)
	if err != nil {
		return fmt.Errorf("failed to pack createOrder call: %w", err)
	}

	createOrderTxHash, err := s.sendTransaction(ctx, client, privateKey, chainID, walletAddress, params.gatewayAddress, createOrderData)
	if err != nil {
		return fmt.Errorf("failed to send createOrder transaction: %w", err)
	}

	logger.Infof("CreateOrder transaction sent: %s", createOrderTxHash.Hex())

	// Wait for confirmation
	receipt, err := s.waitForReceipt(ctx, client, createOrderTxHash)
	if err != nil {
		return fmt.Errorf("failed to wait for createOrder receipt: %w", err)
	}

	if receipt.Status == 0 {
		return fmt.Errorf("createOrder transaction failed")
	}

	logger.Infof("Order created successfully in block %d, tx: %s", receipt.BlockNumber.Uint64(), createOrderTxHash.Hex())
	return nil
}

// SettleOrder settles a lock order on the Hedera gateway contract
func (s *HederaMirrorService) SettleOrder(ctx context.Context, txPayload map[string]interface{}) error {
	logger.Infof("Settling order on Hedera")

	// Setup client and wallet
	client, privateKey, walletAddress, chainID, err := s.setupClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to setup client: %w", err)
	}
	defer client.Close()

	// Get gateway address
	gatewayAddress := common.HexToAddress(txPayload["to"].(string))

	// Convert hex string data to bytes
	dataStr, ok := txPayload["data"].(string)
	if !ok {
		return fmt.Errorf("invalid data type in txPayload, expected string")
	}
	dataStr = strings.TrimPrefix(dataStr, "0x")
	dataBytes, err := hex.DecodeString(dataStr)
	if err != nil {
		return fmt.Errorf("failed to decode hex data: %w", err)
	}

	// Send transaction
	settleTxHash, err := s.sendTransaction(ctx, client, privateKey, chainID, walletAddress, gatewayAddress, dataBytes)
	if err != nil {
		return fmt.Errorf("failed to send settle transaction: %w", err)
	}

	logger.Infof("Settle transaction sent: %s", settleTxHash.Hex())

	// Wait for confirmation
	receipt, err := s.waitForReceipt(ctx, client, settleTxHash)
	if err != nil {
		return fmt.Errorf("failed to wait for settle receipt: %w", err)
	}

	if receipt.Status == 0 {
		return fmt.Errorf("settle transaction failed")
	}

	logger.Infof("Order settled successfully in block %d, tx: %s", receipt.BlockNumber.Uint64(), settleTxHash.Hex())
	return nil
}

// RefundOrder refunds an order on the Hedera gateway contract
func (s *HederaMirrorService) RefundOrder(ctx context.Context, txPayload map[string]interface{}) error {
	logger.Infof("Refunding order on Hedera")

	// Setup client and wallet
	client, privateKey, walletAddress, chainID, err := s.setupClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to setup client: %w", err)
	}
	defer client.Close()

	gatewayAddress := common.HexToAddress(txPayload["to"].(string))
	if gatewayAddress == (common.Address{}) {
		return fmt.Errorf("HEDERA_GATEWAY_CONTRACT not set in configuration")
	}

	// Convert hex string data to bytes
	dataStr, ok := txPayload["data"].(string)
	if !ok {
		return fmt.Errorf("invalid data type in txPayload, expected string")
	}
	dataStr = strings.TrimPrefix(dataStr, "0x")
	dataBytes, err := hex.DecodeString(dataStr)
	if err != nil {
		return fmt.Errorf("failed to decode hex data: %w", err)
	}

	// Send transaction
	refundTxHash, err := s.sendTransaction(ctx, client, privateKey, chainID, walletAddress, gatewayAddress, dataBytes)
	if err != nil {
		return fmt.Errorf("failed to send refund transaction: %w", err)
	}

	logger.Infof("Refund transaction sent: %s", refundTxHash.Hex())

	// Wait for confirmation
	receipt, err := s.waitForReceipt(ctx, client, refundTxHash)
	if err != nil {
		return fmt.Errorf("failed to wait for refund receipt: %w", err)
	}

	if receipt.Status == 0 {
		return fmt.Errorf("refund transaction failed")
	}

	logger.Infof("Order refunded successfully in block %d, tx: %s", receipt.BlockNumber.Uint64(), refundTxHash.Hex())
	return nil
}

// orderParams holds extracted and validated order parameters
type orderParams struct {
	tokenAddress       common.Address
	gatewayAddress     common.Address
	amountBigInt       *big.Int
	senderFeeBigInt    *big.Int
	rateBigInt         *big.Int
	totalAmount        *big.Int
	senderFeeRecipient common.Address
	refundAddress      common.Address
	messageHash        string
}

// setupClient creates an ethclient and returns it along with wallet details
func (s *HederaMirrorService) setupClient(ctx context.Context) (*ethclient.Client, *ecdsa.PrivateKey, common.Address, *big.Int, error) {
	// Connect to Hedera via JSON-RPC
	client, err := ethclient.Dial(s.rpcURL)
	if err != nil {
		return nil, nil, common.Address{}, nil, fmt.Errorf("failed to connect to Hedera RPC: %w", err)
	}

	// Get chain ID
	chainID, err := client.ChainID(ctx)
	if err != nil {
		client.Close()
		return nil, nil, common.Address{}, nil, fmt.Errorf("failed to get chain ID: %w", err)
	}

	// Get private key from config
	hederaConfig := config.HederaConfig()
	privateKeyHex := hederaConfig.PrivateKey
	if privateKeyHex == "" {
		client.Close()
		return nil, nil, common.Address{}, nil, fmt.Errorf("HEDERA_PRIVATE_KEY not set in configuration")
	}

	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		client.Close()
		return nil, nil, common.Address{}, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		client.Close()
		return nil, nil, common.Address{}, nil, fmt.Errorf("failed to cast public key to ECDSA")
	}
	walletAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	return client, privateKey, walletAddress, chainID, nil
}

// parseABIs parses and returns the ERC20 and Gateway ABIs
func (s *HederaMirrorService) parseABIs() (*abi.ABI, *abi.ABI, error) {
	// Parse ERC20 ABI from generated contract
	erc20ABI, err := abi.JSON(strings.NewReader(contracts.ERC20TokenMetaData.ABI))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ERC20 ABI: %w", err)
	}

	// Parse Gateway ABI from generated contract
	gatewayABI, err := abi.JSON(strings.NewReader(contracts.GatewayMetaData.ABI))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse Gateway ABI: %w", err)
	}

	return &erc20ABI, &gatewayABI, nil
}

// extractOrderParams extracts and validates order parameters from orderData map
func (s *HederaMirrorService) extractOrderParams(gatewayContractAddress string, orderData map[string]interface{}) (*orderParams, error) {
	tokenAddress := common.HexToAddress(orderData["token"].(string))

	// Get gateway address from config
	gatewayAddress := common.HexToAddress(gatewayContractAddress)

	if gatewayAddress == (common.Address{}) {
		return nil, fmt.Errorf("HEDERA_GATEWAY_CONTRACT not set in configuration")
	}

	amount, ok := orderData["amount"].(decimal.Decimal)
	if !ok {
		return nil, fmt.Errorf("invalid amount type")
	}

	rate, ok := orderData["rate"].(decimal.Decimal)
	if !ok {
		return nil, fmt.Errorf("invalid rate type")
	}

	senderFee, ok := orderData["senderFee"].(decimal.Decimal)
	if !ok {
		senderFee = decimal.Zero
	}

	senderFeeRecipient := common.HexToAddress(orderData["senderFeeRecipient"].(string))
	refundAddress := common.HexToAddress(orderData["refundAddress"].(string))
	messageHash := orderData["messageHash"].(string)

	// Convert decimals to big.Int
	tokenDecimals := int8(6) // Default USDC decimals
	if decimals, ok := orderData["decimals"].(int32); ok {
		tokenDecimals = int8(decimals)
	}

	amountBigInt := utils.ToSubunit(amount, tokenDecimals)
	senderFeeBigInt := utils.ToSubunit(senderFee, tokenDecimals)
	rateBigInt := rate.Mul(decimal.NewFromInt(100)).BigInt() // Convert to basis points
	totalAmount := new(big.Int).Add(amountBigInt, senderFeeBigInt)

	return &orderParams{
		tokenAddress:       tokenAddress,
		gatewayAddress:     gatewayAddress,
		amountBigInt:       amountBigInt,
		senderFeeBigInt:    senderFeeBigInt,
		rateBigInt:         rateBigInt,
		totalAmount:        totalAmount,
		senderFeeRecipient: senderFeeRecipient,
		refundAddress:      refundAddress,
		messageHash:        messageHash,
	}, nil
}

// handleApproval checks allowance and approves if needed
// func (s *HederaMirrorService) handleApproval(
// 	ctx context.Context,
// 	client *ethclient.Client,
// 	privateKey *ecdsa.PrivateKey,
// 	chainID *big.Int,
// 	walletAddress common.Address,
// 	params *orderParams,
// 	erc20ABI *abi.ABI,
// ) error {
// 	// Check allowance
// 	logger.Infof("Checking allowance for gateway contract")
// 	allowanceData, err := erc20ABI.Pack("allowance", walletAddress, params.gatewayAddress)
// 	if err != nil {
// 		return fmt.Errorf("failed to pack allowance call: %w", err)
// 	}

// 	allowanceResult, err := client.CallContract(ctx, ethereum.CallMsg{
// 		To:   &params.tokenAddress,
// 		Data: allowanceData,
// 	}, nil)
// 	if err != nil {
// 		return fmt.Errorf("failed to call allowance: %w", err)
// 	}

// 	currentAllowance := new(big.Int).SetBytes(allowanceResult)
// 	logger.Infof("Current allowance: %s, needed: %s", currentAllowance.String(), params.totalAmount.String())

// 	// Approve if needed
// 	if currentAllowance.Cmp(params.totalAmount) < 0 {
// 		logger.Infof("Approving gateway to spend %s tokens", params.totalAmount.String())

// 		approveData, err := erc20ABI.Pack("approve", params.gatewayAddress, params.totalAmount)
// 		if err != nil {
// 			return fmt.Errorf("failed to pack approve call: %w", err)
// 		}

// 		approveTxHash, err := s.sendTransaction(ctx, client, privateKey, chainID, walletAddress, params.tokenAddress, approveData)
// 		if err != nil {
// 			return fmt.Errorf("failed to send approve transaction: %w", err)
// 		}

// 		logger.Infof("Approve transaction sent: %s", approveTxHash.Hex())

// 		// Wait for approval confirmation
// 		receipt, err := s.waitForReceipt(ctx, client, approveTxHash)
// 		if err != nil {
// 			return fmt.Errorf("failed to wait for approve receipt: %w", err)
// 		}

// 		if receipt.Status == 0 {
// 			return fmt.Errorf("approve transaction failed")
// 		}

// 		logger.Infof("Approval confirmed in block %d", receipt.BlockNumber.Uint64())
// 	}

// 	return nil
// }

// sendTransaction creates, signs, and sends a transaction
func (s *HederaMirrorService) sendTransaction(
	ctx context.Context,
	client *ethclient.Client,
	privateKey *ecdsa.PrivateKey,
	chainID *big.Int,
	from common.Address,
	to common.Address,
	data []byte,
) (common.Hash, error) {
	nonce, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to get nonce: %w", err)
	}

	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to get gas price: %w", err)
	}

	// Estimate gas
	gasLimit := uint64(500000) // Default
	estimatedGas, err := client.EstimateGas(ctx, ethereum.CallMsg{
		From:     from,
		To:       &to,
		GasPrice: gasPrice,
		Value:    big.NewInt(0),
		Data:     data,
	})
	if err != nil {
		logger.Warnf("Failed to estimate gas: %v, using default %d", err, gasLimit)
	} else {
		gasLimit = estimatedGas * 120 / 100 // Add 20% buffer
	}

	tx := types.NewTransaction(nonce, to, big.NewInt(0), gasLimit, gasPrice, data)
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to sign transaction: %w", err)
	}

	err = client.SendTransaction(ctx, signedTx)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to send transaction: %w", err)
	}

	return signedTx.Hash(), nil
}

// waitForReceipt waits for a transaction receipt with timeout
func (s *HederaMirrorService) waitForReceipt(ctx context.Context, client *ethclient.Client, txHash common.Hash) (*types.Receipt, error) {
	timeout := time.After(2 * time.Minute)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("timeout waiting for transaction receipt")
		case <-ticker.C:
			receipt, err := client.TransactionReceipt(ctx, txHash)
			if err == nil {
				return receipt, nil
			}
			// Continue waiting if receipt not found yet
		}
	}
}

func (s *HederaMirrorService) getContractLogs(contractAddress string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/contracts/%s/results/logs", s.baseURL, contractAddress)
	url += fmt.Sprintf("?timestamp=gte:%d", time.Now().Unix()-60)

	logger.Infof("Fetching Hedera logs from URL: %s", url)

	res, err := fastshot.NewClient(url).
		Config().SetTimeout(60 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}).Build().GET("").Send()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Hedera logs: %w", err)
	}

	logger.Infof("Hedera logs response status: %s (Code: %d)", res.RawResponse.Status, res.RawResponse.StatusCode)

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		logger.Errorf("Failed to parse Hedera logs response: %v", err)
		return nil, fmt.Errorf("failed to parse Hedera logs response: %w", err)
	}

	// Log parsed response data
	logsAny, ok := data["logs"].([]interface{})
	logCount := 0
	if ok && logsAny != nil {
		logCount = len(logsAny)
	}
	logger.Infof("Hedera logs response: Found %d logs, Full response: %+v", logCount, data)

	// Extract logs
	if !ok || logsAny == nil {
		return []map[string]interface{}{}, nil
	}

	logs := make([]map[string]interface{}, 0, len(logsAny))
	for _, item := range logsAny {
		if m, ok := item.(map[string]interface{}); ok {
			logs = append(logs, m)
		}
	}

	return logs, nil
}

func (s *HederaMirrorService) GetContractEventsBySignature(token *ent.Token, eventSignatures []string, matchAddress string) ([]map[string]interface{}, error) {
	var allFiltered []map[string]interface{}
	logger.Infof("Getting Hedera contract events by signature for token %s", token.Symbol)

	// Check if TransferEventSignature is in the list
	hasTransfer := false
	var gatewaySignatures []string

	gatewayContract := token.Edges.Network.GatewayContractAddress

	for _, sig := range eventSignatures {
		if strings.EqualFold(sig, utils.TransferEventSignature) && matchAddress != gatewayContract {
			hasTransfer = true
		} else {
			gatewaySignatures = append(gatewaySignatures, sig)
		}
	}

	// Query transfer events from token contract if included
	if hasTransfer {
		transferLogs, err := s.getContractLogs(token.ContractAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to get transfer logs: %w", err)
		}
		logger.Infof("Transfer logs: %+v", transferLogs)

		// Process transfer events
		for _, log := range transferLogs {
			topics, ok := log["topics"].([]interface{})
			if !ok || len(topics) == 0 {
				continue
			}

			topic0, ok := topics[0].(string)
			if !ok || !strings.EqualFold(topic0, utils.TransferEventSignature) {
				continue
			}

			// Optional address filtering
			if matchAddress != "" {
				matched := false
				for i := 1; i < len(topics); i++ {
					if ts, ok := topics[i].(string); ok {
						if len(ts) == 66 && strings.HasPrefix(ts, "0x") {
							extractedAddr := "0x" + ts[len(ts)-40:]
							if strings.EqualFold(extractedAddr, matchAddress) {
								matched = true
								break
							}
						}
					}
				}
				if !matched {
					continue
				}
			}
			filteredEvent := transferEvent(log, token)
			if filteredEvent != nil {
				logger.Infof("Transfer event: %+v", filteredEvent)
				allFiltered = append(allFiltered, filteredEvent)
			}
		}
	}

	// Query gateway events if there are non-transfer signatures
	if len(gatewaySignatures) > 0 {

		// allgatewaySignatures := append(
		// 	gatewaySignatures,
		// 	utils.OrderCreatedEventSignature,
		// 	utils.OrderSettledEventSignature,
		// 	utils.OrderRefundedEventSignature,
		// )
		gatewayLogs, err := s.getContractLogs(token.Edges.Network.GatewayContractAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to get gateway logs: %w", err)
		}

		// Process gateway events
		for _, log := range gatewayLogs {
			topics, ok := log["topics"].([]interface{})
			if !ok || len(topics) == 0 {
				continue
			}

			topic0, ok := topics[0].(string)
			if !ok {
				continue
			}

			// Process based on event signature
			if strings.EqualFold(topic0, utils.OrderCreatedEventSignature) {
				filteredEvent := orderCreatedEvent(log, token)
				if filteredEvent != nil {
					allFiltered = append(allFiltered, filteredEvent)
				}
			} else if strings.EqualFold(topic0, utils.OrderSettledEventSignature) {
				filteredEvent := orderSettledEvent(log)
				if filteredEvent != nil {
					allFiltered = append(allFiltered, filteredEvent)
				}
			} else if strings.EqualFold(topic0, utils.OrderRefundedEventSignature) {
				filteredEvent := orderRefundedEvent(log)
				if filteredEvent != nil {
					allFiltered = append(allFiltered, filteredEvent)
				}
			}
		}
	}

	return allFiltered, nil
}

func transferEvent(log map[string]interface{}, token *ent.Token) map[string]interface{} {
	topics, ok := log["topics"].([]interface{})
	if !ok || len(topics) < 3 {
		return nil
	}

	var blockNumber int64
	if bn, ok := log["block_number"].(float64); ok {
		blockNumber = int64(bn)
	}

	txHash, _ := log["transaction_hash"].(string)

	fromTopic := topics[1].(string)

	if len(fromTopic) == 66 && strings.HasPrefix(fromTopic, "0x") {
		fromTopic = "0x" + fromTopic[len(fromTopic)-40:]
	}

	toTopic := topics[2].(string)

	if len(toTopic) == 66 && strings.HasPrefix(toTopic, "0x") {
		toTopic = "0x" + toTopic[len(toTopic)-40:]
	}

	amountHex := log["data"].(string)
	amountHex = strings.TrimPrefix(amountHex, "0x")

	bigIntVal := new(big.Int)
	bigIntAmount, ok := bigIntVal.SetString(amountHex, 16)
	if !ok {
		// Handle the error: invalid hex string
		return nil // or log an error
	}

	value := decimal.NewFromBigInt(bigIntAmount, 0)
	// normalize by token decimals
	normalized := value.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(token.Decimals))))

	return map[string]interface{}{
		"Topic":       topics[0].(string),
		"BlockNumber": blockNumber,
		"TxHash":      txHash,
		"From":        fromTopic,
		"To":          toTopic,
		"Value":       normalized,
	}
}

func orderCreatedEvent(log map[string]interface{}, token *ent.Token) map[string]interface{} {
	topics, ok := log["topics"].([]interface{})
	if !ok || len(topics) < 4 {
		return nil
	}

	var blockNumber int64
	if bn, ok := log["block_number"].(float64); ok {
		blockNumber = int64(bn)
	}
	txHash, _ := log["transaction_hash"].(string)

	senderStr, ok := topics[1].(string)
	if !ok || senderStr == "" {
		return nil
	}
	tokenStr, ok := topics[2].(string)
	if !ok || tokenStr == "" {
		return nil
	}
	amountTopicHex, ok := topics[3].(string)
	if !ok || amountTopicHex == "" {
		return nil
	}
	amountTopicHex = strings.TrimPrefix(amountTopicHex, "0x")
	amountBig := new(big.Int)
	_, ok = amountBig.SetString(amountTopicHex, 16)
	if !ok {
		return nil
	}
	amountDec := decimal.NewFromBigInt(amountBig, 0).Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(token.Decimals))))

	dataHex, _ := log["data"].(string)
	dataHex = strings.TrimPrefix(dataHex, "0x")
	dataBytes, err := hex.DecodeString(dataHex)
	if err != nil {
		return nil
	}

	// Expect at least 96 bytes for protocolFee, orderId, rate
	if len(dataBytes) < 96 {
		return nil
	}
	protocolFeeBig := new(big.Int).SetBytes(dataBytes[0:32])
	orderIdBytes := dataBytes[32:64]
	rateBig := new(big.Int).SetBytes(dataBytes[64:96])

	protocolFee := decimal.NewFromBigInt(protocolFeeBig, 0).Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(token.Decimals))))
	rate := decimal.NewFromBigInt(rateBig, 0)

	messageHash := ""
	if len(dataBytes) >= 128 {
		// Try next 32 bytes as messageHash (bytes32)
		messageHash = "0x" + hex.EncodeToString(dataBytes[96:128])
	}

	return map[string]interface{}{
		"Topic":       topics[0].(string),
		"BlockNumber": blockNumber,
		"TxHash":      txHash,
		"Token":       tokenStr,
		"Amount":      amountDec,
		"ProtocolFee": protocolFee,
		"Rate":        rate,
		"OrderId":     "0x" + hex.EncodeToString(orderIdBytes),
		"MessageHash": messageHash,
		"Sender":      senderStr,
	}
}

func orderSettledEvent(log map[string]interface{}) map[string]interface{} {
	topics, ok := log["topics"].([]interface{})
	if !ok || len(topics) < 3 {
		return nil
	}

	var blockNumber int64
	if bn, ok := log["block_number"].(float64); ok {
		blockNumber = int64(bn)
	}
	txHash, _ := log["transaction_hash"].(string)

	// OrderId = topics[1], LiquidityProvider = topics[2]
	orderIdStr, ok := topics[1].(string)
	if !ok || orderIdStr == "" {
		return nil
	}
	liquidityProviderStr, ok := topics[2].(string)
	if !ok || liquidityProviderStr == "" {
		return nil
	}

	// Data: splitOrderId (32 bytes) + settlePercent (left-padded 32 bytes)
	dataHex, _ := log["data"].(string)
	dataHex = strings.TrimPrefix(dataHex, "0x")
	dataBytes, err := hex.DecodeString(dataHex)
	if err != nil || len(dataBytes) < 64 { // need at least 64 bytes
		return nil
	}
	splitOrderId := "0x" + hex.EncodeToString(dataBytes[:32])
	settlePercentBig := new(big.Int).SetBytes(dataBytes[32:64])
	settlePercent := decimal.NewFromBigInt(settlePercentBig, 0)

	return map[string]interface{}{
		"Topic":             topics[0].(string),
		"BlockNumber":       blockNumber,
		"TxHash":            txHash,
		"SplitOrderId":      splitOrderId,
		"OrderId":           orderIdStr,
		"LiquidityProvider": liquidityProviderStr,
		"SettlePercent":     settlePercent,
	}
}

func orderRefundedEvent(log map[string]interface{}) map[string]interface{} {
	topics, ok := log["topics"].([]interface{})
	if !ok || len(topics) < 2 {
		return nil
	}

	var blockNumber int64
	if bn, ok := log["block_number"].(float64); ok {
		blockNumber = int64(bn)
	}
	txHash, _ := log["transaction_hash"].(string)

	orderIdStr, ok := topics[1].(string)
	if !ok || orderIdStr == "" {
		return nil
	}

	dataHex, _ := log["data"].(string)
	dataHex = strings.TrimPrefix(dataHex, "0x")
	dataBytes, err := hex.DecodeString(dataHex)
	if err != nil || len(dataBytes) == 0 {
		return nil
	}
	feeBig := new(big.Int).SetBytes(dataBytes)
	fee := decimal.NewFromBigInt(feeBig, 0)

	return map[string]interface{}{
		"Topic":       topics[0].(string),
		"BlockNumber": blockNumber,
		"TxHash":      txHash,
		"OrderId":     orderIdStr,
		"Fee":         fee,
	}
}
