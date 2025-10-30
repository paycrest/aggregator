package services

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/utils"
	"github.com/shopspring/decimal"
)

// HederaMirrorService provides functionality for interacting with Hedera Mirror Node API
type HederaMirrorService struct {
	baseURL              string
	tokenContractAddress string
}

// NewHederaMirrorService creates a new instance of HederaMirrorService
// If baseURL is empty, it defaults to Hedera mainnet mirror node.
func NewHederaMirrorService(baseURL string, apiKey string) *HederaMirrorService {
	if baseURL == "" {
		baseURL = "https://mainnet.mirrornode.hedera.com/api/v1"
	}
	return &HederaMirrorService{
		baseURL:              baseURL,
		tokenContractAddress: "0x000000000000000000000000000000000006f89a",
	}
}

func (s *HederaMirrorService) getContractLogs(contractAddress string, timestamp string, topic0Signatures []string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/contracts/%s/results/logs", s.baseURL, contractAddress)

	// Build query parameters
	params := []string{}

	if timestamp != "" {
		params = append(params, fmt.Sprintf("timestamp=%s", timestamp))
	}

	// Add multiple topic0 parameters for filtering
	for _, sig := range topic0Signatures {
		params = append(params, fmt.Sprintf("topic0=%s", sig))
	}

	if len(params) > 0 {
		url += "?" + strings.Join(params, "&")
	}

	res, err := fastshot.NewClient(url).
		Config().SetTimeout(60 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}).Build().GET("").Send()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Hedera logs: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Hedera logs response: %w", err)
	}

	// Extract logs
	logsAny, ok := data["logs"].([]interface{})
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

func (s *HederaMirrorService) GetContractEventsBySignature(token *ent.Token, eventSignatures []string, matchAddress string, timestamp string) ([]map[string]interface{}, error) {
	var allFiltered []map[string]interface{}

	// Check if TransferEventSignature is in the list
	hasTransfer := false
	var gatewaySignatures []string

	for _, sig := range eventSignatures {
		if strings.EqualFold(sig, utils.TransferEventSignature) {
			hasTransfer = true
		} else {
			gatewaySignatures = append(gatewaySignatures, sig)
		}
	}

	// Query transfer events from token contract if included
	if hasTransfer {
		transferLogs, err := s.getContractLogs(token.ContractAddress, timestamp, []string{utils.TransferEventSignature})
		if err != nil {
			return nil, fmt.Errorf("failed to get transfer logs: %w", err)
		}

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
					if ts, ok := topics[i].(string); ok && strings.EqualFold(ts, matchAddress) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}

			filteredEvent := transferEvent(log, token)
			if filteredEvent != nil {
				allFiltered = append(allFiltered, filteredEvent)
			}
		}
	}

	// Query gateway events if there are non-transfer signatures
	if len(gatewaySignatures) > 0 {

		allgatewaySignatures := append(
			gatewaySignatures,
			utils.OrderCreatedEventSignature,
			utils.OrderSettledEventSignature,
			utils.OrderRefundedEventSignature,
		)
		gatewayLogs, err := s.getContractLogs(token.Edges.Network.GatewayContractAddress, timestamp, allgatewaySignatures)
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

	fromStr, ok := topics[1].(string)
	if !ok || fromStr == "" {
		return nil
	}
	toStr, ok := topics[2].(string)
	if !ok || toStr == "" {
		return nil
	}
	amountHex, ok := log["data"].(string)
	if !ok || amountHex == "" {
		return nil
	}
	if len(amountHex) >= 3 && strings.HasPrefix(amountHex, "0x") {
		amountHex = amountHex[2:]
	}

	bigIntAmount := new(big.Int)
	_, ok = bigIntAmount.SetString(amountHex, 16)
	if !ok {
		return nil
	}
	value := decimal.NewFromBigInt(bigIntAmount, 0)
	// normalize by token decimals
	normalized := value.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(token.Decimals))))

	return map[string]interface{}{
		"Topic":       topics[0].(string),
		"BlockNumber": blockNumber,
		"TxHash":      txHash,
		"From":        fromStr,
		"To":          toStr,
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
	if strings.HasPrefix(amountTopicHex, "0x") {
		amountTopicHex = amountTopicHex[2:]
	}
	amountBig := new(big.Int)
	_, ok = amountBig.SetString(amountTopicHex, 16)
	if !ok {
		return nil
	}
	amountDec := decimal.NewFromBigInt(amountBig, 0).Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(token.Decimals))))

	dataHex, _ := log["data"].(string)
	if strings.HasPrefix(dataHex, "0x") {
		dataHex = dataHex[2:]
	}
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
	if strings.HasPrefix(dataHex, "0x") {
		dataHex = dataHex[2:]
	}
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
	if strings.HasPrefix(dataHex, "0x") {
		dataHex = dataHex[2:]
	}
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
