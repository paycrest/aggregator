package utils

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Event signatures for Gateway and token contract events
const (
	TransferEventSignature      = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	OrderCreatedEventSignature  = "0x40ccd1ceb111a3c186ef9911e1b876dc1f789ed331b86097b3b8851055b6a137"
	OrderSettledEventSignature  = "0x98ece21e01a01cbe1d1c0dad3b053c8fbd368f99be78be958fcf1d1d13fd249a"
	OrderRefundedEventSignature = "0x0736fe428e1747ca8d387c2e6fa1a31a0cde62d3a167c40a46ade59a3cdc828e"
)

// DecodeTransferEvent decodes a Transfer event from RPC log
func DecodeTransferEvent(log types.Log) (map[string]interface{}, error) {
	// Transfer event: Transfer(address indexed from, address indexed to, uint256 value)
	// Topics: [eventSignature, from, to]
	// Data: value

	if len(log.Topics) != 3 {
		return nil, fmt.Errorf("invalid Transfer event: expected 3 topics, got %d", len(log.Topics))
	}

	from := common.HexToAddress(log.Topics[1].Hex())
	to := common.HexToAddress(log.Topics[2].Hex())

	// Decode value from data
	value := new(big.Int).SetBytes(log.Data)

	return map[string]interface{}{
		"indexed_params": map[string]interface{}{
			"from": from.Hex(),
			"to":   to.Hex(),
		},
		"non_indexed_params": map[string]interface{}{
			"value": value.String(),
		},
	}, nil
}

// DecodeOrderCreatedEvent decodes an OrderCreated event from RPC log
func DecodeOrderCreatedEvent(log types.Log) (map[string]interface{}, error) {
	// OrderCreated event: OrderCreated(address indexed sender, address indexed token, uint256 indexed amount, uint256 protocolFee, bytes32 orderId, uint256 rate, string messageHash)
	// Topics: [eventSignature, sender, token, amount]
	// Data: [protocolFee, orderId, rate, messageHash]

	if len(log.Topics) != 4 {
		return nil, fmt.Errorf("invalid OrderCreated event: expected 4 topics, got %d", len(log.Topics))
	}

	sender := common.HexToAddress(log.Topics[1].Hex())
	token := common.HexToAddress(log.Topics[2].Hex())
	amount := new(big.Int).SetBytes(log.Topics[3].Bytes())

	// Decode non-indexed parameters from data
	// The data contains: protocolFee (32 bytes) + orderId (32 bytes) + rate (32 bytes) + messageHash (dynamic)
	if len(log.Data) < 96 {
		return nil, fmt.Errorf("invalid OrderCreated event data: too short")
	}

	protocolFee := new(big.Int).SetBytes(log.Data[:32])
	orderId := common.BytesToHash(log.Data[32:64])
	rate := new(big.Int).SetBytes(log.Data[64:96])

	// Decode messageHash (dynamic string) - using the correct approach
	messageHash := ""
	if len(log.Data) > 96 {
		messageHashBytes := log.Data[96:]
		// For strings in ABI, the first 32 bytes contain the offset to the string data
		if len(messageHashBytes) >= 32 {
			// Get the offset to the string data
			offset := new(big.Int).SetBytes(messageHashBytes[:32])
			offsetInt := int(offset.Int64())

			// The string data starts at the offset position
			if offsetInt+32 <= len(log.Data) {
				// Read the length of the string (next 32 bytes after offset)
				lengthBytes := log.Data[offsetInt : offsetInt+32]
				length := new(big.Int).SetBytes(lengthBytes)
				lengthInt := int(length.Int64())

				// Read the actual string data
				if offsetInt+32+lengthInt <= len(log.Data) {
					stringData := log.Data[offsetInt+32 : offsetInt+32+lengthInt]
					messageHash = string(stringData)
				}
			}
		}
	}

	return map[string]interface{}{
		"indexed_params": map[string]interface{}{
			"sender": sender.Hex(),
			"token":  token.Hex(),
			"amount": amount.String(),
		},
		"non_indexed_params": map[string]interface{}{
			"protocolFee": protocolFee.String(),
			"orderId":     orderId.Hex(),
			"rate":        rate.String(),
			"messageHash": messageHash,
		},
	}, nil
}

// DecodeOrderSettledEvent decodes an OrderSettled event from RPC log
func DecodeOrderSettledEvent(log types.Log) (map[string]interface{}, error) {
	// OrderSettled event: OrderSettled(bytes32 splitOrderId, bytes32 indexed orderId, address indexed liquidityProvider, uint96 settlePercent)
	// Topics: [eventSignature, orderId, liquidityProvider]
	// Data: [splitOrderId, settlePercent]

	if len(log.Topics) != 3 {
		return nil, fmt.Errorf("invalid OrderSettled event: expected 3 topics, got %d", len(log.Topics))
	}

	orderId := common.BytesToHash(log.Topics[1].Bytes())
	liquidityProvider := common.HexToAddress(log.Topics[2].Hex())

	// Decode non-indexed parameters from data
	// The data contains: splitOrderId (32 bytes) + settlePercent (12 bytes)
	if len(log.Data) < 44 {
		return nil, fmt.Errorf("invalid OrderSettled event data: too short")
	}

	splitOrderId := common.BytesToHash(log.Data[:32])
	settlePercent := new(big.Int).SetBytes(log.Data[32:64])

	return map[string]interface{}{
		"indexed_params": map[string]interface{}{
			"orderId":           orderId.Hex(),
			"liquidityProvider": liquidityProvider.Hex(),
		},
		"non_indexed_params": map[string]interface{}{
			"splitOrderId":  splitOrderId.Hex(),
			"settlePercent": settlePercent.String(),
		},
	}, nil
}

// DecodeOrderRefundedEvent decodes an OrderRefunded event from RPC log
func DecodeOrderRefundedEvent(log types.Log) (map[string]interface{}, error) {
	// OrderRefunded event: OrderRefunded(uint256 fee, bytes32 indexed orderId)
	// Topics: [eventSignature, orderId]
	// Data: [fee]

	if len(log.Topics) != 2 {
		return nil, fmt.Errorf("invalid OrderRefunded event: expected 2 topics, got %d", len(log.Topics))
	}

	orderId := common.BytesToHash(log.Topics[1].Bytes())

	// Decode fee from data
	fee := new(big.Int).SetBytes(log.Data)

	return map[string]interface{}{
		"indexed_params": map[string]interface{}{
			"orderId": orderId.Hex(),
		},
		"non_indexed_params": map[string]interface{}{
			"fee": fee.String(),
		},
	}, nil
}

// ProcessRPCEvents processes RPC events and converts them to the same format as Thirdweb Insight
func ProcessRPCEvents(events []interface{}, eventSignature string) error {
	for _, event := range events {
		eventMap := event.(map[string]interface{})

		// Convert topics to the expected format
		if topics, ok := eventMap["topics"].([]common.Hash); ok {
			topicsHex := make([]string, len(topics))
			for i, topic := range topics {
				topicsHex[i] = topic.Hex()
			}
			eventMap["topics"] = topicsHex
		}

		// Create a mock log for decoding (since we already have the raw log data)
		// We'll decode directly from the event data instead
		if topics, ok := eventMap["topics"].([]string); ok && len(topics) > 0 {
			// Create a mock log with the topics and data
			var logTopics []common.Hash
			for _, topic := range topics {
				logTopics = append(logTopics, common.HexToHash(topic))
			}

			mockLog := types.Log{
				Topics: logTopics,
				Data:   eventMap["data"].([]byte),
			}

			var decoded map[string]interface{}
			var err error

			switch eventSignature {
			case TransferEventSignature:
				decoded, err = DecodeTransferEvent(mockLog)
			case OrderCreatedEventSignature:
				decoded, err = DecodeOrderCreatedEvent(mockLog)
			case OrderSettledEventSignature:
				decoded, err = DecodeOrderSettledEvent(mockLog)
			case OrderRefundedEventSignature:
				decoded, err = DecodeOrderRefundedEvent(mockLog)
			default:
				continue
			}

			if err != nil {
				return fmt.Errorf("failed to decode event: %w", err)
			}

			eventMap["decoded"] = decoded
		}
	}

	return nil
}

// ProcessRPCEventsBySignature processes RPC events and automatically detects their signature for decoding
func ProcessRPCEventsBySignature(events []interface{}) error {
	for _, event := range events {
		eventMap := event.(map[string]interface{})

		// Convert topics to the expected format
		if topics, ok := eventMap["topics"].([]common.Hash); ok {
			topicsHex := make([]string, len(topics))
			for i, topic := range topics {
				topicsHex[i] = topic.Hex()
			}
			eventMap["topics"] = topicsHex
		}

		// Create a mock log for decoding (since we already have the raw log data)
		// We'll decode directly from the event data instead
		if topics, ok := eventMap["topics"].([]string); ok && len(topics) > 0 {
			// Get the event signature from the first topic
			eventSignature := topics[0]

			// Create a mock log with the topics and data
			var logTopics []common.Hash
			for _, topic := range topics {
				logTopics = append(logTopics, common.HexToHash(topic))
			}

			mockLog := types.Log{
				Topics: logTopics,
				Data:   eventMap["data"].([]byte),
			}

			var decoded map[string]interface{}
			var err error

			switch eventSignature {
			case TransferEventSignature:
				decoded, err = DecodeTransferEvent(mockLog)
			case OrderCreatedEventSignature:
				decoded, err = DecodeOrderCreatedEvent(mockLog)
			case OrderSettledEventSignature:
				decoded, err = DecodeOrderSettledEvent(mockLog)
			case OrderRefundedEventSignature:
				decoded, err = DecodeOrderRefundedEvent(mockLog)
			default:
				continue
			}

			if err != nil {
				return fmt.Errorf("failed to decode event: %w", err)
			}

			eventMap["decoded"] = decoded
		}
	}

	return nil
}
