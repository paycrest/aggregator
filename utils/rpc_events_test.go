package utils

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeLocalTransferFeeSplitEvent(t *testing.T) {
	orderID := common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	senderAmount := big.NewInt(1_000_000)
	providerAmount := big.NewInt(2_000_000)
	aggregatorAmount := big.NewInt(3_000_000)
	data := make([]byte, 96)
	copy(data[0:32], common.LeftPadBytes(senderAmount.Bytes(), 32))
	copy(data[32:64], common.LeftPadBytes(providerAmount.Bytes(), 32))
	copy(data[64:96], common.LeftPadBytes(aggregatorAmount.Bytes(), 32))

	log := types.Log{
		Topics: []common.Hash{
			common.HexToHash(LocalTransferFeeSplitEventSignature),
			orderID,
		},
		Data: data,
	}

	decoded, err := DecodeLocalTransferFeeSplitEvent(log)
	require.NoError(t, err)
	idx := decoded["indexed_params"].(map[string]interface{})
	nidx := decoded["non_indexed_params"].(map[string]interface{})
	assert.Equal(t, orderID.Hex(), idx["orderId"])
	assert.Equal(t, "1000000", nidx["senderAmount"])
	assert.Equal(t, "2000000", nidx["providerAmount"])
	assert.Equal(t, "3000000", nidx["aggregatorAmount"])
}

func TestDecodeFxTransferFeeSplitEvent(t *testing.T) {
	orderID := common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	senderAmount := big.NewInt(1_000_000)
	aggregatorAmount := big.NewInt(3_000_000)
	data := make([]byte, 64)
	copy(data[0:32], common.LeftPadBytes(senderAmount.Bytes(), 32))
	copy(data[32:64], common.LeftPadBytes(aggregatorAmount.Bytes(), 32))

	log := types.Log{
		Topics: []common.Hash{
			common.HexToHash(FxTransferFeeSplitEventSignature),
			orderID,
		},
		Data: data,
	}

	decoded, err := DecodeFxTransferFeeSplitEvent(log)
	require.NoError(t, err)
	idx := decoded["indexed_params"].(map[string]interface{})
	nidx := decoded["non_indexed_params"].(map[string]interface{})
	assert.Equal(t, orderID.Hex(), idx["orderId"])
	assert.Equal(t, "1000000", nidx["senderAmount"])
	assert.Equal(t, "3000000", nidx["aggregatorAmount"])
}

func TestProcessRPCEventsBySignature_FeeEvents(t *testing.T) {
	orderID := common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	sa := big.NewInt(100)
	pa := big.NewInt(200)
	ag := big.NewInt(300)
	data := make([]byte, 96)
	copy(data[0:32], common.LeftPadBytes(sa.Bytes(), 32))
	copy(data[32:64], common.LeftPadBytes(pa.Bytes(), 32))
	copy(data[64:96], common.LeftPadBytes(ag.Bytes(), 32))

	events := []interface{}{
		map[string]interface{}{
			"topics":           []string{LocalTransferFeeSplitEventSignature, orderID.Hex()},
			"data":             data,
			"block_number":     float64(1),
			"transaction_hash": "0xtx1",
		},
	}
	err := ProcessRPCEventsBySignature(events)
	require.NoError(t, err)
	ev := events[0].(map[string]interface{})
	dec := ev["decoded"].(map[string]interface{})
	nidx := dec["non_indexed_params"].(map[string]interface{})
	assert.Equal(t, "300", nidx["aggregatorAmount"])
}
