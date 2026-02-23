package indexer

import (
	"context"
	"fmt"
	"math/big"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	ethereumtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
)

// GetContractEventsRPC fetches contract events directly via RPC.
// It filters by event signatures (gateway or transfer events).
func GetContractEventsRPC(ctx context.Context, rpcEndpoint string, contractAddress string, fromBlock int64, toBlock int64, topics []string, txHash string) ([]interface{}, error) {
	client, err := types.NewEthClient(rpcEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to create RPC client: %w", err)
	}

	var eventSignatures []string
	if len(topics) > 0 && topics[0] == utils.TransferEventSignature {
		eventSignatures = []string{utils.TransferEventSignature}
	} else {
		eventSignatures = []string{
			utils.OrderCreatedEventSignature,
			utils.OrderSettledEventSignature,
			utils.OrderRefundedEventSignature,
		}
	}

	var logs []ethereumtypes.Log

	if txHash != "" {
		receipt, err := client.TransactionReceipt(ctx, common.HexToHash(txHash))
		if err != nil {
			return nil, fmt.Errorf("failed to get transaction receipt: %w", err)
		}

		for _, log := range receipt.Logs {
			if log.Address == common.HexToAddress(contractAddress) && len(log.Topics) > 0 {
				sig := log.Topics[0].Hex()
				for _, s := range eventSignatures {
					if sig == s {
						logs = append(logs, *log)
						break
					}
				}
			}
		}
	} else {
		if fromBlock == 0 || toBlock == 0 {
			return nil, fmt.Errorf("fromBlock and toBlock must be provided")
		} else if toBlock-fromBlock > 100 && eventSignatures[0] == utils.TransferEventSignature {
			return nil, fmt.Errorf("fromBlock and toBlock must be within 100 blocks for transfer events")
		} else if toBlock-fromBlock > 1000 && eventSignatures[0] != utils.TransferEventSignature {
			return nil, fmt.Errorf("fromBlock and toBlock must be within 1000 blocks for gateway events")
		}

		filterQuery := ethereum.FilterQuery{
			FromBlock: big.NewInt(fromBlock),
			ToBlock:   big.NewInt(toBlock),
			Addresses: []common.Address{common.HexToAddress(contractAddress)},
			Topics:    [][]common.Hash{},
		}

		for _, topic := range topics {
			if topic != "" {
				filterQuery.Topics = append(filterQuery.Topics, []common.Hash{common.HexToHash(topic)})
			}
		}

		allLogs, err := client.FilterLogs(ctx, filterQuery)
		if err != nil {
			return nil, fmt.Errorf("failed to get logs: %w", err)
		}

		for _, log := range allLogs {
			if len(log.Topics) > 0 {
				sig := log.Topics[0].Hex()
				for _, s := range eventSignatures {
					if sig == s {
						logs = append(logs, log)
						break
					}
				}
			}
		}
	}

	var events []interface{}
	for _, log := range logs {
		event := map[string]interface{}{
			"block_number":     float64(log.BlockNumber),
			"transaction_hash": log.TxHash.Hex(),
			"log_index":        float64(log.Index),
			"address":          log.Address.Hex(),
			"topics":           log.Topics,
			"data":             log.Data,
			"decoded": map[string]interface{}{
				"indexed_params":     make(map[string]interface{}),
				"non_indexed_params": make(map[string]interface{}),
			},
		}
		events = append(events, event)
	}

	if len(events) > 0 {
		if err := utils.ProcessRPCEventsBySignature(events); err != nil {
			return nil, fmt.Errorf("failed to process RPC events: %w", err)
		}
	}

	return events, nil
}
