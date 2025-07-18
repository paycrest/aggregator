package services

import (
	"context"
	"fmt"
	"math/big"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	types "github.com/ethereum/go-ethereum/core/types"
	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/storage"
	aggregatortypes "github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

// EngineService provides functionality for interacting with the engine/thirdweb API
type EngineService struct {
	config *config.EngineConfiguration
}

// NewEngineService creates a new instance of EngineService
func NewEngineService() *EngineService {
	return &EngineService{
		config: config.EngineConfig(),
	}
}

// CreateServerWallet creates a new EIP-4337 smart contract account address
func (s *EngineService) CreateServerWallet(ctx context.Context, label string) (string, error) {
	res, err := fastshot.NewClient(s.config.BaseURL).
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"X-Secret-Key": s.config.ThirdwebSecretKey,
	}).Build().POST("/v1/accounts").
		Body().AsJSON(map[string]interface{}{
		"label": label,
	}).Send()
	if err != nil {
		return "", fmt.Errorf("failed to create smart address: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return data["result"].(map[string]interface{})["smartAccountAddress"].(string), nil
}

// GetLatestBlock fetches the latest block number for a given chain ID
func (s *EngineService) GetLatestBlock(ctx context.Context, chainID int64) (int64, error) {
	// TODO: Remove once thirdweb insight supports BSC
	if chainID != 56 {
		// Try ThirdWeb first for all networks
		res, err := fastshot.NewClient(fmt.Sprintf("https://%d.insight.thirdweb.com", chainID)).
			Config().SetTimeout(30 * time.Second).
			Header().AddAll(map[string]string{
			"Content-Type": "application/json",
			"X-Secret-Key": s.config.ThirdwebSecretKey,
		}).Build().GET("/v1/blocks").
			Query().AddParams(map[string]string{
			"sort_order": "desc",
			"limit":      "1",
		}).Send()
		if err == nil {
			// ThirdWeb succeeded
			data, err := utils.ParseJSONResponse(res.RawResponse)
			if err != nil {
				return 0, fmt.Errorf("failed to parse JSON response: %w", err)
			}

			if data["meta"].(map[string]interface{})["total_items"].(float64) == 0 {
				return 0, fmt.Errorf("no block found")
			}

			blockNumber := int64(data["data"].([]interface{})[0].(map[string]interface{})["block_number"].(float64))
			return blockNumber, nil
		}

		// ThirdWeb failed, try RPC as fallback
		logger.WithFields(logger.Fields{
			"ChainID":       chainID,
			"ThirdWebError": err.Error(),
			"FallbackToRPC": true,
		}).Warnf("ThirdWeb failed, falling back to RPC for latest block")
	}

	// Fetch network from database to get RPC endpoint
	network, err := storage.Client.Network.
		Query().
		Where(networkent.ChainIDEQ(chainID)).
		Only(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch network from database: %w", err)
	}

	// Use RPC as fallback
	client, err := aggregatortypes.NewEthClient(network.RPCEndpoint)
	if err != nil {
		return 0, fmt.Errorf("failed to create RPC client: %w", err)
	}

	header, err := client.HeaderByNumber(ctx, nil) // nil means latest block
	if err != nil {
		return 0, fmt.Errorf("failed to get latest block from RPC: %w", err)
	}

	logger.WithFields(logger.Fields{
		"ChainID":      chainID,
		"BlockNumber":  header.Number.Int64(),
		"FallbackUsed": true,
	}).Infof("RPC fallback succeeded for latest block")

	return header.Number.Int64(), nil
}

// GetContractEvents fetches contract events
func (s *EngineService) GetContractEvents(ctx context.Context, chainID int64, contractAddress string, payload map[string]string) ([]interface{}, error) {
	res, err := fastshot.NewClient(fmt.Sprintf("https://%d.insight.thirdweb.com", chainID)).
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"X-Secret-Key": s.config.ThirdwebSecretKey,
	}).Build().GET(fmt.Sprintf("/v1/events/%s", contractAddress)).
		Query().AddParams(payload).Send()
	if err != nil {
		return nil, fmt.Errorf("failed to get contract events: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w %v", err, data)
	}

	if data["meta"].(map[string]interface{})["total_items"].(float64) == 0 {
		return nil, fmt.Errorf("no events found")
	}

	return data["data"].([]interface{}), nil
}

// SendTransactionBatch sends a batch of transactions
func (s *EngineService) SendTransactionBatch(ctx context.Context, chainID int64, address string, txPayload []map[string]interface{}) (queueID string, err error) {
	res, err := fastshot.NewClient(s.config.BaseURL).
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":               "application/json",
		"Content-Type":         "application/json",
		"x-vault-access-token": s.config.AccessToken,
		"X-Secret-Key":         s.config.ThirdwebSecretKey,
	}).
		Build().POST("/v1/write/transaction").
		Body().AsJSON(map[string]interface{}{
		"params": txPayload,
		"executionOptions": map[string]string{
			"chainId": fmt.Sprintf("%d", chainID),
			"from":    address,
		},
	}).Send()
	if err != nil {
		return "", fmt.Errorf("failed to send transaction batch: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %w", err)
	}

	queueID = data["result"].(map[string]interface{})["transactions"].([]interface{})[0].(map[string]interface{})["id"].(string)

	return
}

// GetTransactionStatus gets the status of a transaction
func (s *EngineService) GetTransactionStatus(ctx context.Context, queueId string) (result map[string]interface{}, err error) {
	res, err := fastshot.NewClient(s.config.BaseURL).
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":               "application/json",
		"Content-Type":         "application/json",
		"x-vault-access-token": s.config.AccessToken,
		"X-Secret-Key":         s.config.ThirdwebSecretKey,
	}).
		Build().POST("/v1/transactions/search").
		Body().AsJSON(map[string]interface{}{
		"filters": []map[string]interface{}{
			{
				"field":     "id",
				"values":    []string{queueId},
				"operation": "OR",
			},
		},
	}).Send()
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction status: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	if data["result"].(map[string]interface{})["transactions"] == nil {
		return nil, fmt.Errorf("no transactions found")
	}

	if len(data["result"].(map[string]interface{})["transactions"].([]interface{})) > 0 {
		result = data["result"].(map[string]interface{})["transactions"].([]interface{})[0].(map[string]interface{})
	}

	return
}

// WaitForTransactionMined waits for a transaction to be mined
func (s *EngineService) WaitForTransactionMined(ctx context.Context, queueId string, timeout time.Duration) (result map[string]interface{}, err error) {
	start := time.Now()
	for {
		result, err := s.GetTransactionStatus(ctx, queueId)
		if err != nil {
			return nil, err
		}

		if result["executionResult"] == nil || result["from"] == nil {
			continue
		}

		if result["executionResult"].(map[string]interface{})["status"].(string) == "CONFIRMED" && result["transactionHash"] != nil {
			return result, nil
		} else if result["executionResult"].(map[string]interface{})["status"].(string) == "FAILED" {
			logger.WithFields(logger.Fields{
				"QueueId": queueId,
				"From":    result["from"].(string),
				"Error":   result["executionResult"].(map[string]interface{})["error"],
			}).Errorf("Transaction failed: %v", result["executionResult"].(map[string]interface{})["error"])
			return nil, fmt.Errorf("transaction failed: %v", result["executionResult"].(map[string]interface{})["error"])
		}

		elapsed := time.Since(start)
		if elapsed >= timeout {
			return nil, fmt.Errorf("transaction mining timeout after %v", timeout)
		}

		time.Sleep(time.Second)
	}
}

// GetContractEventsRPC fetches contract events using RPC for networks not supported by Thirdweb Insight
func (s *EngineService) GetContractEventsRPC(ctx context.Context, rpcEndpoint string, contractAddress string, fromBlock int64, toBlock int64, eventSignature string, topics []string, txHash string) ([]interface{}, error) {
	// Create RPC client
	client, err := aggregatortypes.NewEthClient(rpcEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to create RPC client: %w", err)
	}

	var logs []types.Log
	var err2 error

	if txHash != "" {
		// If transaction hash is provided, get the specific transaction receipt
		receipt, err := client.TransactionReceipt(ctx, common.HexToHash(txHash))
		if err != nil {
			return nil, fmt.Errorf("failed to get transaction receipt: %w", err)
		}

		// Filter logs from the receipt that match our criteria
		for _, log := range receipt.Logs {
			if log.Address == common.HexToAddress(contractAddress) {
				// Check if this log matches our event signature
				if len(log.Topics) > 0 && log.Topics[0].Hex() == eventSignature {
					// Check additional topics if provided
					matches := true
					for i, topic := range topics {
						if topic != "" && (i+1 >= len(log.Topics) || log.Topics[i+1].Hex() != topic) {
							matches = false
							break
						}
					}
					if matches {
						logs = append(logs, *log)
					}
				}
			}
		}
	} else {
		// Use block range filtering (existing logic)
		// Build filter query
		filterQuery := ethereum.FilterQuery{
			FromBlock: big.NewInt(fromBlock),
			ToBlock:   big.NewInt(toBlock),
			Addresses: []common.Address{common.HexToAddress(contractAddress)},
			Topics:    [][]common.Hash{},
		}

		// Add event signature as first topic
		if eventSignature != "" {
			filterQuery.Topics = append(filterQuery.Topics, []common.Hash{common.HexToHash(eventSignature)})
		}

		// Add additional topics if provided
		for _, topic := range topics {
			if topic != "" {
				filterQuery.Topics = append(filterQuery.Topics, []common.Hash{common.HexToHash(topic)})
			}
		}

		// Get logs
		logs, err2 = client.FilterLogs(ctx, filterQuery)
		if err2 != nil {
			return nil, fmt.Errorf("failed to get logs: %w", err2)
		}
	}

	// Convert logs to the same format as Thirdweb Insight
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

	// Decode events based on signature
	if len(events) > 0 {
		err = utils.ProcessRPCEvents(events, eventSignature)
		if err != nil {
			return nil, fmt.Errorf("failed to process RPC events: %w", err)
		}
	}

	return events, nil
}

// GetContractEventsWithFallback tries ThirdWeb first and falls back to RPC if ThirdWeb fails
func (s *EngineService) GetContractEventsWithFallback(ctx context.Context, network *ent.Network, contractAddress string, fromBlock int64, toBlock int64, eventSignature string, topics []string, txHash string, eventPayload map[string]string) ([]interface{}, error) {
	var err error
	
	// TODO: Remove once thirdweb insight supports BSC
	if network.ChainID != 56 {
		// Try ThirdWeb first
		events, err := s.GetContractEvents(ctx, network.ChainID, contractAddress, eventPayload)
		if err == nil {
			// ThirdWeb succeeded, return the events
			return events, nil
		}
	}

	// Try RPC as fallback
	events, rpcErr := s.GetContractEventsRPC(ctx, network.RPCEndpoint, contractAddress, fromBlock, toBlock, eventSignature, topics, txHash)
	if rpcErr != nil {
		// Both ThirdWeb and RPC failed
		logger.WithFields(logger.Fields{
			"Network":       network.Identifier,
			"ChainID":       network.ChainID,
			"Contract":      contractAddress,
			"RPCError":      rpcErr.Error(),
		}).Errorf("Both ThirdWeb and RPC failed")
		return nil, fmt.Errorf("both ThirdWeb and RPC failed - ThirdWeb: %w, RPC: %w", err, rpcErr)
	}

	return events, nil
}
