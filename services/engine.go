package services

import (
	"context"
	"fmt"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
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
	if err != nil {
		return 0, fmt.Errorf("failed to get latest block: %w", err)
	}

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
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
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

		time.Sleep(250 * time.Millisecond)
	}
}
