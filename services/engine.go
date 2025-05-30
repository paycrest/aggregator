package services

import (
	"context"
	"fmt"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/utils"
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
		Auth().BearerToken(s.config.AccessToken).
		Header().AddAll(map[string]string{
		"Content-Type": "application/json",
	}).Build().POST("/backend-wallet/create").
		Body().AsJSON(map[string]interface{}{
		"label": label,
		"type":  "smart:local",
	}).Send()
	if err != nil {
		return "", fmt.Errorf("failed to create smart address: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return data["result"].(map[string]interface{})["walletAddress"].(string), nil
}

// GetLatestBlock fetches the latest block number for a given chain ID
func (s *EngineService) GetLatestBlock(ctx context.Context, chainID int64) (string, error) {
	res, err := fastshot.NewClient("https://insight.thirdweb.com").
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Content-Type": "application/json",
		"X-Secret-Key": s.config.ThirdwebSecretKey,
	}).Build().GET("/v1/blocks").
		Query().AddParams(map[string]string{
		"chain_id":   fmt.Sprintf("%d", chainID),
		"sort_order": "desc",
		"limit":      "1",
	}).Send()
	if err != nil {
		return "", fmt.Errorf("failed to get latest block: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %w", err)
	}

	if data["meta"].(map[string]interface{})["total_items"].(float64) == 0 {
		return "", fmt.Errorf("no block found")
	}

	return fmt.Sprintf("%.0f", data["data"].([]interface{})[0].(map[string]interface{})["block_number"].(float64)), nil
}

// GetContractEvents fetches contract events
func (s *EngineService) GetContractEvents(ctx context.Context, chainID int64, contractAddress string, payload map[string]interface{}) ([]interface{}, error) {
	res, err := fastshot.NewClient(s.config.BaseURL).
		Config().SetTimeout(30 * time.Second).
		Auth().BearerToken(s.config.AccessToken).
		Header().AddAll(map[string]string{
		"Content-Type": "application/json",
	}).Build().POST(fmt.Sprintf("/contract/%d/%s/events/get", chainID, contractAddress)).
		Body().AsJSON(payload).Send()
	if err != nil {
		return nil, fmt.Errorf("failed to get contract events: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return data["result"].([]interface{}), nil
}

// SendTransactionBatch sends a batch of transactions
func (s *EngineService) SendTransactionBatch(ctx context.Context, chainID int64, address string, txPayload []map[string]interface{}) (queueID string, err error) {
	res, err := fastshot.NewClient(s.config.BaseURL).
		Config().SetTimeout(30*time.Second).
		Auth().BearerToken(s.config.AccessToken).
		Header().Add("Accept", "application/json").
		Header().Add("Content-Type", "application/json").
		Header().Add("x-backend-wallet-address", address).
		Build().POST(fmt.Sprintf("/backend-wallet/%d/send-transaction-batch-atomic", chainID)).
		Body().AsJSON(map[string]interface{}{
		"transactions": txPayload,
	}).Send()
	if err != nil {
		return "", fmt.Errorf("failed to send transaction batch: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %w", err)
	}

	queueID = data["result"].(map[string]interface{})["queueId"].(string)

	return
}

// GetTransactionStatus gets the status of a transaction
func (s *EngineService) GetTransactionStatus(ctx context.Context, queueId string) (result map[string]interface{}, err error) {
	res, err := fastshot.NewClient(s.config.BaseURL).
		Config().SetTimeout(30*time.Second).
		Auth().BearerToken(s.config.AccessToken).
		Header().Add("Content-Type", "application/json").
		Build().GET(fmt.Sprintf("/transaction/status/%s", queueId)).Send()
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction status: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	result = data["result"].(map[string]interface{})

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

		if result["status"] == "mined" {
			return result, nil
		}

		elapsed := time.Since(start)
		if elapsed >= timeout {
			return nil, fmt.Errorf("transaction mining timeout after %v", timeout)
		}

		time.Sleep(2 * time.Second)
	}
}
