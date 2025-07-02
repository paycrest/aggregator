package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/storage"
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

// Example usage:
//
// 1. Create a transfer webhook for a specific token contract:
//    webhookID, webhookSecret, err := engineService.CreateTransferWebhook(
//        ctx,
//        137, // Polygon chain ID
//        "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619", // WETH contract address
//        "0x1234567890123456789012345678901234567890"  // To address to monitor
//    )
//
// 2. Create gateway webhooks for all supported chains:
//    webhookID, webhookSecret, err := engineService.CreateGatewayWebhook(ctx)
//
// 3. Set up all webhooks for the environment:
//    err := engineService.SetupWebhooksForEnvironment(ctx)

// CreateTransferWebhook creates a webhook to listen to transfer events to a specific address on a specific chain
func (s *EngineService) CreateTransferWebhook(ctx context.Context, chainID int64, contractAddress string, toAddress string) (string, string, error) {
	webhookCallbackURL := fmt.Sprintf("%s/v1/insight/webhook", config.ServerConfig().ServerURL)

	webhookPayload := map[string]interface{}{
		"name":         fmt.Sprintf("Transfer Webhook - %s", contractAddress),
		"endpoint_url": webhookCallbackURL,
		"filters": map[string]interface{}{
			"v1.events": map[string]interface{}{
				"chain_ids":        []int64{chainID},
				"addresses":        []string{contractAddress},
				"event_signatures": []string{"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"}, // Transfer event signature
				"params": map[string]interface{}{
					"to": toAddress, // Filter for transfers to the specific address
				},
			},
		},
	}

	res, err := fastshot.NewClient(fmt.Sprintf("https://%d.insight.thirdweb.com", chainID)).
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"X-Secret-Key": s.config.ThirdwebSecretKey,
	}).Build().POST("/v1/webhooks").
		Body().AsJSON(webhookPayload).Send()

	if err != nil {
		return "", "", fmt.Errorf("failed to create transfer webhook: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse JSON response: %w", err)
	}

	webhookID := data["id"].(string)
	webhookSecret := data["webhook_secret"].(string)

	return webhookID, webhookSecret, nil
}

// CreateGatewayWebhook creates webhooks for gateway contract events across all supported chains for the environment
func (s *EngineService) CreateGatewayWebhook(ctx context.Context) (string, string, error) {
	serverConf := config.ServerConfig()

	// Check if server URL is configured
	if serverConf.ServerURL == "" {
		logger.WithFields(logger.Fields{
			"Environment": serverConf.Environment,
		}).Errorf("SERVER_URL not configured in environment")
		return "", "", fmt.Errorf("SERVER_URL not configured in environment")
	}

	// Determine if we're in testnet or mainnet
	isTestnet := false
	if serverConf.Environment != "production" {
		isTestnet = true
	}

	// Fetch networks for the current environment
	networks, err := storage.Client.Network.
		Query().
		Where(networkent.IsTestnet(isTestnet)).
		All(ctx)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch networks: %w", err)
	}

	// Event signatures for gateway contract events (using hash-like signatures from EVM indexer)
	eventSignatures := []string{
		"0x40ccd1ceb111a3c186ef9911e1b876dc1f789ed331b86097b3b8851055b6a137", // OrderCreated
		"0x98ece21e01a01cbe1d1c0dad3b053c8fbd368f99be78be958fcf1d1d13fd249a", // OrderSettled
		"0x0736fe428e1747ca8d387c2e6fa1a31a0cde62d3a167c40a46ade59a3cdc828e", // OrderRefunded
	}

	// Collect all chain IDs and gateway addresses
	var chainIDs []int64
	var gatewayAddresses []string

	for _, network := range networks {
		// Skip Tron networks as they don't use EVM webhooks
		if strings.HasPrefix(network.Identifier, "tron") {
			continue
		}
		chainIDs = append(chainIDs, network.ChainID)
		gatewayAddresses = append(gatewayAddresses, network.GatewayContractAddress)
	}

	if len(chainIDs) == 0 {
		logger.Infof("No EVM networks found for webhook creation")
		return "", "", nil
	}

	// Create callback URL for gateway events
	webhookCallbackURL := fmt.Sprintf("%s/v1/insight/webhook", serverConf.ServerURL)

	// Use the first chain ID for the base URL (since we need a specific chain URL)
	baseChainID := chainIDs[0]

	webhookPayload := map[string]interface{}{
		"name":         "Gateway Contract Events Webhook",
		"endpoint_url": webhookCallbackURL,
		"filters": map[string]interface{}{
			"v1.events": map[string]interface{}{
				"chain_ids":        chainIDs,
				"addresses":        gatewayAddresses,
				"event_signatures": eventSignatures,
			},
		},
	}

	res, err := fastshot.NewClient(fmt.Sprintf("https://%d.insight.thirdweb.com", baseChainID)).
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"X-Secret-Key": s.config.ThirdwebSecretKey,
	}).Build().POST("/v1/webhooks").
		Body().AsJSON(webhookPayload).Send()

	if err != nil {
		return "", "", fmt.Errorf("failed to create gateway webhooks: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse JSON response: %w", err)
	}

	webhookID := data["id"].(string)
	webhookSecret := data["webhook_secret"].(string)

	logger.WithFields(logger.Fields{
		"WebhookID":        webhookID,
		"ChainIDs":         chainIDs,
		"GatewayAddresses": gatewayAddresses,
		"EventSignatures":  eventSignatures,
		"CallbackURL":      webhookCallbackURL,
	}).Infof("Created gateway webhooks successfully")

	return webhookID, webhookSecret, nil
}

// SetupWebhooksForEnvironment sets up all necessary webhooks for the current environment
// This function demonstrates how to use the webhook creation functions
func (s *EngineService) SetupWebhooksForEnvironment(ctx context.Context) error {
	// Check if server URL is configured
	if config.ServerConfig().ServerURL == "" {
		return fmt.Errorf("SERVER_URL not configured in environment")
	}

	// Create gateway webhooks for all supported chains
	webhookID, webhookSecret, err := s.CreateGatewayWebhook(ctx)
	if err != nil {
		return fmt.Errorf("failed to create gateway webhooks: %w", err)
	}

	logger.WithFields(logger.Fields{
		"Environment":        config.ServerConfig().Environment,
		"WebhookCallbackURL": fmt.Sprintf("%s/v1/insight/webhook", config.ServerConfig().ServerURL),
		"WebhookID":          webhookID,
		"WebhookSecret":      webhookSecret,
	}).Infof("Successfully set up webhooks for environment")

	return nil
}
