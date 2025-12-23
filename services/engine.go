package services

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	ethereumtypes "github.com/ethereum/go-ethereum/core/types"
	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentwebhook"
	"github.com/paycrest/aggregator/storage"
	types "github.com/paycrest/aggregator/types"
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
	// TODO: Remove once thirdweb insight supports BSC and Lisk
	if chainID != 56 && chainID != 1135 {
		// Try ThirdWeb first for all networks
		res, err := fastshot.NewClient(fmt.Sprintf("https://%d.insight.thirdweb.com", chainID)).
			Config().SetTimeout(60 * time.Second).
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
	client, err := types.NewEthClient(network.RPCEndpoint)
	if err != nil {
		return 0, fmt.Errorf("failed to create RPC client: %w", err)
	}

	header, err := client.HeaderByNumber(ctx, nil) // nil means latest block
	if err != nil {
		return 0, fmt.Errorf("failed to get latest block from RPC: %w", err)
	}

	return header.Number.Int64(), nil
}

// GetContractEvents fetches contract events
func (s *EngineService) GetContractEvents(ctx context.Context, chainID int64, contractAddress string, payload map[string]string) ([]interface{}, error) {
	res, err := fastshot.NewClient(fmt.Sprintf("https://%d.insight.thirdweb.com", chainID)).
		Config().SetTimeout(60 * time.Second).
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
		Config().SetTimeout(60 * time.Second).
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
//        "0x1234567890123456789012345678901234567890", // To address to monitor
//        "order-uuid-here" // Order ID for webhook name
//    )
//
// 2. Create gateway webhooks for all supported chains:
//    webhookID, webhookSecret, err := engineService.CreateGatewayWebhook(ctx)
//
// 3. Set up all webhooks for the environment:
//    err := engineService.SetupWebhooksForEnvironment(ctx)
//
// 4. Delete a webhook from thirdweb:
//    err := engineService.DeleteWebhook(ctx, "webhook_id_here")
//
// 5. Delete a webhook from thirdweb and remove the record from database:
//    err := engineService.DeleteWebhookAndRecord(ctx, "webhook_id_here")

// CreateTransferWebhook creates webhooks to listen to transfer events to a specific address on a specific chain
func (s *EngineService) CreateTransferWebhook(ctx context.Context, chainID int64, contractAddress string, toAddress string, orderID string) (string, string, error) {
	// Check if this is BNB Smart Chain (chain ID 56) or Lisk (chain ID 1135) - not supported by Thirdweb Insight
	if chainID == 56 || chainID == 1135 {
		return "", "", fmt.Errorf("webhook creation not supported for BNB Smart Chain (chain ID 56) or Lisk (chain ID 1135) via Thirdweb API")
	}

	webhookCallbackURL := fmt.Sprintf("%s/v1/insight/webhook", config.ServerConfig().ServerURL)

	webhookPayload := map[string]interface{}{
		"name":        orderID,
		"webhook_url": webhookCallbackURL,
		"filters": map[string]interface{}{
			"v1.events": map[string]interface{}{
				"chain_ids": []string{strconv.FormatInt(chainID, 10)},
				"addresses": []string{contractAddress},
				"signatures": []map[string]interface{}{
					{
						"sig_hash": "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", // Transfer event signature
						"abi":      "{\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"from\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"to\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"Transfer\",\"type\":\"event\"}",
						"params": map[string]interface{}{
							"to": toAddress, // Filter for transfers to the specific address
						},
					},
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

	// Handle nested data structure
	responseData, ok := data["data"].(map[string]interface{})
	if !ok {
		return "", "", fmt.Errorf("invalid response structure: missing 'data' field")
	}

	webhookID, ok := responseData["id"].(string)
	if !ok {
		return "", "", fmt.Errorf("invalid response structure: missing or invalid 'id' field")
	}

	webhookSecret, ok := responseData["webhook_secret"].(string)
	if !ok {
		return "", "", fmt.Errorf("invalid response structure: missing or invalid 'webhook_secret' field")
	}

	return webhookID, webhookSecret, nil
}

// DeleteWebhook deletes a webhook by its ID
func (s *EngineService) DeleteWebhook(ctx context.Context, webhookID string) error {
	res, err := fastshot.NewClient("https://insight.thirdweb.com").
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"X-Secret-Key": s.config.ThirdwebSecretKey,
	}).Build().DELETE(fmt.Sprintf("/v1/webhooks/%s", webhookID)).
		Send()
	if err != nil {
		return fmt.Errorf("failed to delete webhook: %w", err)
	}

	// Check if the response indicates success
	if res.StatusCode() != 200 && res.StatusCode() != 204 {
		return fmt.Errorf("failed to delete webhook: HTTP %d", res.StatusCode())
	}

	return nil
}

// DeleteWebhookAndRecord deletes a webhook from thirdweb and removes the PaymentWebhook record from our database
func (s *EngineService) DeleteWebhookAndRecord(ctx context.Context, webhookID string) error {
	// First, delete the webhook from thirdweb
	err := s.DeleteWebhook(ctx, webhookID)
	if err != nil {
		return fmt.Errorf("failed to delete webhook from thirdweb: %w", err)
	}

	// Then, delete the PaymentWebhook record from our database
	_, err = storage.Client.PaymentWebhook.
		Delete().
		Where(paymentwebhook.WebhookIDEQ(webhookID)).
		Exec(ctx)
	if err != nil {
		logger.Errorf("Failed to delete PaymentWebhook record from database: %v", err)
		// Don't fail the entire operation if database deletion fails
		// The webhook is already deleted from thirdweb
	}

	return nil
}

// WebhookInfo represents a webhook from thirdweb API
type WebhookInfo struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	WebhookURL    string                 `json:"webhook_url"`
	WebhookSecret string                 `json:"webhook_secret"`
	Disabled      bool                   `json:"disabled"`
	CreatedAt     string                 `json:"created_at"`
	UpdatedAt     string                 `json:"updated_at"`
	ProjectID     string                 `json:"project_id"`
	Filters       map[string]interface{} `json:"filters"`
}

// WebhookListResponse represents the response from GET /v1/webhooks
type WebhookListResponse struct {
	Data []WebhookInfo `json:"data"`
	Meta struct {
		Page       int `json:"page"`
		Limit      int `json:"limit"`
		TotalItems int `json:"total_items"`
		TotalPages int `json:"total_pages"`
	} `json:"meta"`
}

// GetWebhookByID fetches a webhook by its ID from thirdweb
func (s *EngineService) GetWebhookByID(ctx context.Context, webhookID string, chainID int64) (*WebhookInfo, error) {
	res, err := fastshot.NewClient(fmt.Sprintf("https://%d.insight.thirdweb.com", chainID)).
		Config().SetTimeout(60 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"X-Secret-Key": s.config.ThirdwebSecretKey,
	}).Build().GET("/v1/webhooks").
		Query().AddParams(map[string]string{
		"webhook_id": webhookID,
	}).Send()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch webhook: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse webhook response: %w", err)
	}

	// Parse the response data
	responseData := data["data"].([]interface{})
	if len(responseData) == 0 {
		return nil, fmt.Errorf("webhook not found")
	}

	webhookData := responseData[0].(map[string]interface{})
	webhookInfo := &WebhookInfo{
		ID:            webhookData["id"].(string),
		Name:          webhookData["name"].(string),
		WebhookURL:    webhookData["webhook_url"].(string),
		WebhookSecret: webhookData["webhook_secret"].(string),
		Disabled:      webhookData["disabled"].(bool),
		CreatedAt:     webhookData["created_at"].(string),
		UpdatedAt:     webhookData["updated_at"].(string),
		ProjectID:     webhookData["project_id"].(string),
		Filters:       webhookData["filters"].(map[string]interface{}),
	}

	return webhookInfo, nil
}

// UpdateWebhook updates an existing webhook with new filters
func (s *EngineService) UpdateWebhook(ctx context.Context, webhookID string, webhookPayload map[string]interface{}) error {
	res, err := fastshot.NewClient("https://insight.thirdweb.com").
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"X-Secret-Key": s.config.ThirdwebSecretKey,
	}).Build().PATCH(fmt.Sprintf("/v1/webhooks/%s", webhookID)).
		Body().AsJSON(webhookPayload).Send()
	if err != nil {
		return fmt.Errorf("failed to update webhook: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Data":       data,
			"StatusCode": res.RawResponse.StatusCode,
		}).Errorf("failed to parse JSON response: %v", err)
		return fmt.Errorf("failed to parse JSON response: %v", err)
	}

	return nil
}

// CreateGatewayWebhook creates webhooks for gateway contract events across all supported chains for the environment
func (s *EngineService) CreateGatewayWebhook() error {
	ctx := context.Background()
	serverConf := config.ServerConfig()

	// Check if server URL is configured
	if serverConf.ServerURL == "" {
		logger.WithFields(logger.Fields{
			"Environment": serverConf.Environment,
		}).Errorf("SERVER_URL not configured in environment")
		return fmt.Errorf("SERVER_URL not configured in environment")
	}

	// Fetch networks for the current environment
	networks, err := storage.Client.Network.
		Query().
		Where(networkent.ChainIDNotIn(56, 1135)).
		All(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch networks: %w", err)
	}

	// Event signatures for gateway contract events (using hash-like signatures from EVM indexer)
	eventSignatures := []map[string]interface{}{
		{
			"sig_hash": "0x40ccd1ceb111a3c186ef9911e1b876dc1f789ed331b86097b3b8851055b6a137", // OrderCreated event signature
			"abi":      "{\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"token\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"protocolFee\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"rate\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"string\",\"name\":\"messageHash\",\"type\":\"string\"}],\"name\":\"OrderCreated\",\"type\":\"event\"}",
		},
		{
			"sig_hash": "0x57c683de2e7c8263c7f57fd108416b9bdaa7a6e7f2e4e7102c3b6f9e37f1cc37", // OrderSettled event signature
			"abi":      "{\"inputs\":[{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"splitOrderId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"liquidityProvider\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint64\",\"name\":\"settlePercent\",\"type\":\"uint64\"},{\"indexed\":false,\"internalType\":\"uint64\",\"name\":\"rebatePercent\",\"type\":\"uint64\"}],\"name\":\"OrderSettled\",\"type\":\"event\"}",
		},
		{
			"sig_hash": "0x0736fe428e1747ca8d387c2e6fa1a31a0cde62d3a167c40a46ade59a3cdc828e", // OrderRefunded event signature
			"abi":      "{\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"fee\",\"type\":\"uint256\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"orderId\",\"type\":\"bytes32\"}],\"name\":\"OrderRefunded\",\"type\":\"event\"}",
		},
	}

	// Collect all chain IDs and gateway addresses
	var chainIDs []int64
	var chainIDsStrings []string
	var gatewayAddresses []string
	var evmNetworks []*ent.Network

	for _, network := range networks {
		// Skip Tron networks as they don't use EVM webhooks
		if strings.HasPrefix(network.Identifier, "tron") {
			continue
		}
		chainIDs = append(chainIDs, network.ChainID)
		chainIDsStrings = append(chainIDsStrings, strconv.FormatInt(network.ChainID, 10))
		gatewayAddresses = append(gatewayAddresses, network.GatewayContractAddress)
		evmNetworks = append(evmNetworks, network)
	}

	if len(chainIDs) == 0 {
		logger.Infof("No EVM networks found for webhook creation")
		return nil
	}

	// Check if any EVM network has an associated PaymentWebhook
	var existingWebhookID string
	var existingWebhookSecret string

	for _, network := range evmNetworks {
		paymentWebhook, err := storage.Client.PaymentWebhook.
			Query().
			Where(paymentwebhook.HasNetworkWith(networkent.IDEQ(network.ID))).
			Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				// No webhook for this network - continue checking others
				continue
			} else {
				// Real database error - log and return
				logger.Errorf("Database error checking webhook for network %s: %v", network.Identifier, err)
				return fmt.Errorf("failed to check existing webhooks: %w", err)
			}
		}

		// Found an existing webhook
		existingWebhookID = paymentWebhook.WebhookID
		existingWebhookSecret = paymentWebhook.WebhookSecret
		break
	}

	// Create callback URL for gateway events
	webhookCallbackURL := fmt.Sprintf("%s/v1/insight/webhook", serverConf.ServerURL)

	if existingWebhookID != "" {
		// Fetch the existing webhook from thirdweb
		webhookInfo, err := s.GetWebhookByID(ctx, existingWebhookID, evmNetworks[0].ChainID)
		if err != nil {
			logger.WithFields(logger.Fields{
				"WebhookID": existingWebhookID,
				"ChainID":   evmNetworks[0].ChainID,
			}).Errorf("Failed to fetch existing webhook: %v", err)
			// Continue with creating a new webhook
		} else {
			// Check if the webhook filters match our current chain IDs
			filters, ok := webhookInfo.Filters["v1.events"].(map[string]interface{})
			if ok {
				existingChainIDs, ok := filters["chain_ids"].([]interface{})
				if ok {
					// Convert existing chain IDs to int64 for comparison
					var existingChainIDsInt64 []int64
					for _, chainID := range existingChainIDs {
						if chainIDFloat, ok := chainID.(float64); ok {
							existingChainIDsInt64 = append(existingChainIDsInt64, int64(chainIDFloat))
						}
					}

					// Check if all our chain IDs are in the existing webhook
					allChainsIncluded := true
					for _, chainID := range chainIDs {
						found := false
						for _, existingChainID := range existingChainIDsInt64 {
							if chainID == existingChainID {
								found = true
								break
							}
						}
						if !found {
							allChainsIncluded = false
							break
						}
					}

					if allChainsIncluded {
						// Perfect match - no update needed
						logger.WithFields(logger.Fields{
							"WebhookID": existingWebhookID,
							"ChainIDs":  chainIDs,
						}).Infof("Gateway webhook already exists and includes all required chains")
						return nil
					}
				}
			}

			// Update the webhook with new chain IDs
			webhookPayload := map[string]interface{}{
				"webhook_url": webhookCallbackURL,
				"filters": map[string]interface{}{
					"v1.events": map[string]interface{}{
						"chain_ids":  chainIDsStrings,
						"addresses":  gatewayAddresses,
						"signatures": eventSignatures,
					},
				},
			}

			err = s.UpdateWebhook(ctx, existingWebhookID, webhookPayload)
			if err != nil {
				logger.Errorf("Failed to update webhook %s: %v", existingWebhookID, err)
				// Continue with creating a new webhook
			} else {
				// Update successful, now update all PaymentWebhook records
				for _, network := range evmNetworks {
					// Delete existing PaymentWebhook for this network, if any
					_, err = storage.Client.PaymentWebhook.Delete().
						Where(paymentwebhook.HasNetworkWith(networkent.IDEQ(network.ID))).
						Exec(ctx)
					if err != nil {
						logger.Errorf("Failed to delete existing PaymentWebhook for network %s: %v", network.Identifier, err)
						continue
					}

					// Create new PaymentWebhook with updated webhook info
					_, err = storage.Client.PaymentWebhook.Create().
						SetWebhookID(existingWebhookID).
						SetWebhookSecret(existingWebhookSecret).
						SetCallbackURL(webhookCallbackURL).
						SetNetwork(network).
						Save(ctx)
					if err != nil {
						logger.Errorf("Failed to create PaymentWebhook for network %s: %v", network.Identifier, err)
						continue
					}
				}

				logger.WithFields(logger.Fields{
					"WebhookID":        existingWebhookID,
					"ChainIDs":         chainIDs,
					"GatewayAddresses": gatewayAddresses,
					"EventSignatures":  eventSignatures,
					"CallbackURL":      webhookCallbackURL,
					"NetworksCount":    len(chainIDs),
				}).Infof("Updated gateway webhook successfully")

				return nil
			}
		}
	}

	// No existing webhook found or update failed, create a new one
	webhookPayload := map[string]interface{}{
		"name":        "Gateway Contract Events Webhook",
		"webhook_url": webhookCallbackURL,
		"filters": map[string]interface{}{
			"v1.events": map[string]interface{}{
				"chain_ids":  chainIDsStrings,
				"addresses":  gatewayAddresses,
				"signatures": eventSignatures,
			},
		},
	}

	res, err := fastshot.NewClient("https://insight.thirdweb.com").
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"X-Secret-Key": s.config.ThirdwebSecretKey,
	}).Build().POST("/v1/webhooks").
		Body().AsJSON(webhookPayload).Send()

	if err != nil {
		return fmt.Errorf("failed to create gateway webhooks: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Data":       data,
			"ChainIDs":   chainIDsStrings,
			"StatusCode": res.RawResponse.StatusCode,
		}).Errorf("failed to parse JSON response: %v", err)
		return fmt.Errorf("failed to parse JSON response: %v", err)
	}

	// Parse webhook data from response - handle nested data structure
	responseData, ok := data["data"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid response structure: missing 'data' field")
	}

	webhookID, ok := responseData["id"].(string)
	if !ok {
		return fmt.Errorf("invalid response structure: missing or invalid 'id' field")
	}

	webhookSecret, ok := responseData["webhook_secret"].(string)
	if !ok {
		return fmt.Errorf("invalid response structure: missing or invalid 'webhook_secret' field")
	}

	// Create PaymentWebhook records for all EVM networks
	for _, network := range evmNetworks {
		// Delete existing PaymentWebhook for this network, if any
		_, err = storage.Client.PaymentWebhook.Delete().
			Where(paymentwebhook.HasNetworkWith(networkent.IDEQ(network.ID))).
			Exec(ctx)
		if err != nil {
			logger.Errorf("Failed to delete existing PaymentWebhook for network %s: %v", network.Identifier, err)
			continue
		}

		// Create new PaymentWebhook
		_, err = storage.Client.PaymentWebhook.Create().
			SetWebhookID(webhookID).
			SetWebhookSecret(webhookSecret).
			SetCallbackURL(webhookCallbackURL).
			SetNetwork(network).
			Save(ctx)
		if err != nil {
			logger.Errorf("Failed to create PaymentWebhook for network %s: %v", network.Identifier, err)
			continue
		}
	}

	logger.WithFields(logger.Fields{
		"WebhookID":        webhookID,
		"ChainIDs":         chainIDs,
		"GatewayAddresses": gatewayAddresses,
		"EventSignatures":  eventSignatures,
		"CallbackURL":      webhookCallbackURL,
		"NetworksCount":    len(chainIDs),
	}).Infof("Created gateway webhooks successfully")

	return nil
}

// GetContractEventsRPC fetches contract events using RPC for networks not supported by Thirdweb Insight
// It fetches all events and filters for specified event signatures (gateway events or transfer events)
func (s *EngineService) GetContractEventsRPC(ctx context.Context, rpcEndpoint string, contractAddress string, fromBlock int64, toBlock int64, topics []string, txHash string) ([]interface{}, error) {
	// Create RPC client
	client, err := types.NewEthClient(rpcEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to create RPC client: %w", err)
	}

	var logs []ethereumtypes.Log

	// Determine which event signatures to filter for based on topics
	var eventSignatures []string
	if len(topics) > 0 && topics[0] == utils.TransferEventSignature {
		// If transfer event signature is provided, filter for transfer events
		eventSignatures = []string{utils.TransferEventSignature}
	} else {
		// Default to gateway event signatures
		eventSignatures = []string{
			utils.OrderCreatedEventSignature,
			utils.OrderSettledEventSignature,
			utils.OrderRefundedEventSignature,
		}
	}

	if txHash != "" {
		// If transaction hash is provided, get the specific transaction receipt
		receipt, err := client.TransactionReceipt(ctx, common.HexToHash(txHash))
		if err != nil {
			return nil, fmt.Errorf("failed to get transaction receipt: %w", err)
		}

		// Filter logs from the receipt that match the specified event signatures
		for _, log := range receipt.Logs {
			if log.Address == common.HexToAddress(contractAddress) {
				// Check if this log matches any of our event signatures
				if len(log.Topics) > 0 {
					eventSignature := log.Topics[0].Hex()
					for _, signature := range eventSignatures {
						if eventSignature == signature {
							logs = append(logs, *log)
							break
						}
					}
				}
			}
		}
	} else {
		if fromBlock == 0 || toBlock == 0 {
			return nil, fmt.Errorf("fromBlock and toBlock must be provided")
		} else if fromBlock-toBlock > 100 && eventSignatures[0] == utils.TransferEventSignature {
			return nil, fmt.Errorf("fromBlock and toBlock must be within 100 blocks for transfer events")
		} else if fromBlock-toBlock > 1000 && eventSignatures[0] != utils.TransferEventSignature {
			return nil, fmt.Errorf("fromBlock and toBlock must be within 1000 blocks for gateway events")
		}

		// Use block range filtering to get all logs from the contract
		filterQuery := ethereum.FilterQuery{
			FromBlock: big.NewInt(fromBlock),
			ToBlock:   big.NewInt(toBlock),
			Addresses: []common.Address{common.HexToAddress(contractAddress)},
			Topics:    [][]common.Hash{},
		}

		// Add additional topics if provided
		for _, topic := range topics {
			if topic != "" {
				filterQuery.Topics = append(filterQuery.Topics, []common.Hash{common.HexToHash(topic)})
			}
		}

		// Get all logs from the contract
		allLogs, err2 := client.FilterLogs(ctx, filterQuery)
		if err2 != nil {
			return nil, fmt.Errorf("failed to get logs: %w", err2)
		}

		// Filter for the specified event signatures
		for _, log := range allLogs {
			if len(log.Topics) > 0 {
				eventSignature := log.Topics[0].Hex()
				for _, signature := range eventSignatures {
					if eventSignature == signature {
						logs = append(logs, log)
						break
					}
				}
			}
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

	// Decode events based on their signatures
	if len(events) > 0 {
		err = utils.ProcessRPCEventsBySignature(events)
		if err != nil {
			return nil, fmt.Errorf("failed to process RPC events: %w", err)
		}
	}

	return events, nil
}

// GetAddressTransactionHistory fetches transaction history for any address from thirdweb insight API
func (s *EngineService) GetAddressTransactionHistory(ctx context.Context, chainID int64, walletAddress string, limit int, fromBlock int64, toBlock int64) ([]map[string]interface{}, error) {
	// Check if this is BNB Smart Chain (chain ID 56) or Linea (chain ID 1135) - not supported by Thirdweb Insight
	if chainID == 56 || chainID == 1135 {
		return nil, fmt.Errorf("transaction history not supported for BNB Smart Chain (chain ID 56) or Lisk (chain ID 1135) via Thirdweb API")
	}

	// Build query parameters
	params := map[string]string{
		"limit": fmt.Sprintf("%d", limit),
	}

	// Add block range filtering if specified
	if fromBlock > 0 {
		params["filter_block_number_gte"] = fmt.Sprintf("%d", fromBlock)
	}
	if toBlock > 0 {
		params["filter_block_number_lte"] = fmt.Sprintf("%d", toBlock)
	}

	res, err := fastshot.NewClient(fmt.Sprintf("https://%d.insight.thirdweb.com", chainID)).
		Config().SetTimeout(60 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"X-Secret-Key": s.config.ThirdwebSecretKey,
	}).Build().GET(fmt.Sprintf("/v1/wallets/%s/transactions", walletAddress)).
		Query().AddParams(params).Send()
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction history: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w %v", err, data)
	}

	if data["data"] == nil {
		return []map[string]interface{}{}, nil
	}

	transactions := data["data"].([]interface{})
	result := make([]map[string]interface{}, len(transactions))

	for i, tx := range transactions {
		result[i] = tx.(map[string]interface{})
	}

	return result, nil
}

// GetContractEventsWithFallback tries RPC first and falls back to ThirdWeb if RPC fails
func (s *EngineService) GetContractEventsWithFallback(ctx context.Context, network *ent.Network, contractAddress string, fromBlock int64, toBlock int64, topics []string, txHash string, eventPayload map[string]string) ([]interface{}, error) {
	// Try RPC first
	events, rpcErr := s.GetContractEventsRPC(ctx, network.RPCEndpoint, contractAddress, fromBlock, toBlock, topics, txHash)
	if rpcErr == nil {
		return events, nil
	}

	// If RPC fails, try ThirdWeb (except for BSC and Lisk)
	if network.ChainID != 56 && network.ChainID != 1135 {
		events, thirdwebErr := s.GetContractEvents(ctx, network.ChainID, contractAddress, eventPayload)
		if thirdwebErr == nil {
			return events, nil
		}
		logger.WithFields(logger.Fields{
			"Network":       network.Identifier,
			"ChainID":       network.ChainID,
			"Contract":      contractAddress,
			"ThirdWebError": thirdwebErr.Error(),
			"FallbackToRPC": false,
		}).Errorf("Both RPC and ThirdWeb failed")
		return nil, fmt.Errorf("both RPC and ThirdWeb failed - RPC: %w, ThirdWeb: %w", rpcErr, thirdwebErr)
	}

	return nil, fmt.Errorf("both RPC and ThirdWeb failed - RPC: %w", rpcErr)
}

// TransferToken transfers ERC-20 tokens using Thirdweb Engine API
func (s *EngineService) TransferToken(ctx context.Context, chainID int64, fromAddress string, toAddress string, tokenAddress string, amount string, idempotencyKey string) (queueID string, err error) {
	if tokenAddress == "" {
		return "", fmt.Errorf("tokenAddress is required for ERC-20 transfers")
	}

	// ERC-20 transfer function ABI
	transferABI := `[
		{
			"inputs": [
				{"internalType": "address", "name": "to", "type": "address"},
				{"internalType": "uint256", "name": "amount", "type": "uint256"}
			],
			"name": "transfer",
			"outputs": [
				{"internalType": "bool", "name": "", "type": "bool"}
			],
			"stateMutability": "nonpayable",
			"type": "function"
		}
	]`

	// Prepare the contract call parameters
	contractParams := map[string]interface{}{
		"contractAddress": tokenAddress,
		"method":         "transfer",
		"params":         []interface{}{toAddress, amount},
		"abi":            transferABI,
		"value":          "0", // No ETH value for ERC-20 transfers
	}

	// Prepare execution options
	executionOptions := map[string]interface{}{
		"chainId":         fmt.Sprintf("%d", chainID),
		"idempotencyKey":  idempotencyKey,
		"from":            fromAddress,
		"type":            "auto",
	}

	// Prepare the request payload
	payload := map[string]interface{}{
		"executionOptions": executionOptions,
		"params":           []map[string]interface{}{contractParams},
		"webhookOptions":   []interface{}{}, // No webhook
	}

	res, err := fastshot.NewClient(s.config.BaseURL).
		Config().SetTimeout(60 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":               "application/json",
		"Content-Type":         "application/json",
		"x-vault-access-token": s.config.AccessToken,
		"X-Secret-Key":         s.config.ThirdwebSecretKey,
	}).Build().POST("/v1/write/contract").
		Body().AsJSON(payload).Send()
	if err != nil {
		return "", fmt.Errorf("failed to execute token transfer: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %w", err)
	}

	// Extract queue ID from response
	if result, ok := data["result"].(map[string]interface{}); ok {
		if transactions, ok := result["transactions"].([]interface{}); ok && len(transactions) > 0 {
			if tx, ok := transactions[0].(map[string]interface{}); ok {
				if id, ok := tx["id"].(string); ok {
					return id, nil
				}
			}
		}
	}

	return "", fmt.Errorf("failed to extract queue ID from response")
}

// ParseUserOpErrorJSON parses a UserOperation error JSON and returns the decoded error string
func (s *EngineService) ParseUserOpErrorJSON(errorJSON map[string]interface{}) string {
	// Extract the error object if it's nested
	errorData, ok := errorJSON["error"].(map[string]interface{})
	if !ok {
		// If not nested, use the input directly
		errorData = errorJSON
	}

	// Extract inner error details
	if innerError, ok := errorData["inner_error"].(map[string]interface{}); ok {
		if kind, ok := innerError["kind"].(map[string]interface{}); ok {
			if body, ok := kind["body"].(string); ok {
				// Extract and decode the hex-encoded revert reason
				return s.extractAndDecodeRevertReason(body)
			}
		}
	}

	return "Unknown error"
}

// SendContractCall sends a contract call using ThirdWeb's /v1/write/contract endpoint
func (s *EngineService) SendContractCall(ctx context.Context, chainID int64, fromAddress string, contractAddress string, method string, params []interface{}) (queueID string, err error) {
	res, err := fastshot.NewClient(s.config.BaseURL).
		Config().SetTimeout(30 * time.Second).
		Header().AddAll(map[string]string{
		"Accept":               "application/json",
		"Content-Type":         "application/json",
		"x-vault-access-token": s.config.AccessToken,
		"X-Secret-Key":         s.config.ThirdwebSecretKey,
	}).
		Build().POST("/v1/write/contract").
		Body().AsJSON(map[string]interface{}{
		"executionOptions": map[string]interface{}{
			"chainId": fmt.Sprintf("%d", chainID),
			"from":    fromAddress,
			"type":    "auto",
		},
		"params": []map[string]interface{}{
			{
				"contractAddress": contractAddress,
				"method":          method,
				"params":          params,
			},
		},
	}).Send()
	if err != nil {
		return "", fmt.Errorf("failed to send contract call: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %w", err)
	}

	// Extract result field
	result, ok := data["result"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid response structure: missing or invalid 'result' field")
	}

	transactionsRaw, ok := result["transactions"].([]interface{})
	if !ok {
		return "", fmt.Errorf("invalid response structure: missing or invalid 'transactions' field")
	}

	if len(transactionsRaw) == 0 {
		return "", fmt.Errorf("invalid response structure: empty 'transactions' array")
	}

	firstTransaction, ok := transactionsRaw[0].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid response structure: invalid transaction object")
	}

	queueID, ok = firstTransaction["id"].(string)
	if !ok {
		return "", fmt.Errorf("invalid response structure: missing or invalid 'id' field")
	}

	return queueID, nil
}

// extractAndDecodeRevertReason extracts the hex-encoded revert reason from the error message and decodes it
func (s *EngineService) extractAndDecodeRevertReason(errorBody string) string {
	// Regular expression to find the hex-encoded revert reason
	// This looks for the pattern that starts with 0x08c379a0 (Error(string) selector)
	// and captures the hex string that follows
	re := regexp.MustCompile(`0x08c379a0[0-9a-fA-F]+`)
	matches := re.FindString(errorBody)

	if matches == "" {
		return "Unknown revert reason"
	}

	// Remove the function selector (0x08c379a0) and decode the rest
	hexData := strings.TrimPrefix(matches, "0x08c379a0")

	// The hex data contains:
	// - 32 bytes for offset (first 64 hex chars)
	// - 32 bytes for length (next 64 hex chars)
	// - The actual string data (remaining hex chars)

	if len(hexData) < 128 {
		return "Invalid hex data length"
	}

	// Skip the offset and length, get the actual string data
	stringDataHex := hexData[128:]

	// Decode the hex string
	decodedBytes, err := hex.DecodeString(stringDataHex)
	if err != nil {
		return fmt.Sprintf("Failed to decode hex: %v", err)
	}

	// Convert bytes to string, removing null bytes
	decodedString := strings.TrimRight(string(decodedBytes), "\x00")

	return decodedString
}
