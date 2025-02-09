package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

var streamConf = config.StreamConfig()


// StreamManager is an interface for managing streams
type StreamManager interface {
    // AddressStreamManager is an interface for managing address streams
    CreateAddressStream(ctx context.Context, network *ent.Network, order *ent.PaymentOrder, startRange int, endRange int) (string, error)
    UpdateAddressStream(ctx context.Context, streamID string, network *ent.Network, order *ent.PaymentOrder, startRange int, endRange int) error
    DeleteAddressStream(ctx context.Context, streamID string) error
	GetAddressStream(ctx context.Context, streamID string) (*types.StreamReturnPayload, error)
    
    // EventStreamManager is an interface for managing event streams
    // CreateContractEventStream(ctx context.Context, params types.StreamCreationParams) (string, error)
    // DeleteContractEventStream(ctx context.Context, streamID string) error
    // UpdateContractEventStream(ctx context.Context, streamID string, params types.StreamCreationParams) error
	// GetContractEventStream(ctx context.Context, streamID string) (*types.StreamReturnPayload, error)

	GetAllStreams(ctx context.Context) ([]*types.StreamReturnPayload, error)
}

// QuickNodeStreamManager is a service for managing streams using QuickNode
type QuickNodeStreamManager struct {
	streamManager StreamManager
}

// This function will need to be called everytime a new receive address is generated
func (q *QuickNodeStreamManager) CreateAddressStream(ctx context.Context, network *ent.Network, order *ent.PaymentOrder, startRange int, endRange int) (string, error) {
	params := types.StreamCreationParams{
		Name: "PaycrestAddressStream",
		Network: network.Identifier,
		Dataset: "receipts",
		// There will be need for Key-Value Store functions inside your Streams filter function so that it will be flexible enough to update the function with new addresses
		// when the response returns a new address that is on the watchlist, the update function will be called to remove the address from the watchlist
		// source: https://www.quicknode.com/docs/streams/filters#available-key-value-store-functions-inside-your-streams-filter
		// remeber, the data set is only the receipts.
		FilterFunction: "The filter function need to specifically listen to the reciept logs and only return the logs that are related to the address",
		Region: "usa_east",
		StartRange: startRange,
		EndRange: endRange,
		DatasetBatchSize: 2, // need to be verify to know how many transactions to fetch at a time
		IncludeStreamMetadata: "body",
		Status: "active",
		Destination: "webhook",
		DestinationAttributes: map[string]interface{}{
			"url": "webhook", // todo, set up a webhook to receive the data
			"compression": "none", // we don't want the data to be compressed
			// "headers": map[string]string{
			// 	"Content-Type":  "Test",
			// 	"Authorization": "again",
			// },
			"max_retry": 5,
			"retry_interval_sec": 1,
			"post_timeout_sec":   10,
		},
	}

    return q.createQuickNodeStream(ctx, params)
}


func (q *QuickNodeStreamManager) createQuickNodeStream(ctx context.Context, payload types.StreamCreationParams) (string, error) {
	// Convert payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("error marshaling payload: %w", err)
	}

	client := fastshot.NewClient(streamConf.QuickNodeAPIURL).
		Config().SetTimeout(30 * time.Second).
        Header().Add("accept", "application/json").
        Header().Add("Content-Type", "application/json").
        Header().Add("x-api-key", streamConf.QuickNodeAPIKey)

	// Execute POST request using FastShot
	res, err := client.Build().
		POST(streamConf.QuickNodeAPIURL).
		Body().AsJSON(jsonPayload).
		Retry().Set(3, 1*time.Second).
		Send()
	if err != nil {
		logger.Errorf("error sending request: %v", err)
		return "", fmt.Errorf("error sending request: %w", err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return "", fmt.Errorf("error parsing response: %w", err)
	}

	return data["id"].(string), nil
}