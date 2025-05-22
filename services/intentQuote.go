package services

import (
	"fmt"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/types"

	u "github.com/paycrest/aggregator/utils"
	intentUtils "github.com/paycrest/aggregator/utils/intent"
	"github.com/paycrest/aggregator/utils/logger"
)

type ClickDefuseService struct {
	OneclickURL   string
	OneclickAuth string
}

func NewClickDefuseService(url, authorization string) *ClickDefuseService {
	return &ClickDefuseService{
		OneclickURL:   url,
		OneclickAuth: authorization,
	}
}

func (s *ClickDefuseService) GetIntentQuote(networkIdentifierFrom, recipient, refund, amount string, slippage int) (*types.QuoteResponse, error) {
	if s.OneclickURL == "" {
		logger.Errorf("Oneclick URL is not set")
		return nil, fmt.Errorf("oneclick URL is not set")
	} 

    originAssets, err := intentUtils.GetAssetsByNetworkID(networkIdentifierFrom)
    if err != nil {
        logger.WithFields(logger.Fields{
            "error":            fmt.Sprintf("Failed to get origin assets: %v", err),
            "networkIdentifier": networkIdentifierFrom,
        }).Error("Failed to get origin assets")
        return nil, fmt.Errorf("failed to get origin assets: %w", err)
    }

    // Get assets for destination network
    destinationAsset := intentUtils.GetDestinationAssetsByNetworkID()

	deadline := time.Now().Add(5 * time.Minute).Format(time.RFC3339)

	// Construct the JSON body
	payload := map[string]interface{}{
		"dry":               false,
		"swapType":          "EXACT_INPUT",
		"slippageTolerance": slippage,
		"originAsset":       originAssets.AssetID,
		"depositType":       "ORIGIN_CHAIN",
		"destinationAsset":  destinationAsset,
		"amount":            amount,
		"refundTo":          refund,
		"refundType":        "ORIGIN_CHAIN",
		"recipient":         recipient,
		"recipientType":     "DESTINATION_CHAIN",
		"deadline":          deadline,
		"referral":          "referral",
		"quoteWaitingTimeMs": 3000,
	}

	res, err := fastshot.NewClient(s.OneclickURL).
		Config().SetTimeout(30*time.Second).
		Header().Add("Authorization", fmt.Sprintf("Bearer %s", s.OneclickAuth)).
		Header().Add("Content-Type", "application/json").
		Build().POST("/quote").
		Body().AsJSON(payload).
		Send()

	if err != nil {
		logger.WithFields(logger.Fields{
			"error": fmt.Sprintf("Failed to send intent quote request: %v", err),
			"From Chain": originAssets.AssetID,
			"To Chain": destinationAsset,
			"deadline": deadline,
		}).Error("failed to send intent quote request")
		return nil, fmt.Errorf("failed to send intent quote request: %w", err)
	}

	quoteResponse, err := u.ParseJSONResponse(res.RawResponse)
	if err != nil {
		logger.WithFields(logger.Fields{
			"error": fmt.Sprintf("Failed to parse JSON response: %v", err),
			"From Chain": originAssets.AssetID,
			"To Chain": destinationAsset,
		}).Error("Failed to parse JSON response")
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	quoteData, ok := quoteResponse["quote"].(map[string]interface{})
    if !ok {
        err := fmt.Errorf("invalid or missing 'quote' field in response")
        logger.WithFields(logger.Fields{
            "error": err,
        }).Error("Failed to extract quote data")
        return nil, err
    }
	extractedQuoteResponse := &types.QuoteResponse{}

	extractedQuoteResponse.DepositAddress = quoteData["depositAddress"].(string)
	extractedQuoteResponse.AmountOut = quoteData["amountOut"].(string)
	extractedQuoteResponse.MinAmountOut = quoteData["minAmountOut"].(string)
	extractedQuoteResponse.AmountInUsd = quoteData["amountInUsd"].(string)
	extractedQuoteResponse.Deadline = quoteData["deadline"].(string)

	return extractedQuoteResponse, nil
}
