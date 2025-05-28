package services

import (
	"context"
	"fmt"
	"time"

	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/utils"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	tronWallet "github.com/paycrest/tron-wallet"
	tronEnums "github.com/paycrest/tron-wallet/enums"
)

// ReceiveAddressService provides functionality related to managing receive addresses
type ReceiveAddressService struct{}

// NewReceiveAddressService creates a new instance of ReceiveAddressService.
func NewReceiveAddressService() *ReceiveAddressService {
	return &ReceiveAddressService{}
}

// CreateSmartAddress function generates and saves a new EIP-4337 smart contract account address
func (s *ReceiveAddressService) CreateSmartAddress(ctx context.Context, label string) (string, error) {
	engineConf := config.EngineConfig()

	res, err := fastshot.NewClient(engineConf.BaseURL).
		Config().SetTimeout(15 * time.Second).
		Auth().BearerToken(engineConf.AccessToken).
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

// CreateTronAddress generates and saves a new Tron address
func (s *ReceiveAddressService) CreateTronAddress(ctx context.Context) (string, []byte, error) {
	var nodeUrl tronEnums.Node
	if serverConf.Environment == "production" {
		nodeUrl = tronEnums.MAIN_NODE
	} else {
		nodeUrl = tronEnums.SHASTA_NODE
	}

	// Generate a new Tron address
	wallet := tronWallet.GenerateTronWallet(nodeUrl)

	// Encrypt private key
	privateKeyEncrypted, err := cryptoUtils.EncryptPlain([]byte(wallet.PrivateKey))
	if err != nil {
		return "", nil, fmt.Errorf("failed to encrypt salt: %w", err)
	}

	return wallet.AddressBase58, privateKeyEncrypted, nil
}
