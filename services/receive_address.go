package services

import (
	"context"
	"fmt"

	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	tronWallet "github.com/paycrest/tron-wallet"
	tronEnums "github.com/paycrest/tron-wallet/enums"
	"github.com/paycrest/aggregator/services/starknet"
)

// ReceiveAddressService provides functionality related to managing receive addresses
type ReceiveAddressService struct {
	engineService *EngineService
	starknetClient *starknet.Client
}

// NewReceiveAddressService creates a new instance of ReceiveAddressService.
func NewReceiveAddressService() (*ReceiveAddressService, error) {
	ctx := context.Background()
	starknetClient, err := starknet.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewOrderStarknet: %w", err)
	}
	return &ReceiveAddressService{
		engineService: NewEngineService(),
		starknetClient: starknetClient,
	}, nil
}

// CreateSmartAddress function generates and saves a new EIP-4337 smart contract account address
func (s *ReceiveAddressService) CreateSmartAddress(ctx context.Context, label string) (string, error) {
	return s.engineService.CreateServerWallet(ctx, label)
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

// CreateStarknetAddress generates and saves a new Starknet address
func (s *ReceiveAddressService) CreateStarknetAddress(ctx context.Context) (string, []byte, error) {
	accountInfo, err := s.starknetClient.GenerateDeterministicAccount("")
	if err != nil {
		return "", nil, fmt.Errorf("CreateStarknetAddress: %w", err)
	}

	saltBytes := accountInfo.Salt.Bytes()
	return accountInfo.NewAccount.Address.String(), saltBytes[:], nil
}
