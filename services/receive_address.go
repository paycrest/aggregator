package services

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/paycrest/aggregator/services/starknet"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	tronWallet "github.com/paycrest/tron-wallet"
	tronEnums "github.com/paycrest/tron-wallet/enums"
)

// ReceiveAddressService provides functionality related to managing receive addresses
type ReceiveAddressService struct {
	starknetClient *starknet.Client
	engineService  *EngineService
}

// NewReceiveAddressService creates a new instance of ReceiveAddressService.
// engineService can be nil when not used (e.g. index controller); required for thirdweb mode in sender.
func NewReceiveAddressService(engineService *EngineService) *ReceiveAddressService {
	return &ReceiveAddressService{
		engineService: engineService,
	}
}

// CreateSmartAddress returns (address, saltOrNil, error).
// thirdweb: uses EngineService.CreateServerWallet; no salt.
// self_sponsored: generates EOA locally, encrypts key as salt.
func (s *ReceiveAddressService) CreateSmartAddress(ctx context.Context, label string, mode string) (string, []byte, error) {
	switch mode {
	case "thirdweb":
		if s.engineService == nil {
			return "", nil, fmt.Errorf("engine service required for thirdweb mode")
		}
		address, err := s.engineService.CreateServerWallet(ctx, label)
		if err != nil {
			return "", nil, err
		}
		return address, nil, nil
	case "self_sponsored":
		privateKey, err := crypto.GenerateKey()
		if err != nil {
			return "", nil, fmt.Errorf("failed to generate EOA key: %w", err)
		}
		address := crypto.PubkeyToAddress(privateKey.PublicKey)
		privateKeyHex := hex.EncodeToString(crypto.FromECDSA(privateKey))
		salt, err := cryptoUtils.EncryptPlain([]byte(privateKeyHex))
		if err != nil {
			return "", nil, fmt.Errorf("failed to encrypt salt: %w", err)
		}
		return address.Hex(), salt, nil
	default:
		return "", nil, fmt.Errorf("unsupported sponsorship_mode: %s", mode)
	}
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
func (s *ReceiveAddressService) CreateStarknetAddress(client *starknet.Client) (string, []byte, error) {
	// Generate a secure random seed
	seed, err := cryptoUtils.GenerateSecureSeed()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	// Generate deterministic account from the seed
	accountInfo, err := client.GenerateDeterministicAccount(seed)
	if err != nil {
		return "", nil, fmt.Errorf("CreateStarknetAddress: %w", err)
	}

	seedWithSuffix := fmt.Sprintf("%s-paycrest", seed)
	saltEncrypted, err := cryptoUtils.EncryptPlain([]byte(seedWithSuffix))
	if err != nil {
		return "", nil, fmt.Errorf("failed to encrypt salt: %w", err)
	}
	return cryptoUtils.NormalizeStarknetAddress(accountInfo.NewAccount.Address.String()), saltEncrypted, nil
}

