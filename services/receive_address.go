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
}

// NewReceiveAddressService creates a new instance of ReceiveAddressService.
func NewReceiveAddressService() *ReceiveAddressService {
	return &ReceiveAddressService{}
}

// CreateSmartAddress generates a fresh EOA and returns its address + encrypted private key as salt.
func (s *ReceiveAddressService) CreateSmartAddress() (string, []byte, error) {
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

