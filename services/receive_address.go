package services

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/paycrest/aggregator/services/contracts"
	"github.com/paycrest/aggregator/types"
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
func (s *ReceiveAddressService) CreateSmartAddress(ctx context.Context, client types.RPCClient, factory *common.Address) (string, []byte, error) {

	// Connect to RPC endpoint
	var err error
	if client == nil {
		client, err = types.NewEthClient("https://mainnet.infura.io/v3/4818dbcee84d4651a832894818bd4534")
		if err != nil {
			return "", nil, fmt.Errorf("failed to connect to RPC client: %w", err)
		}
	}

	// Initialize contract factory
	if factory == nil {
		// https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/samples/SimpleAccountFactory.sol
		factoryAddress := common.HexToAddress("0x9406Cc6185a346906296840746125a0E44976454")
		factory = &factoryAddress
	}

	simpleAccountFactory, err := contracts.NewSimpleAccountFactory(*factory, client.(bind.ContractBackend))
	if err != nil {
		return "", nil, fmt.Errorf("failed to initialize factory contract: %w", err)
	}

	// Get master account
	ownerAddress, _, _ := cryptoUtils.GenerateAccountFromIndex(0)

	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	if err != nil {
		return "", nil, err
	}

	// Create a new big.Int from the hash
	salt := new(big.Int).SetBytes(nonce)

	// Generate address
	address, err := simpleAccountFactory.GetAddress(nil, *ownerAddress, salt)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate address: %w", err)
	}

	// Encrypt salt
	saltEncrypted, err := cryptoUtils.EncryptPlain([]byte(salt.String()))
	if err != nil {
		return "", nil, fmt.Errorf("failed to encrypt salt: %w", err)
	}

	return address.Hex(), saltEncrypted, nil
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
