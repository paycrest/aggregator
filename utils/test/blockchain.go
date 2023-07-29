package test

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/paycrest/paycrest-protocol/types"
	cryptoUtils "github.com/paycrest/paycrest-protocol/utils/crypto"

	"github.com/paycrest/paycrest-protocol/services/contracts"
)

// SimulatedBackend extends the backends.SimulatedBackend struct.
type SimulatedBackend struct {
	*backends.SimulatedBackend
}

// SendTransaction sends a transaction to the simulated backend and commits the state.
func (s *SimulatedBackend) SendTransaction(ctx context.Context, tx *ethTypes.Transaction) error {
	if err := s.SimulatedBackend.SendTransaction(ctx, tx); err != nil {
		return err
	}
	s.Commit()
	return nil
}

// NewSimulatedBlockchain creates a new instance of SimulatedBackend and returns it.
func NewSimulatedBlockchain() (*SimulatedBackend, error) {
	// Generate a private key for the simulated blockchain
	_, privateKey, _ := getMasterAccount()

	// Create a new transactor using the generated private key
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
	if err != nil {
		return nil, err
	}

	// Set the balance for the transactor's address
	balance := new(big.Int)
	balance.SetString("10000000000000000000", 10) // 10 eth in wei

	// Set the genesis account with the transactor's address and balance
	address := auth.From
	genesisAlloc := map[common.Address]core.GenesisAccount{
		address: {
			Balance: balance,
		},
	}

	// Set the block gas limit
	blockGasLimit := uint64(4712388)

	// Create a new simulated backend using the genesis allocation and block gas limit
	client := &SimulatedBackend{backends.NewSimulatedBackend(genesisAlloc, blockGasLimit)}

	client.Commit()

	return client, nil
}

// deployERC20Contract deploys an ERC20 contract with the provided parameters.
// It returns the address of the deployed contract, the transaction object for the deployment,
// an instance of the deployed contract, and any error that occurred.
func DeployERC20Contract(client types.RPCClient) (*common.Address, error) {
	// Prepare the deployment
	auth, err := prepareDeployment(client)
	if err != nil {
		return nil, err
	}

	initialSupply := new(big.Int)
	initialSupply.SetString("200000000", 10)

	// Deploy the contract
	address, _, _, err := contracts.DeployTestToken(auth, client.(bind.ContractBackend), initialSupply)
	if err != nil {
		return nil, err
	}

	client.Commit()

	return &address, nil
}

func DeployEIP4337FactoryContract(client types.RPCClient) (*common.Address, error) {
	// Prepare the deployment
	auth, err := prepareDeployment(client)
	if err != nil {
		return nil, err
	}

	// Deploy the contract
	address, _, _, err := contracts.DeploySimpleAccountFactory(
		auth, client.(bind.ContractBackend), common.HexToAddress("0x0000000"))
	if err != nil {
		return nil, err
	}

	client.Commit()

	return &address, nil
}

// FundAddressWithTestToken funds an amount of a test ERC20 token from the owner account
func FundAddressWithTestToken(token common.Address, amount *big.Int, address common.Address) error {
	// Create a new simulated blockchain
	backend, err := NewSimulatedBlockchain()
	if err != nil {
		return err
	}

	// Get master private key
	_, privateKeyHex, _ := cryptoUtils.GenerateAccountFromIndex(0)

	privateKeyBytes, err := hexutil.Decode(privateKeyHex)
	if err != nil {
		return err
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return err
	}

	// Create a new instance of the TestToken contract
	testToken, err := contracts.NewTestToken(token, backend)
	if err != nil {
		return err
	}

	auth, _ := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))

	// Transfer test token to the address
	tx, err := testToken.Transfer(auth, address, amount)
	if err != nil {
		return err
	}

	receipt, err := bind.WaitMined(context.Background(), backend, tx)
	if err != nil {
		return err
	}

	fmt.Println(receipt.TxHash.String())

	return nil
}

// prepareDeployment prepares the deployment of a contract.
func prepareDeployment(client types.RPCClient) (*bind.TransactOpts, error) {
	// Get master account
	fromAddress, privateKey, _ := getMasterAccount()

	// Configure the transaction
	ctx := context.Background()

	nonce, err := client.PendingNonceAt(ctx, *fromAddress)
	if err != nil {
		return nil, err
	}

	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, err
	}

	auth, _ := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))

	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)     // in wei
	auth.GasLimit = uint64(400000) // in units
	auth.GasPrice = gasPrice

	return auth, nil
}

// getMasterAccount returns the master account address and private key.
func getMasterAccount() (*common.Address, *ecdsa.PrivateKey, error) {
	fromAddress, privateKeyHex, err := cryptoUtils.GenerateAccountFromIndex(0)
	if err != nil {
		return nil, nil, err
	}

	address := common.HexToAddress(fromAddress)

	privateKeyBytes, err := hexutil.Decode(privateKeyHex)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	return &address, privateKey, nil
}
