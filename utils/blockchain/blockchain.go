package blockchain

import (
	"fmt"
	"math/big"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/paycrest/aggregator/services/contracts"
)

// GetTokenBalance fetches token balance from blockchain RPC endpoint
func GetTokenBalance(rpcEndpoint string, tokenContractAddress string, walletAddress string) (*big.Int, error) {
	client, err := ethclient.Dial(rpcEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to create RPC client: %w", err)
	}
	defer client.Close()

	tokenContract, err := contracts.NewERC20Token(ethcommon.HexToAddress(tokenContractAddress), client)
	if err != nil {
		return nil, fmt.Errorf("failed to create token contract instance: %w", err)
	}

	balance, err := tokenContract.BalanceOf(nil, ethcommon.HexToAddress(walletAddress))
	if err != nil {
		return nil, fmt.Errorf("failed to get token balance: %w", err)
	}

	return balance, nil
}
