package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"encoding/hex"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/shopspring/decimal"

	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/services/contracts"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	"github.com/stackup-wallet/stackup-bundler/pkg/userop"
)

var (
	fromAddress, privateKey, _ = cryptoUtils.GenerateAccountFromIndex(0)
	orderConf                  = config.OrderConfig()
	engineConf                 = config.EngineConfig()
)

// Initialize user operation with defaults
func InitializeUserOperation(ctx context.Context, client types.RPCClient, rpcUrl, sender, salt string) (*userop.UserOperation, error) {
	var err error

	// Connect to RPC endpoint
	if client == nil {
		retryErr := Retry(3, 5*time.Second, func() error {
			client, err = types.NewEthClient(rpcUrl)
			return err
		})
		if retryErr != nil {
			return nil, fmt.Errorf("failed to connect to RPC client: %w", err)
		}
	}

	// Build user operation
	userOperation := &userop.UserOperation{
		Sender:               common.HexToAddress(sender),
		Nonce:                big.NewInt(0),
		InitCode:             common.FromHex("0x"),
		CallData:             common.FromHex("0x"),
		CallGasLimit:         big.NewInt(350000),
		VerificationGasLimit: big.NewInt(300000),
		PreVerificationGas:   big.NewInt(100000),
		MaxFeePerGas:         big.NewInt(50000),
		MaxPriorityFeePerGas: big.NewInt(1000),
		PaymasterAndData:     common.FromHex("0x"),
		Signature:            common.FromHex("0xa925dcc5e5131636e244d4405334c25f034ebdd85c0cb12e8cdb13c15249c2d466d0bade18e2cafd3513497f7f968dcbb63e519acd9b76dcae7acd61f11aa8421b"),
	}

	// Get nonce
	nonce, err := getNonce(client, userOperation.Sender)
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce: %w", err)
	}
	userOperation.Nonce = nonce

	// Create initcode
	code, err := client.CodeAt(ctx, userOperation.Sender, nil)
	if err != nil {
		return nil, err
	}

	if len(code) == 0 {
		// address does not exist yet
		salt, _ := new(big.Int).SetString(salt, 10)

		createAccountCallData, err := createAccountCallData(*fromAddress, salt)
		if err != nil {
			return nil, fmt.Errorf("failed to create init code: %w", err)
		}

		var factoryAddress [20]byte
		copy(factoryAddress[:], common.HexToAddress("0x9406Cc6185a346906296840746125a0E44976454").Bytes())

		userOperation.InitCode = append(factoryAddress[:], createAccountCallData...)
	}

	// Set gas fees
	maxFeePerGas, maxPriorityFeePerGas, err := eip1559GasPrice(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to get gas price: %w", err)
	}

	userOperation.MaxFeePerGas = maxFeePerGas
	userOperation.MaxPriorityFeePerGas = maxPriorityFeePerGas

	return userOperation, nil
}

// SponsorUserOperation sponsors the user operation with different AA services
func SponsorUserOperation(userOp *userop.UserOperation, mode string, token string, chainId int64) error {

	_, paymasterUrl, err := getEndpoints(chainId)
	if err != nil {
		return fmt.Errorf("failed to get endpoints for chain ID %d: %w", chainId, err)
	}

	client, err := rpc.Dial(paymasterUrl)
	if err != nil {
		return fmt.Errorf("failed to connect to RPC client: %w", err)
	}

	aaService, err := detectAAService(paymasterUrl)
	if err != nil {
		return fmt.Errorf("invalid AA service URL pattern: %w", err)
	}

	var payload map[string]interface{}
	var requestParams []interface{}
	method := "pm_sponsorUserOperation"
	userOpExpanded := map[string]interface{}{
		"sender":               userOp.Sender.Hex(),
		"nonce":                userOp.Nonce.String(),
		"initCode":             hexutil.Encode(userOp.InitCode),
		"callData":             hexutil.Encode(userOp.CallData),
		"callGasLimit":         userOp.CallGasLimit.String(),
		"verificationGasLimit": userOp.VerificationGasLimit.String(),
		"preVerificationGas":   userOp.PreVerificationGas.String(),
		"maxFeePerGas":         userOp.MaxFeePerGas.String(),
		"maxPriorityFeePerGas": userOp.MaxPriorityFeePerGas.String(),
		"paymasterAndData":     hexutil.Encode(userOp.PaymasterAndData),
		"signature":            hexutil.Encode(userOp.Signature),
	}

	switch aaService {
	case "biconomy":
		switch mode {
		case "sponsored":
			payload = map[string]interface{}{
				"mode": "SPONSORED",
				"sponsorshipInfo": map[string]interface{}{
					"webhookData": map[string]interface{}{},
					"smartAccountInfo": map[string]string{
						"name":    "INFINITISM",
						"version": "1.0.0",
					},
				},
				"expiryDuration":     300,
				"calculateGasLimits": true,
			}
		case "erc20":
			if token == "" {
				return fmt.Errorf("token address is required")
			}
			payload = map[string]interface{}{
				"mode": "ERC20",
				"tokenInfo": map[string]string{
					"feeTokenAddress": token,
				},
				"calculateGasLimits": true,
			}
		default:
			return fmt.Errorf("invalid mode")
		}

		requestParams = []interface{}{
			userOpExpanded,
			payload,
		}

	case "thirdweb":
		maxFeePerGas, maxPriorityFeePerGas, err := getStandardGasPrices(chainId)
		if err == nil {
			userOp.MaxFeePerGas = maxFeePerGas
			userOp.MaxPriorityFeePerGas = maxPriorityFeePerGas
		} else if chainId == 137 {
			// increase maxFeePerGas and maxPriorityFeePerGas by 50%
			userOp.MaxFeePerGas = new(big.Int).Div(
				new(big.Int).Mul(userOp.MaxFeePerGas, big.NewInt(150)),
				big.NewInt(100),
			)
			userOp.MaxPriorityFeePerGas = new(big.Int).Div(
				new(big.Int).Mul(userOp.MaxPriorityFeePerGas, big.NewInt(150)),
				big.NewInt(100),
			)
		}

		httpClient := &http.Client{
			Transport: &http.Transport{},
		}
		header := http.Header{}
		header.Set("x-secret-key", engineConf.ThirdwebSecretKey)

		client, err = rpc.DialOptions(
			context.Background(),
			paymasterUrl,
			rpc.WithHTTPClient(httpClient),
			rpc.WithHeaders(header),
		)
		if err != nil {
			return fmt.Errorf("failed to connect to RPC client: %w", err)
		}

		requestParams = []interface{}{
			userOp,
			orderConf.EntryPointContractAddress.Hex(),
		}
	default:
		return fmt.Errorf("unsupported AA service: %s", aaService)
	}

	var result json.RawMessage
	err = client.Call(&result, method, requestParams...)
	if err != nil {
		op, _ := userOp.MarshalJSON()
		return fmt.Errorf("RPC error: %w\nUser Operation: %s", err, string(op))
	}

	var response map[string]interface{}
	err = json.Unmarshal(result, &response)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	switch aaService {
	case "biconomy":
		userOp.PaymasterAndData = common.FromHex(response["paymasterAndData"].(string))
		userOp.PreVerificationGas, _ = new(big.Int).SetString(response["preVerificationGas"].(string), 0)
		userOp.VerificationGasLimit = decimal.NewFromFloat(response["verificationGasLimit"].(float64)).BigInt()
		userOp.CallGasLimit = decimal.NewFromFloat(response["callGasLimit"].(float64)).BigInt()

	case "thirdweb":
		userOp.CallGasLimit, _ = new(big.Int).SetString(response["callGasLimit"].(string), 0)
		userOp.VerificationGasLimit, _ = new(big.Int).SetString(response["verificationGasLimit"].(string), 0)
		userOp.PreVerificationGas, _ = new(big.Int).SetString(response["preVerificationGas"].(string), 0)
		userOp.PaymasterAndData = common.FromHex(response["paymasterAndData"].(string))

	}

	return nil
}

// SignUserOperation signs the user operation
func SignUserOperation(userOperation *userop.UserOperation, chainId int64) error {
	// Sign user operation
	userOpHash := userOperation.GetUserOpHash(
		orderConf.EntryPointContractAddress,
		big.NewInt(chainId),
	)

	signature, err := PersonalSign(string(userOpHash[:]), privateKey)
	if err != nil {
		return err
	}
	userOperation.Signature = signature

	return nil
}

// SendUserOperation sends the user operation
func SendUserOperation(userOp *userop.UserOperation, chainId int64) (string, string, int64, error) {

	bundlerUrl, _, err := getEndpoints(chainId)
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to get endpoints for chain ID %d: %w", chainId, err)
	}

	client, err := rpc.Dial(bundlerUrl)
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to connect to RPC client: %w", err)
	}

	aaService, err := detectAAService(bundlerUrl)
	if err != nil {
		return "", "", 0, fmt.Errorf("invalid AA service URL pattern: %w", err)
	}

	var requestParams []interface{}
	method := "eth_sendUserOperation"
	switch aaService {
	case "biconomy":
		requestParams = []interface{}{
			userOp,
			orderConf.EntryPointContractAddress.Hex(),
			map[string]string{
				"simulation_type": "validation_and_execution",
			},
		}
	case "thirdweb":
		httpClient := &http.Client{
			Transport: &http.Transport{},
		}
		header := http.Header{}
		header.Set("x-secret-key", engineConf.ThirdwebSecretKey)

		client, err = rpc.DialOptions(
			context.Background(),
			bundlerUrl,
			rpc.WithHTTPClient(httpClient),
			rpc.WithHeaders(header),
		)
		if err != nil {
			return "", "", 0, fmt.Errorf("failed to connect to RPC client: %w", err)
		}

		requestParams = []interface{}{
			userOp,
			orderConf.EntryPointContractAddress.Hex(),
		}
	default:
		return "", "", 0, fmt.Errorf("unsupported AA service: %s", aaService)
	}

	var result json.RawMessage
	err = client.Call(&result, method, requestParams...)
	if err != nil {
		op, _ := userOp.MarshalJSON()
		return "", "", 0, fmt.Errorf("RPC error: %w\nUser Operation: %s", err, string(op))
	}

	var userOpHash string
	err = json.Unmarshal(result, &userOpHash)
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	response, err := GetUserOperationByReceipt(userOpHash, chainId)
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to get user operation by hash: %w", err)
	}

	transactionHash, ok := response["transactionHash"].(string)
	if !ok {
		return "", "", 0, fmt.Errorf("failed to get transaction hash")
	}
	orderId, ok := response["orderId"].(string)
	if !ok {
		return "", "", 0, fmt.Errorf("failed to get order ID")
	}

	blockNumberStr, ok := response["blockNumber"].(string)
	if !ok {
		return "", "", 0, fmt.Errorf("failed to get block number")
	}

	blockNumberHex := blockNumberStr[2:]

	blockNumberInt, err := strconv.ParseInt(blockNumberHex, 16, 64)
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to parse block number: %w", err)
	}

	return transactionHash, orderId, blockNumberInt, nil
}

// GetUserOperationByReceipt fetches the user operation by hash
func GetUserOperationByReceipt(userOpHash string, chainId int64) (map[string]interface{}, error) {
	bundlerUrl, _, err := getEndpoints(chainId)
	if err != nil {
		return nil, fmt.Errorf("failed to get endpoints for chain ID %d: %w", chainId, err)
	}

	aaService, err := detectAAService(bundlerUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid AA service URL pattern: %w", err)
	}

	var client *rpc.Client
	if aaService == "thirdweb" {
		httpClient := &http.Client{
			Transport: &http.Transport{},
		}
		header := http.Header{}
		header.Set("x-secret-key", engineConf.ThirdwebSecretKey)

		client, err = rpc.DialOptions(
			context.Background(),
			bundlerUrl,
			rpc.WithHTTPClient(httpClient),
			rpc.WithHeaders(header),
		)
	} else {
		client, err = rpc.Dial(bundlerUrl)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RPC client: %w", err)
	}

	start := time.Now()
	timeout := 1 * time.Minute

	var response map[string]interface{}
	for {
		time.Sleep(5 * time.Second)
		var result json.RawMessage
		err = client.Call(&result, "eth_getUserOperationReceipt", []interface{}{userOpHash}...)
		if err != nil {
			return nil, fmt.Errorf("RPC error: %w", err)
		}

		if result == nil {
			continue
		}

		err = json.Unmarshal(result, &response)
		if err != nil {
			return nil, err
		}

		// Check if operation was successful
		var success bool
		switch v := response["success"].(type) {
		case bool:
			success = v
		case string:
			success = v == "true"
		default:
			return nil, fmt.Errorf("unexpected type for success field: %T", response["success"])
		}

		if !success {
			return nil, fmt.Errorf("user operation failed")
		}

		// Get receipt from the response
		receipt, ok := response["receipt"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to get receipt")
		}

		// Get transaction hash and block number from receipt
		transactionHash, ok := receipt["transactionHash"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to get transaction hash")
		}

		blockNumber, ok := receipt["blockNumber"].(string)
		if !ok {
			return nil, fmt.Errorf("failed to get block number")
		}

		// Get logs from receipt
		logs, ok := receipt["logs"].([]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to get logs")
		}

		// If logs is empty, continue waiting
		if len(logs) == 0 {
			elapsed := time.Since(start)
			if elapsed >= timeout {
				return nil, fmt.Errorf("timeout waiting for logs")
			}
			continue
		}

		var orderId string
		// Iterate over logs to find the OrderCreated event
		for _, event := range logs {
			eventData := event.(map[string]interface{})
			if eventData["topics"].([]interface{})[0] == "0x40ccd1ceb111a3c186ef9911e1b876dc1f789ed331b86097b3b8851055b6a137" {
				data := strings.TrimPrefix(eventData["data"].(string), "0x")
				unpackedEventData, err := UnpackEventData(data, contracts.GatewayMetaData.ABI, "OrderCreated")
				if err != nil {
					return nil, fmt.Errorf("userop failed to unpack event data: %w %v", err, eventData)
				}
				orderIdBytes := unpackedEventData[1].([32]byte)
				orderId = "0x" + hex.EncodeToString(orderIdBytes[:])
				if orderId == "" {
					return nil, fmt.Errorf("failed to get order ID")
				}
				break
			}
		}

		return map[string]interface{}{
			"orderId":         orderId,
			"blockNumber":     blockNumber,
			"transactionHash": transactionHash,
		}, nil
	}
}

// GetPaymasterAccount returns the paymaster account for the given chain ID
func GetPaymasterAccount(chainId int64) (string, error) {

	_, paymasterUrl, err := getEndpoints(chainId)
	if err != nil {
		return "", fmt.Errorf("failed to get endpoints for chain ID %d: %w", chainId, err)
	}

	aaService, err := detectAAService(paymasterUrl)
	if err != nil {
		return "", fmt.Errorf("failed to detect AA service: %w", err)
	}

	// Handle biconomy case specifically
	if aaService == "biconomy" {
		return "0x00000f7365ca6c59a2c93719ad53d567ed49c14c", nil
	}

	client, err := rpc.Dial(paymasterUrl)
	if err != nil {
		return "", fmt.Errorf("failed to connect to RPC client: %w", err)
	}

	requestParams := []interface{}{
		orderConf.EntryPointContractAddress.Hex(),
	}

	var result json.RawMessage
	err = client.Call(&result, "pm_accounts", requestParams...)
	if err != nil {
		return "", fmt.Errorf("RPC error: %w", err)
	}

	var response []string
	err = json.Unmarshal(result, &response)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return response[0], nil
}

// GetUserOperationStatus returns the status of the user operation
func GetUserOperationStatus(userOpHash string, chainId int64) (bool, error) {
	bundlerUrl, _, err := getEndpoints(chainId)
	if err != nil {
		return false, fmt.Errorf("failed to get endpoints for chain ID %d: %w", chainId, err)
	}

	aaService, err := detectAAService(bundlerUrl)
	if err != nil {
		return false, fmt.Errorf("invalid AA service URL pattern: %w", err)
	}

	var client *rpc.Client
	if aaService == "thirdweb" {
		httpClient := &http.Client{
			Transport: &http.Transport{},
		}
		header := http.Header{}
		header.Set("x-secret-key", engineConf.ThirdwebSecretKey)

		client, err = rpc.DialOptions(
			context.Background(),
			bundlerUrl,
			rpc.WithHTTPClient(httpClient),
			rpc.WithHeaders(header),
		)
	} else {
		client, err = rpc.Dial(bundlerUrl)
	}
	if err != nil {
		return false, fmt.Errorf("failed to connect to RPC client: %w", err)
	}

	requestParams := []interface{}{
		userOpHash,
	}

	var result json.RawMessage
	err = client.Call(&result, "eth_getUserOperationReceipt", requestParams)
	if err != nil {
		return false, fmt.Errorf("RPC error: %w", err)
	}

	var userOpStatus map[string]interface{}
	err = json.Unmarshal(result, &userOpStatus)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return userOpStatus["success"].(bool), nil
}

// createAccountCallData creates the data for the createAccount method
func createAccountCallData(owner common.Address, salt *big.Int) ([]byte, error) {
	// Create ABI
	accountFactoryABI, err := abi.JSON(strings.NewReader(contracts.SimpleAccountFactoryMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse account factory ABI: %w", err)
	}

	// Create calldata
	calldata, err := accountFactoryABI.Pack("createAccount", owner, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to pack createAccount ABI: %w", err)
	}

	return calldata, nil
}

// eip1559GasPrice computes the EIP1559 gas price
func eip1559GasPrice(ctx context.Context, client types.RPCClient) (maxFeePerGas, maxPriorityFeePerGas *big.Int, err error) {
	latestHeader, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, nil, err
	}

	if latestHeader.BaseFee != nil {
		tip, err := client.SuggestGasTipCap(ctx)
		if err != nil {
			return nil, nil, err
		}

		// Ensure minimum priority fee of 700000 wei
		minPriorityFee := big.NewInt(700000)
		if tip.Cmp(minPriorityFee) < 0 {
			tip = minPriorityFee
		}

		maxFeePerGas = big.NewInt(0).Add(tip, new(big.Int).Mul(latestHeader.BaseFee, common.Big2))
		maxPriorityFeePerGas = tip
	} else {
		sgp, err := client.SuggestGasPrice(ctx)
		if err != nil {
			return nil, nil, err
		}

		// Ensure minimum gas price of 700000 wei
		minGasPrice := big.NewInt(700000)
		if sgp.Cmp(minGasPrice) < 0 {
			sgp = minGasPrice
		}

		maxFeePerGas = sgp
		maxPriorityFeePerGas = sgp
	}

	return maxFeePerGas, maxPriorityFeePerGas, nil
}

func getStandardGasPrices(chainId int64) (*big.Int, *big.Int, error) {
	_, paymasterUrl, err := getEndpoints(chainId)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get endpoints for chain ID %d: %w", chainId, err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{},
	}
	header := http.Header{}
	header.Set("x-secret-key", engineConf.ThirdwebSecretKey)

	client, err := rpc.DialOptions(
		context.Background(),
		paymasterUrl,
		rpc.WithHTTPClient(httpClient),
		rpc.WithHeaders(header),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to RPC client: %w", err)
	}

	var result struct {
		Slow struct {
			MaxFeePerGas         string `json:"maxFeePerGas"`
			MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"`
		} `json:"slow"`
		Standard struct {
			MaxFeePerGas         string `json:"maxFeePerGas"`
			MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"`
		} `json:"standard"`
		Fast struct {
			MaxFeePerGas         string `json:"maxFeePerGas"`
			MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"`
		} `json:"fast"`
	}

	err = client.Call(&result, "thirdweb_getUserOperationGasPrice")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get gas prices: %w", err)
	}

	// Convert hex strings to big.Int
	maxFeePerGas := new(big.Int)
	maxFeePerGas.SetString(result.Standard.MaxFeePerGas, 0)

	maxPriorityFeePerGas := new(big.Int)
	maxPriorityFeePerGas.SetString(result.Standard.MaxPriorityFeePerGas, 0)

	return maxFeePerGas, maxPriorityFeePerGas, nil
}

// getEndpoints fetches bundler and paymaster URLs for the given chain ID from the database
func getEndpoints(chainID int64) (string, string, error) {
	ctx := context.Background()

	network, err := storage.Client.Network.
		Query().
		Where(network.ChainID(chainID)).
		Only(ctx)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch network: %w", err)
	}

	// Handle optional AA service
	if network.BundlerURL == "" && network.PaymasterURL == "" {
		return "", "", fmt.Errorf("AA service not enabled for network ID: %d", chainID)
	}

	// Ensure consistency if AA service is enabled
	if (network.BundlerURL == "") != (network.PaymasterURL == "") {
		return "", "", fmt.Errorf("incomplete AA configuration for network ID: %d - both bundler and paymaster URLs must be set if AA service is enabled", chainID)
	}

	// Validate URL patterns
	_, err = detectAAService(network.BundlerURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid bundler URL pattern: %w", err)
	}

	return network.BundlerURL, network.PaymasterURL, nil
}

// detectAAService detects the AA service based on the provided URL pattern
func detectAAService(url string) (string, error) {
	switch {
	case strings.Contains(url, "biconomy.io"):
		return "biconomy", nil

	case strings.Contains(url, "thirdweb.com"):
		return "thirdweb", nil
	default:
		return "", fmt.Errorf("unsupported AA service URL pattern: %s", url)
	}
}

// getNonce returns the nonce for the given sender
func getNonce(client types.RPCClient, sender common.Address) (nonce *big.Int, err error) {
	entrypoint, err := contracts.NewEntryPoint(orderConf.EntryPointContractAddress, client.(bind.ContractBackend))
	if err != nil {
		return nil, err
	}

	key := big.NewInt(0)
	nonce, err = entrypoint.GetNonce(nil, sender, key)
	if err != nil {
		return nil, err
	}

	return nonce, nil
}
