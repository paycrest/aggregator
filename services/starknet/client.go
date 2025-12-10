package starknet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/NethermindEth/juno/core/felt"
	"github.com/NethermindEth/starknet.go/account"
	"github.com/NethermindEth/starknet.go/client"
	"github.com/NethermindEth/starknet.go/curve"
	"github.com/NethermindEth/starknet.go/paymaster"
	"github.com/NethermindEth/starknet.go/rpc"
	"github.com/NethermindEth/starknet.go/utils"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/types"
	u "github.com/paycrest/aggregator/utils"
	"github.com/paycrest/aggregator/utils/logger"
)

// Client wraps Starknet RPC provider with additional functionality
type Client struct {
	providerClient  *rpc.Provider
	paymasterClient *paymaster.Paymaster
	AggregatorSalt  string
}

var starknetConf = config.StarknetConfig()

// NewClient creates a new Starknet client
func NewClient(ctx context.Context) (*Client, error) {
	providerClient, err := rpc.NewProvider(ctx, starknetConf.StarknetClientURL)
	if err != nil {
		// Check if it's a version incompatibility warning (provider is still usable)
		if strings.Contains(err.Error(), "incompatible JSON-RPC specification version") {
			logger.Warnf("Starknet RPC version warning: %v", err)
		} else {
			return nil, fmt.Errorf("failed to create starknet provider: %w", err)
		}
	}

	paymasterClient, err := paymaster.New(
		ctx,
		starknetConf.StarknetPaymasterURL,
		client.WithHeader("x-paymaster-api-key", starknetConf.StarknetPaymasterAPIKey),
	)
	if err != nil {
		if strings.Contains(err.Error(), "incompatible JSON-RPC specification version") {
			fmt.Printf("⚠️  Warning: %v\n", err)
		} else {
			return nil, fmt.Errorf("provider error: %w", err)
		}
	}

	if !isPaymasterAvailable(ctx, paymasterClient) {
		return nil, fmt.Errorf("paymaster is not available at %s", starknetConf.StarknetPaymasterURL)
	}

	return &Client{
		providerClient:  providerClient,
		paymasterClient: paymasterClient,
		AggregatorSalt:  starknetConf.StarknetAggregatorSalt,
	}, nil
}

func isPaymasterAvailable(ctx context.Context, paymasterClient *paymaster.Paymaster) bool {
	if paymasterClient == nil {
		return false
	}
	isAvailable, err := paymasterClient.IsAvailable(ctx)
	if err != nil {
		return false
	}
	return isAvailable
}

// GetBlockNumber returns the latest block number
func (c *Client) GetBlockNumber(ctx context.Context) (uint64, error) {
	blockNumber, err := c.providerClient.BlockNumber(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get block number: %w", err)
	}
	return blockNumber, nil
}

// GetEvents fetches events from the blockchain
func (c *Client) GetEvents(ctx context.Context, accountAddress *felt.Felt, fromBlock int64, toBlock int64, topics []*felt.Felt, chunkSize int) ([]map[string]interface{}, error) {
	if fromBlock < 0 || toBlock < 0 || fromBlock > toBlock {
		return nil, fmt.Errorf("invalid block range: fromBlock=%d, toBlock=%d", fromBlock, toBlock)
	}

	transferSelectorFelt, err := utils.HexToFelt(u.TransferStarknetSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to parse transfer selector felt: %w", err)
	}

	orderSettledSelectorFelt, _ := utils.HexToFelt(u.OrderSettledStarknetSelector)
	
	var eventSignatures [][]*felt.Felt
	if len(topics) > 0 && topics[0] == transferSelectorFelt {
		eventSignatures = [][]*felt.Felt{{transferSelectorFelt}}
	} else if topics[0] == orderSettledSelectorFelt {
		eventSignatures = [][]*felt.Felt{{orderSettledSelectorFelt}}
	} else {
		orderCreatedSelectorFelt, _ := utils.HexToFelt(u.OrderCreatedStarknetSelector)
		orderRefundedSelectorFelt, _ := utils.HexToFelt(u.OrderRefundedStarknetSelector)

		eventSignatures = [][]*felt.Felt{
			{
				orderCreatedSelectorFelt,
				orderSettledSelectorFelt,
				orderRefundedSelectorFelt,
			},
		}
	}

	fromBlockNum := uint64(fromBlock)
	toBlockNum := uint64(toBlock)

	eventFilter := rpc.EventFilter{
		FromBlock: rpc.BlockID{Number: &fromBlockNum},
		ToBlock:   rpc.BlockID{Number: &toBlockNum},
		Address:   accountAddress,
		Keys:      eventSignatures,
	}

	eventsChunk, err := c.providerClient.Events(ctx, rpc.EventsInput{
		EventFilter: eventFilter,
		ResultPageRequest: rpc.ResultPageRequest{
			ChunkSize: chunkSize,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get events: %w", err)
	}

	var events []map[string]interface{}
	for _, event := range eventsChunk.Events {
		processedEvents, err := c.processEvent(event)
		if err != nil {
			return nil, fmt.Errorf("failed to process event: %w", err)
		}
		events = append(events, processedEvents)
	}

	return events, nil
}

// GetTransactionReceipt retrieves transaction receipt
func (c *Client) GetTransactionReceipt(ctx context.Context, txHash, accountAddress *felt.Felt, topics []*felt.Felt) ([]map[string]interface{}, error) {
	if txHash == nil {
		return nil, fmt.Errorf("transaction hash is nil")
	}

	transferSelectorFelt, err := utils.HexToFelt(u.TransferStarknetSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to parse transfer selector felt: %w", err)
	}
	
	orderSettledSelectorFelt, _ := utils.HexToFelt(u.OrderSettledStarknetSelector)
	var eventSignatures []felt.Felt
	if len(topics) > 0 && topics[0] == transferSelectorFelt {
		// If transfer event signature is provided, filter for transfer events
		eventSignatures = []felt.Felt{*transferSelectorFelt}
	} else if topics[0] == orderSettledSelectorFelt {
		eventSignatures = []felt.Felt{*orderSettledSelectorFelt}
	} else {
		orderCreatedSelectorFelt, _ := utils.HexToFelt(u.OrderCreatedStarknetSelector)
		orderRefundedSelectorFelt, _ := utils.HexToFelt(u.OrderRefundedStarknetSelector)

		// Default to gateway event signatures
		eventSignatures = []felt.Felt{
			*orderCreatedSelectorFelt,
			*orderSettledSelectorFelt,
			*orderRefundedSelectorFelt,
		}
	}

	var logs []types.StarknetEventsData

	receipt, err := c.providerClient.TransactionReceipt(ctx, txHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction receipt: %w", err)
	}

	// Filter logs from the receipt that match the specified event signatures
	// If token contract is used, the caller should handle the receive address logs
	for _, log := range receipt.Events {
		if log.FromAddress == accountAddress {
			// Check if this log matches any of our event signatures
			eventSignature := log.Keys[0]
			for _, signature := range eventSignatures {
				if *eventSignature == signature {
					eventsPacked := types.StarknetEventsData{
						Events: rpc.EmittedEvent{
							Event:           log,
							BlockHash:       receipt.BlockHash,
							BlockNumber:     uint64(receipt.BlockNumber),
							TransactionHash: receipt.Hash,
						},
					}
					logs = append(logs, eventsPacked)
					break
				}
			}
		}
	}

	var events []map[string]interface{}
	for _, event := range logs {
		processedEvents, err := c.processEvent(event.Events)
		if err != nil {
			return nil, fmt.Errorf("failed to process event: %w", err)
		}
		events = append(events, processedEvents)
	}

	return events, nil
}

func (c *Client) GetExecutableRequest(
	ctx context.Context,
	accountInfo *types.StarknetDeterministicAccountInfo,
	buildReq paymaster.BuildTransactionRequest,
	buildResp paymaster.BuildTransactionResponse,
) (paymaster.ExecuteTransactionRequest, error) {
	if accountInfo == nil {
		return paymaster.ExecuteTransactionRequest{}, fmt.Errorf("accountInfo is required to sign the paymaster transaction")
	}

	var executeInvoke *paymaster.ExecutableUserInvoke

	// buildResp.TypedData can be nil when the paymaster does not require an
	// external signature (e.g., deploy-only requests). Only compute the
	// message hash and sign when TypedData is present.
	if buildResp.TypedData != nil {
		typedHash, err := buildResp.TypedData.GetMessageHash(accountInfo.NewAccount.Address.String())
		if err != nil {
			return paymaster.ExecuteTransactionRequest{}, fmt.Errorf("failed to compute typed data hash: %w", err)
		}

		sig, err := accountInfo.NewAccount.Sign(ctx, typedHash)
		if err != nil {
			return paymaster.ExecuteTransactionRequest{}, fmt.Errorf("failed to sign message: %w", err)
		}

		executeInvoke = &paymaster.ExecutableUserInvoke{
			UserAddress: accountInfo.NewAccount.Address,
			TypedData:   buildResp.TypedData,
			Signature:   sig,
		}
	} else {
		// No typed data -> no signature required. executeInvoke remains nil.
		executeInvoke = nil
	}

	transactions := paymaster.ExecutableUserTransaction{
		Type:       buildReq.Transaction.Type,
		Deployment: buildReq.Transaction.Deployment,
		Invoke:     executeInvoke,
	}

	executeReq := paymaster.ExecuteTransactionRequest{
		Transaction: transactions,
		Parameters:  buildReq.Parameters,
	}

	return executeReq, nil
}

func (c *Client) BuildAccountDeployment(ctx context.Context, accountInfo *types.StarknetDeterministicAccountInfo) (*paymaster.BuildTransactionRequest, paymaster.BuildTransactionResponse, error) {
	classHash, err := utils.HexToFelt(starknetConf.AccountClassHash)
	if err != nil {
		return nil, paymaster.BuildTransactionResponse{}, fmt.Errorf("failed to parse class hash: %w", err)
	}

	deployment := &paymaster.AccountDeploymentData{
		Address:   accountInfo.NewAccount.Address,
		ClassHash: classHash,
		Salt:      accountInfo.Salt,
		Calldata:  []*felt.Felt{accountInfo.PublicKey},
		Version:   paymaster.Cairo1,
	}

	userTxn := paymaster.UserTransaction{
		Type:       paymaster.UserTxnDeploy, // "deploy"
		Deployment: deployment,
		Invoke:     nil,
	}

	userParams := getUserUserParameters()

	buildReq := &paymaster.BuildTransactionRequest{
		Transaction: userTxn,
		Parameters:  userParams,
	}

	buildResp, err := c.paymasterClient.BuildTransaction(ctx, buildReq)
	if err != nil {
		return nil, paymaster.BuildTransactionResponse{}, fmt.Errorf("paymaster BuildTransaction failed for account deployment: %w", err)
	}

	return buildReq, buildResp, nil
}

func (c *Client) BuildApprovalAndCreateOrderCall(
	ctx context.Context,
	accountInfo *types.StarknetDeterministicAccountInfo,
	gatewayContractAddress *felt.Felt,
	token *felt.Felt,
	orderAmount *felt.Felt,
	rate *felt.Felt,
	senderFeeRecipient *felt.Felt,
	senderFee *felt.Felt,
	refundAddress *felt.Felt,
	messageHash string,
) (*paymaster.BuildTransactionRequest, paymaster.BuildTransactionResponse, error) {
	if !isPaymasterAvailable(ctx, c.paymasterClient) {
		return nil, paymaster.BuildTransactionResponse{}, fmt.Errorf("paymaster is not available")
	}
	acctDeploymentBuildReq, _, err := c.BuildAccountDeployment(ctx, accountInfo)
	if err != nil {
		return nil, paymaster.BuildTransactionResponse{}, fmt.Errorf("failed to build account deployment: %w", err)
	}
	userParams := getUserUserParameters()

	approveSelectorBigInt := utils.GetSelectorFromName("approve")
	createOrderSelectorBigInt := utils.GetSelectorFromName("create_order")
	approveSelectorFelt := new(felt.Felt).SetBigInt(approveSelectorBigInt)
	createOrderSelectorFelt := new(felt.Felt).SetBigInt(createOrderSelectorBigInt)

	// Encode messageHash as ByteArray (Cairo string format)
	messageHashBytes := []byte(messageHash)
	messageHashCalldata := encodeCairoByteArray(messageHashBytes)

	buildReq := &paymaster.BuildTransactionRequest{
		Transaction: paymaster.UserTransaction{
			Type:       paymaster.UserTxnDeployAndInvoke, // "UserTxnInvoke" UserTxnDeployAndInvoke
			Deployment: acctDeploymentBuildReq.Transaction.Deployment,
			Invoke: &paymaster.UserInvoke{
				UserAddress: accountInfo.NewAccount.Address,
				Calls: []paymaster.Call{
					{
						To:       token,
						Selector: approveSelectorFelt,
						Calldata: []*felt.Felt{
							gatewayContractAddress,
							orderAmount,                 // amount low
							new(felt.Felt).SetUint64(0), // amount high
						},
					},
					{
						To:       gatewayContractAddress,
						Selector: createOrderSelectorFelt,
						Calldata: append([]*felt.Felt{
							token,
							orderAmount,                 // amount low
							new(felt.Felt).SetUint64(0), // amount high
							rate,
							senderFeeRecipient,
							senderFee,                   // sender_fee low
							new(felt.Felt).SetUint64(0), // sender_fee high
							refundAddress,
						}, messageHashCalldata...), // message_hash as ByteArray
					},
				},
			},
		},
		Parameters: userParams,
	}

	buildResp, err := c.paymasterClient.BuildTransaction(ctx, buildReq)
	if err != nil {
		return nil, paymaster.BuildTransactionResponse{}, fmt.Errorf("paymaster BuildTransaction failed for createOrder: %w", err)
	}

	return buildReq, buildResp, nil
}

func (c *Client) BuildSettleOrderCall(
	ctx context.Context,
	aggregatorAccount *felt.Felt,
	gatewayContractAddress *felt.Felt,
	splitOrderID *felt.Felt,
	orderID *felt.Felt,
	liquidityProvider *felt.Felt,
	settlePercent uint64,
	rebatePercent uint64,
) (*paymaster.BuildTransactionRequest, paymaster.BuildTransactionResponse, error) {
	if !isPaymasterAvailable(ctx, c.paymasterClient) {
		return nil, paymaster.BuildTransactionResponse{}, fmt.Errorf("paymaster is not available")
	}
	userParams := getUserUserParameters()

	settleSelectorBigInt := utils.GetSelectorFromName("settle")
	settleSelectorFelt := new(felt.Felt).SetBigInt(settleSelectorBigInt)

	buildReq := &paymaster.BuildTransactionRequest{
		Transaction: paymaster.UserTransaction{
			Type:       paymaster.UserTxnInvoke, // Use Invoke only since account is already deployed
			Deployment: nil,                     // No deployment needed
			Invoke: &paymaster.UserInvoke{
				UserAddress: aggregatorAccount,
				Calls: []paymaster.Call{
					{
						To:       gatewayContractAddress,
						Selector: settleSelectorFelt,
						Calldata: []*felt.Felt{
							splitOrderID,                            // split_order_id
							orderID,                                 // order_id
							liquidityProvider,                       // liquidity_provider
							new(felt.Felt).SetUint64(settlePercent), // settle_percent
							new(felt.Felt).SetUint64(rebatePercent), // rebate_percent
						},
					},
				},
			},
		},
		Parameters: userParams,
	}

	buildResp, err := c.paymasterClient.BuildTransaction(ctx, buildReq)
	if err != nil {
		return nil, paymaster.BuildTransactionResponse{}, fmt.Errorf("paymaster BuildTransaction failed: %w", err)
	}

	return buildReq, buildResp, nil
}

func (c *Client) BuildRefundOrderCall(
	ctx context.Context,
	aggregatorAccount *felt.Felt,
	gatewayContractAddress *felt.Felt,
	orderID *felt.Felt,
	fee *felt.Felt,
) (*paymaster.BuildTransactionRequest, paymaster.BuildTransactionResponse, error) {
	if !isPaymasterAvailable(ctx, c.paymasterClient) {
		return nil, paymaster.BuildTransactionResponse{}, fmt.Errorf("paymaster is not available")
	}
	userParams := getUserUserParameters()

	refundSelectorBigInt := utils.GetSelectorFromName("refund")
	refundSelectorFelt := new(felt.Felt).SetBigInt(refundSelectorBigInt)

	buildReq := &paymaster.BuildTransactionRequest{
		Transaction: paymaster.UserTransaction{
			Type:       paymaster.UserTxnInvoke, // Use Invoke only since account is already deployed
			Deployment: nil,                     // No deployment needed
			Invoke: &paymaster.UserInvoke{
				UserAddress: aggregatorAccount,
				Calls: []paymaster.Call{
					{
						To:       gatewayContractAddress,
						Selector: refundSelectorFelt,
						Calldata: []*felt.Felt{
							fee,                         // fee (u256 low)
							new(felt.Felt).SetUint64(0), // fee (u256 high)
							orderID,                     // order_id
						},
					},
				},
			},
		},
		Parameters: userParams,
	}

	buildResp, err := c.paymasterClient.BuildTransaction(ctx, buildReq)
	if err != nil {
		return nil, paymaster.BuildTransactionResponse{}, fmt.Errorf("paymaster BuildTransaction failed: %w", err)
	}

	return buildReq, buildResp, nil
}

func (c *Client) GenerateDeterministicAccount(seed string) (*types.StarknetDeterministicAccountInfo, error) {
	// Validate that exactly one of seed or salt is provided
	if seed == "" {
		return nil, fmt.Errorf("seed must be provided")
	}

	// This assume that all accounts inclusive with aggregator use the same class hash
	accountClassHash, err := utils.HexToFelt(starknetConf.AccountClassHash)
	if err != nil {
		return nil, fmt.Errorf("invalid account class hash: %w", err)
	}

	var privateKey *big.Int

	if seed != "" {
		sum := sha256.Sum256([]byte(seed))
		privateKey = new(big.Int).SetBytes(sum[:])

	} else {
		seed, err = generateSecureSeed()
		if err != nil {
			return nil, fmt.Errorf("failed to generate secure seed: %w", err)
		}

		privateKeySeed := sha256.Sum256([]byte(seed))
		privateKey = new(big.Int).SetBytes(privateKeySeed[:])
	}

	publicKeyBig, _ := curve.PrivateKeyToPoint(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate deterministic key: %w", err)
	}
	publicKey := new(felt.Felt).SetBigInt(publicKeyBig)

	// Generate deterministic salt from seed
	saltBytes := sha256.Sum256([]byte(fmt.Sprintf("%s-paycrest", seed)))
	saltFelt := new(felt.Felt).SetBytes(saltBytes[:])

	// Constructor calldata for the account
	constructorCalldata := []*felt.Felt{
		publicKey,
	}

	// Precompute the account address
	address := account.PrecomputeAccountAddress(
		saltFelt,
		accountClassHash,
		constructorCalldata,
	)

	ks := account.NewMemKeystore()
	ks.Put(publicKey.String(), privateKey)

	// Initialize Account (Cairo v2)
	account, err := account.NewAccount(c.providerClient, address, publicKey.String(), ks, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to create account: %w", err)
	}

	return &types.StarknetDeterministicAccountInfo{
		Salt:       saltFelt,
		PublicKey:  publicKey,
		NewAccount: account,
	}, nil
}

func (c *Client) PaymasterExecuteTransaction(
	ctx context.Context,
	executeReq paymaster.ExecuteTransactionRequest,
) (paymaster.ExecuteTransactionResponse, error) {
	executeResp, err := c.paymasterClient.ExecuteTransaction(ctx, &executeReq)
	if err != nil {
		return paymaster.ExecuteTransactionResponse{}, fmt.Errorf("paymaster ExecuteTransaction failed: %w", err)
	}

	return executeResp, nil
}

func (c *Client) processEvent(event rpc.EmittedEvent) (map[string]interface{}, error) {
	if len(event.Keys) == 0 {
		return nil, fmt.Errorf("event has no keys")
	}

	eventSelector := event.Keys[0]
	orderCreatedSelectorFelt, _ := utils.HexToFelt(u.OrderCreatedStarknetSelector)
	orderSettledSelectorFelt, _ := utils.HexToFelt(u.OrderSettledStarknetSelector)
	orderRefundedSelectorFelt, _ := utils.HexToFelt(u.OrderRefundedStarknetSelector)
	transferSelectorFelt, _ := utils.HexToFelt(u.TransferStarknetSelector)

	switch {
	case eventSelector.Equal(orderCreatedSelectorFelt):
		return c.handleOrderCreated(event)
	case eventSelector.Equal(orderSettledSelectorFelt):
		return c.handleOrderSettled(event)
	case eventSelector.Equal(orderRefundedSelectorFelt):
		return c.handleOrderRefunded(event)
	case eventSelector.Equal(transferSelectorFelt):
		return c.handleTransfer(event)
	// case eventSelector.Equal(SenderFeeTransferredSelector):
	// 	return c.handleSenderFeeTransferred(event)
	// case eventSelector.Equal(LocalTransferFeeSplitSelector):
	// 	return c.handleLocalTransferFeeSplit(event)
	// case eventSelector.Equal(FxTransferFeeSplitSelector):
	// 	return c.handleFxTransferFeeSplit(event)
	default:
		return nil, fmt.Errorf("unknown event selector: %s", eventSelector.String())
	}
}

// handleOrderCreated processes OrderCreated events
func (c *Client) handleOrderCreated(emittedEvent rpc.EmittedEvent) (map[string]interface{}, error) {
	// Keys: [event_selector, sender, token, amount]
	// Data: [protocol_fee, order_id, rate, message_hash...]

	if len(emittedEvent.Keys) < 4 {
		return nil, fmt.Errorf("invalid OrderCreated event: insufficient keys")
	}

	sender := emittedEvent.Keys[1]
	token := emittedEvent.Keys[2]
	amountLow := emittedEvent.Keys[3]
	amountHigh := emittedEvent.Keys[4]
	amount := u256FromFelts(amountLow, amountHigh)

	if len(emittedEvent.Data) < 3 {
		return nil, fmt.Errorf("invalid OrderCreated event: insufficient data")
	}

	// Parse protocol_fee (u256)
	protocolFeeLow := emittedEvent.Data[0]
	protocolFeeHigh := emittedEvent.Data[1]
	protocolFee := u256FromFelts(protocolFeeLow, protocolFeeHigh)

	orderID := emittedEvent.Data[2]

	// Parse rate (u128)
	rateLow := emittedEvent.Data[3]
	rateBytes := rateLow.Bytes()
	rate := new(big.Int).SetBytes(rateBytes[:])

	// Parse ByteArray message_hash starting at index 5
	messageHash := ""
	if len(emittedEvent.Data) > 3 {
		messageHash = parseByteArray(emittedEvent.Data[4:])
	}

	event := map[string]interface{}{
		"block_number":     float64(emittedEvent.BlockNumber),
		"transaction_hash": emittedEvent.TransactionHash,
		"address":          emittedEvent.FromAddress,
		"topics":           emittedEvent.Keys[0],
		"data":             emittedEvent.Data,
		"decoded": map[string]interface{}{
			"indexed_params": map[string]interface{}{
				"sender": sender,
				"token":  token,
				"amount": amount,
			},
			"non_indexed_params": map[string]interface{}{
				"protocol_fee": protocolFee,
				"order_id":     orderID,
				"rate":         rate,
				"message_hash": messageHash,
			},
		},
	}

	return event, nil
}

// handleOrderSettled processes OrderSettled events
func (c *Client) handleOrderSettled(emittedEvent rpc.EmittedEvent) (map[string]interface{}, error) {
	// Keys: [event_selector, order_id, liquidity_provider]
	// Data: [split_order_id, settle_percent, rebate_percent]

	if len(emittedEvent.Keys) < 3 {
		return nil, fmt.Errorf("invalid OrderSettled event: insufficient keys")
	}

	orderID := emittedEvent.Keys[1]
	liquidityProvider := emittedEvent.Keys[2]

	if len(emittedEvent.Data) < 3 {
		return nil, fmt.Errorf("invalid OrderSettled event: insufficient data")
	}

	splitOrderID := emittedEvent.Data[0]
	settlePercent := emittedEvent.Data[1].BigInt(big.NewInt(0)).Uint64()
	rebatePercent := emittedEvent.Data[2].BigInt(big.NewInt(0)).Uint64()

	event := map[string]interface{}{
		"block_number":     float64(emittedEvent.BlockNumber),
		"transaction_hash": emittedEvent.TransactionHash,
		"address":          emittedEvent.FromAddress,
		"topics":           emittedEvent.Keys[0],
		"decoded": map[string]interface{}{
			"indexed_params": map[string]interface{}{
				"order_id":           orderID,
				"liquidity_provider": liquidityProvider,
			},
			"non_indexed_params": map[string]interface{}{
				"split_order_id": splitOrderID,
				"settle_percent": settlePercent,
				"rebate_percent": rebatePercent,
			},
		},
	}

	return event, nil
}

// handleOrderRefunded processes OrderRefunded events
func (c *Client) handleOrderRefunded(emittedEvent rpc.EmittedEvent) (map[string]interface{}, error) {
	// Keys: [event_selector, order_id]
	// Data: [fee_low, fee_high]

	if len(emittedEvent.Keys) < 2 {
		return nil, fmt.Errorf("invalid OrderRefunded event: insufficient keys")
	}

	orderID := emittedEvent.Keys[1]

	if len(emittedEvent.Data) < 2 {
		return nil, fmt.Errorf("invalid OrderRefunded event: insufficient data")
	}

	// Parse u256 fee
	feeLow := emittedEvent.Data[0]
	feeHigh := emittedEvent.Data[1]
	fee := u256FromFelts(feeLow, feeHigh)

	event := map[string]interface{}{
		"block_number":     float64(emittedEvent.BlockNumber),
		"transaction_hash": emittedEvent.TransactionHash,
		"address":          emittedEvent.FromAddress,
		"topics":           emittedEvent.Keys[0],
		"decoded": map[string]interface{}{
			"indexed_params": map[string]interface{}{
				"order_id": orderID,
			},
			"non_indexed_params": map[string]interface{}{
				"fee": fee,
			},
		},
	}

	return event, nil
}

// handleTransfer processes ERC20 Transfer events
func (c *Client) handleTransfer(emittedEvent rpc.EmittedEvent) (map[string]interface{}, error) {
	// Keys: [event_selector, from, to, value_low, value_high]
	// Data: [] (empty - all data is in keys for Transfer event on Starknet)

	if len(emittedEvent.Keys) == 0 {
		return nil, fmt.Errorf("invalid Transfer event: insufficient keys")
	}

	from := emittedEvent.Data[0]
	to := emittedEvent.Data[1]

	amountLow := emittedEvent.Data[2]
	amountHigh := emittedEvent.Data[3]
	amount := u256FromFelts(amountLow, amountHigh)

	event := map[string]interface{}{
		"block_number":     float64(emittedEvent.BlockNumber),
		"transaction_hash": emittedEvent.TransactionHash,
		"address":          emittedEvent.FromAddress,
		"topics":           emittedEvent.Keys[0],
		"decoded": map[string]interface{}{
			"indexed_params": map[string]interface{}{},
			"non_indexed_params": map[string]interface{}{
				// Starknet Transfer event are non-indexed
				"from":  from,
				"to":    to,
				"value": amount,
			},
		},
	}

	return event, nil
}

func getUserUserParameters() paymaster.UserParameters {
	userParams := paymaster.UserParameters{
		Version: paymaster.UserParamV1, // "0x1"
		FeeMode: paymaster.FeeMode{
			Mode: paymaster.FeeModeSponsored, // ask the paymaster to sponsor
			// GasToken: nil,                        // must be omitted for sponsored mode
			// Tip:      nil,                        // default tip
		},
		// TimeBounds can be nil if you don't need time constraints
		// TimeBounds: nil,
	}
	return userParams
}

func encodeCairoByteArray(data []byte) []*felt.Felt {
	const BYTES_IN_FELT = 31 // Cairo felts can hold up to 31 bytes

	dataLen := len(data)
	numFullChunks := dataLen / BYTES_IN_FELT
	pendingWordLen := dataLen % BYTES_IN_FELT

	result := make([]*felt.Felt, 0)

	// 1. Number of full chunks
	result = append(result, new(felt.Felt).SetUint64(uint64(numFullChunks)))

	// 2. Full chunks (each 31 bytes)
	for i := 0; i < numFullChunks; i++ {
		chunk := data[i*BYTES_IN_FELT : (i+1)*BYTES_IN_FELT]
		chunkFelt := new(felt.Felt).SetBytes(chunk)
		result = append(result, chunkFelt)
	}

	// 3. Pending word (remaining bytes)
	var pendingWord *felt.Felt
	if pendingWordLen > 0 {
		pendingBytes := data[numFullChunks*BYTES_IN_FELT:]
		pendingWord = new(felt.Felt).SetBytes(pendingBytes)
	} else {
		pendingWord = new(felt.Felt).SetUint64(0)
	}
	result = append(result, pendingWord)

	// 4. Pending word length
	result = append(result, new(felt.Felt).SetUint64(uint64(pendingWordLen)))

	return result
}

func generateSecureSeed() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// u256FromFelts converts two felts (low, high) to a big.Int (u256)
func u256FromFelts(low, high *felt.Felt) *big.Int {
	lowBytes := low.Bytes()
	highBytes := high.Bytes()

	lowBig := new(big.Int).SetBytes(lowBytes[:])
	highBig := new(big.Int).SetBytes(highBytes[:])

	// result = low + (high << 128)
	result := new(big.Int).Lsh(highBig, 128)
	result.Add(result, lowBig)

	return result
}

// parseByteArray converts Cairo ByteArray format to string
// ByteArray format: [num_full_chunks, ...full_chunks, pending_word, pending_word_len]
func parseByteArray(data []*felt.Felt) string {
	if len(data) < 3 {
		return ""
	}

	numFullChunks := int(data[0].BigInt(big.NewInt(0)).Int64())

	if len(data) < numFullChunks+3 {
		return ""
	}

	var result []byte

	// Process full chunks (31 bytes each)
	for i := 0; i < numFullChunks; i++ {
		chunk := data[1+i]
		chunkBytes := chunk.Bytes()

		// Convert [32]byte to slice and take last 31 bytes
		chunkSlice := chunkBytes[:]
		if len(chunkSlice) >= 31 {
			result = append(result, chunkSlice[len(chunkSlice)-31:]...)
		} else {
			// If less than 31 bytes, pad with zeros at the front
			padding := make([]byte, 31-len(chunkSlice))
			result = append(result, padding...)
			result = append(result, chunkSlice...)
		}
	}

	// Process pending word
	pendingWord := data[1+numFullChunks]
	pendingWordLen := int(data[2+numFullChunks].BigInt(big.NewInt(0)).Int64())

	if pendingWordLen > 0 {
		pendingBytes := pendingWord.Bytes()
		pendingSlice := pendingBytes[:]

		if len(pendingSlice) > pendingWordLen {
			pendingSlice = pendingSlice[len(pendingSlice)-pendingWordLen:]
		}
		result = append(result, pendingSlice...)
	}

	return string(result)
}
