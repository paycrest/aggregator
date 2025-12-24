package common

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/google/uuid"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/ent/fiatcurrency"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providercurrencies"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/provisionbucket"
	tokenent "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/transactionlog"
	"github.com/paycrest/aggregator/ent/user"
	svc "github.com/paycrest/aggregator/services"
	db "github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/logger"
	"github.com/shopspring/decimal"
)

// Common functions that can be used by VM specific implementations

var (
	serverConf = config.ServerConfig()
	orderConf  = config.OrderConfig()
)

// ProcessPaymentOrderFromBlockchain processes a payment order from blockchain event.
// It either creates a new order or updates an existing API-created order (with messageHash but no gatewayID)
// with on-chain details when the OrderCreatedEvent is indexed.
func ProcessPaymentOrderFromBlockchain(
	ctx context.Context,
	network *ent.Network,
	event *types.OrderCreatedEvent,
	refundOrder func(context.Context, *ent.Network, string) error,
	assignPaymentOrder func(context.Context, types.PaymentOrderFields) error,
) error {
	// Check if order already exists with gatewayID (already indexed from blockchain)
	existingOrderWithGatewayID, err := db.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.GatewayIDEQ(event.OrderId),
			paymentorder.HasTokenWith(
				tokenent.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return fmt.Errorf("ProcessPaymentOrderFromBlockchain.db: %v", err)
	}
	if existingOrderWithGatewayID != nil {
		// Order already indexed with gatewayID, skip
		return nil
	}

	// Check if order exists with messageHash but no gatewayID (API-created order awaiting on-chain details)
	var existingOrderWithMessageHash *ent.PaymentOrder
	if event.MessageHash != "" {
		existingOrderWithMessageHash, err = db.Client.PaymentOrder.
			Query().
			Where(
				paymentorder.MessageHashEQ(event.MessageHash),
				paymentorder.GatewayIDIsNil(),
				paymentorder.HasTokenWith(
					tokenent.HasNetworkWith(
						networkent.IdentifierEQ(network.Identifier),
					),
				),
			).
			Only(ctx)
		if err != nil && !ent.IsNotFound(err) {
			return fmt.Errorf("ProcessPaymentOrderFromBlockchain.db: %v", err)
		}
	}

	// Validate and prepare payment order data
	paymentOrderFields, _, _, _, _, err := validateAndPreparePaymentOrderData(ctx, network, event, refundOrder)
	if err != nil {
		return err
	}
	if paymentOrderFields == nil {
		// Order was cancelled during validation
		return nil
	}

	// If order exists with messageHash but no gatewayID, update it with on-chain details
	if existingOrderWithMessageHash != nil {
		tx, err := db.Client.Tx(ctx)
		if err != nil {
			return fmt.Errorf("%s failed to initiate db transaction for update: %w", paymentOrderFields.GatewayID, err)
		}

		// Update existing order with on-chain details
		updateBuilder := tx.PaymentOrder.
			Update().
			Where(paymentorder.IDEQ(existingOrderWithMessageHash.ID)).
			SetGatewayID(paymentOrderFields.GatewayID).
			SetOrderPercent(decimal.NewFromInt(100)).
			SetTxHash(paymentOrderFields.TxHash).
			SetBlockNumber(paymentOrderFields.BlockNumber).
			SetStatus(paymentorder.StatusPending)

		// Update protocol fee if needed
		if paymentOrderFields.ProtocolFee.GreaterThan(decimal.Zero) {
			updateBuilder = updateBuilder.SetProtocolFee(paymentOrderFields.ProtocolFee)
		}

		// Update sender if provided
		if paymentOrderFields.Sender != "" {
			updateBuilder = updateBuilder.SetSender(paymentOrderFields.Sender)
		}

		// Update provision bucket if available (should always be set for regular orders)
		if paymentOrderFields.ProvisionBucket != nil {
			updateBuilder = updateBuilder.SetProvisionBucket(paymentOrderFields.ProvisionBucket)
		}

		_, err = updateBuilder.Save(ctx)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("%s - failed to update payment order with on-chain details: %w", paymentOrderFields.GatewayID, err)
		}

		// Ensure transaction log exists
		transactionLog, err := ensureTransactionLog(ctx, tx, network, paymentOrderFields)
		if err != nil {
			_ = tx.Rollback()
			return err
		}

		// Link transaction log to payment order if it was newly created
		if transactionLog != nil {
			_, err = tx.PaymentOrder.
				Update().
				Where(paymentorder.IDEQ(existingOrderWithMessageHash.ID)).
				AddTransactions(transactionLog).
				Save(ctx)
			if err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("%s - failed to link transaction log: %w", paymentOrderFields.GatewayID, err)
			}
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("%s - failed to update payment order: %w", paymentOrderFields.GatewayID, err)
		}

		// Handle post-processing: webhook, AML check, provider assignment
		return processPaymentOrderPostCreation(ctx, existingOrderWithMessageHash, network, event, paymentOrderFields, refundOrder, assignPaymentOrder)
	}

	// Create new payment order
	tx, err := db.Client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("%s failed to initiate db transaction %w", paymentOrderFields.GatewayID, err)
	}

	// Ensure transaction log exists
	transactionLog, err := ensureTransactionLog(ctx, tx, network, paymentOrderFields)
	if err != nil {
		return err
	}

	// Create payment order in db
	orderBuilder := tx.PaymentOrder.
		Create().
		SetToken(paymentOrderFields.Token).
		SetGatewayID(paymentOrderFields.GatewayID).
		SetAmount(paymentOrderFields.Amount).
		SetRate(paymentOrderFields.Rate).
		SetProtocolFee(paymentOrderFields.ProtocolFee).
		SetOrderPercent(decimal.NewFromInt(100)).
		SetAmountInUsd(paymentOrderFields.AmountInUSD).
		SetBlockNumber(paymentOrderFields.BlockNumber).
		SetTxHash(paymentOrderFields.TxHash).
		SetInstitution(paymentOrderFields.Institution).
		SetAccountIdentifier(paymentOrderFields.AccountIdentifier).
		SetAccountName(paymentOrderFields.AccountName).
		SetSender(paymentOrderFields.Sender).
		SetMessageHash(paymentOrderFields.MessageHash).
		SetMemo(paymentOrderFields.Memo).
		SetMetadata(paymentOrderFields.Metadata).
		SetProvisionBucket(paymentOrderFields.ProvisionBucket).
		SetOrderType(paymentorder.OrderType(paymentOrderFields.OrderType)).
		SetStatus(paymentorder.StatusPending)

	// Set provider if ProviderID exists
	if paymentOrderFields.ProviderID != "" {
		provider, err := tx.ProviderProfile.Query().Where(providerprofile.IDEQ(paymentOrderFields.ProviderID)).Only(ctx)
		if err == nil && provider != nil {
			orderBuilder = orderBuilder.SetProvider(provider)
		}
	}

	if transactionLog != nil {
		orderBuilder = orderBuilder.AddTransactions(transactionLog)
	}

	orderCreated, err := orderBuilder.Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - failed to create payment order: %w", paymentOrderFields.GatewayID, err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%s - failed to create payment order: %w", paymentOrderFields.GatewayID, err)
	}

	// Handle post-processing: webhook, AML check, provider assignment
	return processPaymentOrderPostCreation(ctx, orderCreated, network, event, paymentOrderFields, refundOrder, assignPaymentOrder)
}

// UpdateOrderStatusRefunded updates the status of a payment order to refunded
func UpdateOrderStatusRefunded(ctx context.Context, network *ent.Network, event *types.OrderRefundedEvent, messageHash string) error {
	tx, err := db.Client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusRefunded.dbtransaction %v", err)
	}

	// Attempt to update an existing log
	var transactionLog *ent.TransactionLog
	updatedLogRows, err := tx.TransactionLog.
		Update().
		Where(
			transactionlog.StatusEQ(transactionlog.StatusOrderRefunded),
			transactionlog.GatewayIDEQ(event.OrderId),
			transactionlog.NetworkEQ(network.Identifier),
		).
		SetTxHash(event.TxHash).
		SetMetadata(
			map[string]interface{}{
				"GatewayID":       event.OrderId,
				"TransactionData": event,
			}).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusRefunded.update: %v", err)
	}

	// If no rows were updated, create a new log
	if updatedLogRows == 0 {
		transactionLog, err = tx.TransactionLog.
			Create().
			SetStatus(transactionlog.StatusOrderRefunded).
			SetTxHash(event.TxHash).
			SetGatewayID(event.OrderId).
			SetNetwork(network.Identifier).
			SetMetadata(
				map[string]interface{}{
					"GatewayID":       event.OrderId,
					"TransactionData": event,
				}).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("UpdateOrderStatusRefunded.create: %v", err)
		}
	}

	// Update payment order status
	paymentOrderUpdate := tx.PaymentOrder.
		Update().
		Where(
			paymentorder.GatewayIDEQ(event.OrderId),
			paymentorder.HasTokenWith(
				tokenent.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		SetBlockNumber(event.BlockNumber).
		SetTxHash(event.TxHash).
		SetStatus(paymentorder.StatusRefunded)

	if transactionLog != nil {
		paymentOrderUpdate = paymentOrderUpdate.AddTransactions(transactionLog)
	}

	_, err = paymentOrderUpdate.Save(ctx)
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusRefunded.aggregator: %v", err)
	}

	// Release reserved balance for refunded orders
	// Get the payment order to access provider and currency info
	paymentOrder, err := tx.PaymentOrder.
		Query().
		Where(
			paymentorder.GatewayIDEQ(event.OrderId),
			paymentorder.HasTokenWith(
				tokenent.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		WithProvider().
		WithProvisionBucket(func(pbq *ent.ProvisionBucketQuery) {
			pbq.WithCurrency()
		}).
		Only(ctx)
	if err == nil && paymentOrder != nil && paymentOrder.Edges.Provider != nil && paymentOrder.Edges.ProvisionBucket != nil && paymentOrder.Edges.ProvisionBucket.Edges.Currency != nil {
		// Only attempt balance operations if we have the required edge data
		// Create a new balance service instance for this transaction
		balanceService := svc.NewBalanceManagementService()

		providerID := paymentOrder.Edges.Provider.ID
		currency := paymentOrder.Edges.ProvisionBucket.Edges.Currency.Code
		amount := paymentOrder.Amount.Mul(paymentOrder.Rate).RoundBank(0)

		err = balanceService.ReleaseReservedBalance(ctx, providerID, currency, amount, nil)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":      fmt.Sprintf("%v", err),
				"OrderID":    event.OrderId,
				"ProviderID": providerID,
				"Currency":   currency,
				"Amount":     amount.String(),
			}).Errorf("failed to release reserved balance for refunded order")
			// Don't return error here as the order status is already updated
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("UpdateOrderStatusRefunded.commit %v", err)
	}

	// Clean up order exclude list from Redis (best effort, don't fail if it errors)
	if paymentOrder != nil {
		orderKey := fmt.Sprintf("order_exclude_list_%s", paymentOrder.ID)
		_ = db.RedisClient.Del(ctx, orderKey).Err()
	}

	// Send webhook notification to sender
	err = utils.SendPaymentOrderWebhook(ctx, paymentOrder)
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusRefunded.webhook: %v", err)
	}

	return nil
}

// UpdateOrderStatusSettled updates the status of a payment order to settled
func UpdateOrderStatusSettled(ctx context.Context, network *ent.Network, event *types.OrderSettledEvent, messageHash string) error {
	tx, err := db.Client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusSettled.db: %v", err)
	}

	// Attempt to update an existing log
	var transactionLog *ent.TransactionLog
	updatedLogRows, err := tx.TransactionLog.
		Update().
		Where(
			transactionlog.StatusEQ(transactionlog.StatusOrderSettled),
			transactionlog.GatewayIDEQ(event.OrderId),
			transactionlog.NetworkEQ(network.Identifier),
		).
		SetTxHash(event.TxHash).
		SetMetadata(map[string]interface{}{
			"GatewayID":   event.OrderId,
			"BlockNumber": event.BlockNumber,
		}).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusSettled.update: %v", err)
	}

	// If no rows were updated, create a new log
	if updatedLogRows == 0 {
		transactionLog, err = tx.TransactionLog.
			Create().
			SetStatus(transactionlog.StatusOrderSettled).
			SetTxHash(event.TxHash).
			SetGatewayID(event.OrderId).
			SetNetwork(network.Identifier).
			SetMetadata(map[string]interface{}{
				"GatewayID":   event.OrderId,
				"BlockNumber": event.BlockNumber,
			}).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("UpdateOrderStatusSettled.create: %v", err)
		}
	}

	// Update payment order status
	splitOrderId, err := uuid.Parse(string(ethcommon.FromHex(event.SplitOrderId)))
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusSettled.splitOrderId: %v", err)
	}

	paymentOrderUpdate := tx.PaymentOrder.
		Update().
		Where(
			paymentorder.IDEQ(splitOrderId),
			paymentorder.HasTokenWith(
				tokenent.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		SetBlockNumber(event.BlockNumber).
		SetTxHash(event.TxHash).
		SetStatus(paymentorder.StatusSettled).
		AddPercentSettled(event.SettlePercent.Div(decimal.NewFromInt(1000)))

	if transactionLog != nil {
		paymentOrderUpdate = paymentOrderUpdate.AddTransactions(transactionLog)
	}

	_, err = paymentOrderUpdate.Save(ctx)
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusSettled.aggregator: %v", err)
	}

	// Update provider balance for settled orders
	// Get the payment order to access provider and currency info
	paymentOrder, err := tx.PaymentOrder.
		Query().
		Where(
			paymentorder.IDEQ(splitOrderId),
			paymentorder.HasTokenWith(
				tokenent.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		WithProvider().
		WithProvisionBucket(func(pbq *ent.ProvisionBucketQuery) {
			pbq.WithCurrency()
		}).
		Only(ctx)
	if err == nil && paymentOrder != nil && paymentOrder.Edges.Provider != nil && paymentOrder.Edges.ProvisionBucket != nil && paymentOrder.Edges.ProvisionBucket.Edges.Currency != nil {
		// Only attempt balance operations if we have the required edge data
		// Create a new balance service instance for this transaction
		balanceService := svc.NewBalanceManagementService()

		providerID := paymentOrder.Edges.Provider.ID
		currency := paymentOrder.Edges.ProvisionBucket.Edges.Currency.Code
		amount := paymentOrder.Amount.Mul(paymentOrder.Rate).RoundBank(0)

		// Get current balance to update it appropriately
		currentBalance, err := balanceService.GetProviderBalance(ctx, providerID, currency)
		if err == nil && currentBalance != nil {
			// For settlement, we only reduce the reserved balance since the available balance was already reduced during assignment
			newReservedBalance := currentBalance.ReservedBalance.Sub(amount)

			// Ensure reserved balance doesn't go negative
			if newReservedBalance.LessThan(decimal.Zero) {
				newReservedBalance = decimal.Zero
			}

			// For settlement, we reduce the reserved balance and total balance
			// Available balance was already reduced during assignment
			// Total balance is reduced because the provider has actually spent money to fulfill the order
			newTotalBalance := currentBalance.TotalBalance.Sub(amount)
			if newTotalBalance.LessThan(decimal.Zero) {
				newTotalBalance = decimal.Zero
			}

			err = balanceService.UpdateProviderBalance(ctx, providerID, currency, currentBalance.AvailableBalance, newTotalBalance, newReservedBalance)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":      fmt.Sprintf("%v", err),
					"OrderID":    event.OrderId,
					"ProviderID": providerID,
					"Currency":   currency,
					"Amount":     amount.String(),
				}).Errorf("failed to update provider balance for settled order")
				// Don't return error here as the order status is already updated
			}
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("UpdateOrderStatusSettled.sender %v", err)
	}

	// Clean up order exclude list from Redis (best effort, don't fail if it errors)
	if paymentOrder != nil {
		orderKey := fmt.Sprintf("order_exclude_list_%s", paymentOrder.ID)
		_ = db.RedisClient.Del(ctx, orderKey).Err()
	}

	// Send webhook notification to sender
	err = utils.SendPaymentOrderWebhook(ctx, paymentOrder)
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusSettled.webhook: %v", err)
	}

	return nil
}

// GetProvisionBucket gets a provision bucket for the given amount and currency.
func GetProvisionBucket(ctx context.Context, amount decimal.Decimal, currency *ent.FiatCurrency) (*ent.ProvisionBucket, bool, error) {
	provisionBucket, err := db.Client.ProvisionBucket.
		Query().
		Where(
			provisionbucket.MaxAmountGTE(amount),
			provisionbucket.MinAmountLTE(amount),
			provisionbucket.HasCurrencyWith(
				fiatcurrency.IDEQ(currency.ID),
			),
		).
		WithCurrency().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			// Check if the amount is less than the minimum bucket
			minBucket, err := db.Client.ProvisionBucket.
				Query().
				Where(
					provisionbucket.HasCurrencyWith(
						fiatcurrency.IDEQ(currency.ID),
					),
				).
				Order(ent.Asc(provisionbucket.FieldMinAmount)).
				First(ctx)
			if err != nil {
				return nil, false, fmt.Errorf("failed to fetch minimum bucket: %w", err)
			}
			if amount.LessThan(minBucket.MinAmount) {
				return nil, true, nil
			}
		}
		return nil, false, fmt.Errorf("failed to fetch provision bucket: %w", err)
	}

	return provisionBucket, false, nil
}

// HandleCancellation handles the cancellation of a payment order.
func HandleCancellation(ctx context.Context, createdPaymentOrder *ent.PaymentOrder, paymentOrderFields *types.PaymentOrderFields, cancellationReason string, refundOrder func(context.Context, *ent.Network, string) error) error {
	// paymentOrderFields and createdPaymentOrder are mutually exclusive
	if (createdPaymentOrder == nil && paymentOrderFields == nil) || (createdPaymentOrder != nil && paymentOrderFields != nil) {
		return nil
	}

	if paymentOrderFields != nil {
		orderBuilder := db.Client.PaymentOrder.
			Create().
			SetToken(paymentOrderFields.Token).
			SetGatewayID(paymentOrderFields.GatewayID).
			SetAmount(paymentOrderFields.Amount).
			SetRate(paymentOrderFields.Rate).
			SetProtocolFee(paymentOrderFields.ProtocolFee).
			SetOrderPercent(decimal.NewFromInt(100)).
			SetBlockNumber(paymentOrderFields.BlockNumber).
			SetTxHash(paymentOrderFields.TxHash).
			SetInstitution(paymentOrderFields.Institution).
			SetAccountIdentifier(paymentOrderFields.AccountIdentifier).
			SetAccountName(paymentOrderFields.AccountName).
			SetSender(paymentOrderFields.Sender).
			SetAmountInUsd(paymentOrderFields.AmountInUSD).
			SetMemo(paymentOrderFields.Memo).
			SetMetadata(paymentOrderFields.Metadata).
			SetCancellationCount(3).
			SetCancellationReasons([]string{cancellationReason}).
			SetStatus(paymentorder.StatusCancelled)

		// Only set ProvisionBucket if it's not nil
		if paymentOrderFields.ProvisionBucket != nil {
			orderBuilder = orderBuilder.SetProvisionBucket(paymentOrderFields.ProvisionBucket)
		}

		// Set provider if ProviderID exists
		if paymentOrderFields.ProviderID != "" {
			provider, err := db.Client.ProviderProfile.Query().Where(providerprofile.IDEQ(paymentOrderFields.ProviderID)).Only(ctx)
			if err == nil && provider != nil {
				orderBuilder = orderBuilder.SetProvider(provider)
			}
		}

		order, err := orderBuilder.Save(ctx)
		if err != nil {
			return fmt.Errorf("%s - failed to create payment order: %w", paymentOrderFields.GatewayID, err)
		}

		network, err := paymentOrderFields.Token.QueryNetwork().Only(ctx)
		if err != nil {
			return fmt.Errorf("%s - failed to fetch network: %w", paymentOrderFields.GatewayID, err)
		}

		err = refundOrder(ctx, network, paymentOrderFields.GatewayID)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":        fmt.Sprintf("%v", err),
				"OrderID":      order.ID.String(),
				"OrderTrxHash": order.TxHash,
				"GatewayID":    order.GatewayID,
			}).Errorf("Handle cancellation failed to refund order")
		}

	} else if createdPaymentOrder != nil {
		_, err := db.Client.PaymentOrder.
			Update().
			Where(
				paymentorder.IDEQ(createdPaymentOrder.ID),
			).
			SetCancellationCount(3).
			SetCancellationReasons([]string{cancellationReason}).
			SetStatus(paymentorder.StatusCancelled).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("%s - failed to update payment order: %w", createdPaymentOrder.GatewayID, err)
		}

		network, err := createdPaymentOrder.QueryToken().QueryNetwork().Only(ctx)
		if err != nil {
			return fmt.Errorf("%s - failed to fetch network: %w", createdPaymentOrder.GatewayID, err)
		}

		err = refundOrder(ctx, network, createdPaymentOrder.GatewayID)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":        fmt.Sprintf("%v", err),
				"OrderID":      fmt.Sprintf("0x%v", hex.EncodeToString(createdPaymentOrder.ID[:])),
				"OrderTrxHash": createdPaymentOrder.TxHash,
				"GatewayID":    createdPaymentOrder.GatewayID,
			}).Errorf("Handle cancellation failed to refund order")
		}
	}

	return nil
}

// CheckAMLCompliance checks if a transaction is compliant with AML regulations.
func CheckAMLCompliance(rpcUrl string, txHash string) (bool, error) {
	if !strings.Contains(rpcUrl, "shield3") {
		return true, nil
	}

	type Transaction struct {
		Kind int         `json:"__kind"`
		Data interface{} `json:"data"`
	}

	type Response struct {
		Transaction Transaction `json:"transaction"`
		Decision    string      `json:"decision"`
	}

	// Make RPC call to Shield3 here
	var err error
	var client *rpc.Client
	client, err = rpc.Dial(rpcUrl)
	if err != nil {
		return false, fmt.Errorf("failed to connect to RPC client: %v", err)
	}

	var result json.RawMessage
	err = client.Call(&result, "eth_backfillTransaction", txHash)
	if err != nil {
		return false, fmt.Errorf("failed to backfill transaction: %v", err)
	}

	var backfillTransaction Response
	err = json.Unmarshal(result, &backfillTransaction)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if backfillTransaction.Decision == "Allow" {
		return true, nil
	}

	return false, nil
}

// HandleReceiveAddressValidity handles the validity of a receive address.
func HandleReceiveAddressValidity(ctx context.Context, paymentOrder *ent.PaymentOrder) error {
	if paymentOrder.ReceiveAddressExpiry.IsZero() {
		return nil
	}

	if paymentOrder.Status != paymentorder.StatusPending && paymentOrder.Status != paymentorder.StatusExpired {
		validUntilIsFarGone := paymentOrder.ReceiveAddressExpiry.Before(time.Now().Add(-(2 * time.Minute)))
		isExpired := paymentOrder.ReceiveAddressExpiry.Before(time.Now())

		if validUntilIsFarGone {
			_, err := paymentOrder.
				Update().
				SetReceiveAddressExpiry(time.Now().Add(orderConf.ReceiveAddressValidity)).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("HandleReceiveAddressValidity.db: %v", err)
			}
		} else if isExpired && paymentOrder.Status != paymentorder.StatusExpired {
			// Expire payment order
			_, err := paymentOrder.
				Update().
				SetStatus(paymentorder.StatusExpired).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("HandleReceiveAddressValidity.db: %v", err)
			}

			// Send webhook notification for expired payment order
			// The paymentOrder already has all necessary edges loaded from tasks.go
			err = utils.SendPaymentOrderWebhook(ctx, paymentOrder)
			if err != nil {
				logger.WithFields(logger.Fields{
					"OrderID":     paymentOrder.ID,
					"MessageHash": paymentOrder.MessageHash,
					"Error":       err.Error(),
				}).Errorf("Failed to send expired payment order webhook")
			}
		}
	}

	return nil
}

// deleteTransferWebhook deletes the transfer webhook associated with a payment order
func deleteTransferWebhook(ctx context.Context, txHash string) error {
	// Get the payment order by txHash
	paymentOrder, err := db.Client.PaymentOrder.
		Query().
		Where(paymentorder.TxHashEQ(txHash)).
		WithPaymentWebhook().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			// No payment order found, nothing to delete
			return nil
		}
		return fmt.Errorf("failed to fetch payment order: %w", err)
	}

	// Check if there's an associated webhook
	if paymentOrder.Edges.PaymentWebhook == nil {
		// No webhook found, nothing to delete
		return nil
	}

	// Create engine service to delete the webhook
	engineService := svc.NewEngineService()

	// Delete the webhook from thirdweb and our database
	err = engineService.DeleteWebhookAndRecord(ctx, paymentOrder.Edges.PaymentWebhook.WebhookID)
	if err != nil {
		return fmt.Errorf("failed to delete webhook: %w", err)
	}

	return nil
}

// ensureTransactionLog ensures a transaction log exists for the order, creating it if needed.
// Returns the transaction log and any error.
func ensureTransactionLog(
	ctx context.Context,
	tx *ent.Tx,
	network *ent.Network,
	paymentOrderFields *types.PaymentOrderFields,
) (*ent.TransactionLog, error) {
	// Check if transaction log already exists
	existingLog, err := tx.TransactionLog.
		Query().
		Where(
			transactionlog.StatusEQ(transactionlog.StatusOrderCreated),
			transactionlog.TxHashEQ(paymentOrderFields.TxHash),
			transactionlog.GatewayIDEQ(paymentOrderFields.GatewayID),
		).
		Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return nil, fmt.Errorf("%s - failed to fetch transaction log: %w", paymentOrderFields.GatewayID, err)
	}
	if existingLog != nil {
		return existingLog, nil
	}

	// Create new transaction log
	transactionLog, err := tx.TransactionLog.
		Create().
		SetStatus(transactionlog.StatusOrderCreated).
		SetTxHash(paymentOrderFields.TxHash).
		SetNetwork(network.Identifier).
		SetGatewayID(paymentOrderFields.GatewayID).
		SetMetadata(
			map[string]interface{}{
				"Token":           paymentOrderFields.Token,
				"GatewayID":       paymentOrderFields.GatewayID,
				"Amount":          paymentOrderFields.Amount,
				"Rate":            paymentOrderFields.Rate,
				"Memo":            paymentOrderFields.Memo,
				"Metadata":        paymentOrderFields.Metadata,
				"ProviderID":      paymentOrderFields.ProviderID,
				"ProvisionBucket": paymentOrderFields.ProvisionBucket,
			}).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s - failed to create transaction log: %w", paymentOrderFields.GatewayID, err)
	}

	return transactionLog, nil
}

// processPaymentOrderPostCreation handles post-creation tasks: webhook deletion, webhook sending, AML check, and provider assignment.
func processPaymentOrderPostCreation(
	ctx context.Context,
	paymentOrder *ent.PaymentOrder,
	network *ent.Network,
	event *types.OrderCreatedEvent,
	paymentOrderFields *types.PaymentOrderFields,
	refundOrder func(context.Context, *ent.Network, string) error,
	assignPaymentOrder func(context.Context, types.PaymentOrderFields) error,
) error {
	// Delete the transfer webhook now that payment order is created/updated
	err := deleteTransferWebhook(ctx, event.TxHash)
	if err != nil {
		logger.Errorf("Failed to delete transfer webhook for payment order: %v", err)
		// Don't fail the entire operation if webhook deletion fails
	}

	// Send webhook notification to sender
	err = utils.SendPaymentOrderWebhook(ctx, paymentOrder)
	if err != nil {
		logger.WithFields(logger.Fields{
			"OrderID":     paymentOrder.ID,
			"MessageHash": paymentOrder.MessageHash,
			"Error":       err.Error(),
		}).Errorf("Failed to send payment order webhook")
	}

	// Check AML compliance
	if serverConf.Environment == "production" && !strings.HasPrefix(network.Identifier, "tron") && !strings.HasPrefix(network.Identifier, "starknet") {
		ok, err := CheckAMLCompliance(network.RPCEndpoint, event.TxHash)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":    fmt.Sprintf("%v", err),
				"endpoint": network.RPCEndpoint,
				"TxHash":   event.TxHash,
			}).Errorf("Failed to check AML Compliance")
		}

		if !ok && err == nil {
			err := HandleCancellation(ctx, paymentOrder, nil, "AML compliance check failed", refundOrder)
			if err != nil {
				return fmt.Errorf("checkAMLCompliance.RefundOrder: %w", err)
			}
			return nil
		}
	}

	// Assign the payment order to a provider
	paymentOrderFields.ID = paymentOrder.ID
	_ = assignPaymentOrder(ctx, *paymentOrderFields)

	return nil
}

// validateAndPreparePaymentOrderData validates the blockchain event data and prepares payment order fields.
// Returns the prepared fields, token, institution, currency, provision bucket, and any error.
func validateAndPreparePaymentOrderData(
	ctx context.Context,
	network *ent.Network,
	event *types.OrderCreatedEvent,
	refundOrder func(context.Context, *ent.Network, string) error,
) (*types.PaymentOrderFields, *ent.Token, *ent.Institution, *ent.FiatCurrency, *ent.ProvisionBucket, error) {
	// Get token from db
	token, err := db.Client.Token.
		Query().
		Where(
			tokenent.ContractAddressEQ(event.Token),
			tokenent.HasNetworkWith(
				networkent.IDEQ(network.ID),
			),
		).
		WithNetwork().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			// Cannot call createBasicPaymentOrderAndCancel without token - refund directly
			refundErr := refundOrder(ctx, network, event.OrderId)
			if refundErr != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("token lookup failed and refund failed: %w", refundErr)
			}
		}
		return nil, nil, nil, nil, nil, nil
	}

	// Get order recipient from message hash
	recipient, err := cryptoUtils.GetOrderRecipientFromMessageHash(event.MessageHash)
	if err != nil {
		return nil, nil, nil, nil, nil, createBasicPaymentOrderAndCancel(ctx, event, network, token, nil, "Message hash decryption failed", refundOrder)
	}

	// Get institution
	institution, err := utils.GetInstitutionByCode(ctx, recipient.Institution, true)
	if err != nil {
		return nil, nil, nil, nil, nil, createBasicPaymentOrderAndCancel(ctx, event, network, token, recipient, "Institution lookup failed", refundOrder)
	}

	// Get currency
	currency, err := db.Client.FiatCurrency.
		Query().
		Where(
			fiatcurrency.IsEnabledEQ(true),
			fiatcurrency.CodeEQ(institution.Edges.FiatCurrency.Code),
		).
		Only(ctx)
	if err != nil {
		return nil, nil, nil, nil, nil, createBasicPaymentOrderAndCancel(ctx, event, network, token, recipient, "Currency lookup failed", refundOrder)
	}

	// Adjust amounts for token decimals
	event.Amount = event.Amount.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(token.Decimals))))
	event.ProtocolFee = event.ProtocolFee.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(token.Decimals))))

	// Get provision bucket
	provisionBucket, isLessThanMin, err := GetProvisionBucket(ctx, event.Amount.Mul(event.Rate), currency)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Amount":   event.Amount,
			"Currency": currency,
		}).Errorf("failed to fetch provision bucket when creating payment order")

		return nil, nil, nil, nil, nil, createBasicPaymentOrderAndCancel(ctx, event, network, token, recipient, "Provision bucket lookup failed", refundOrder)
	}

	// Create payment order fields
	paymentOrderFields := &types.PaymentOrderFields{
		Token:             token,
		Network:           network,
		GatewayID:         event.OrderId,
		Amount:            event.Amount,
		Rate:              event.Rate,
		ProtocolFee:       event.ProtocolFee,
		AmountInUSD:       utils.CalculatePaymentOrderAmountInUSD(event.Amount, token, institution),
		BlockNumber:       int64(event.BlockNumber),
		TxHash:            event.TxHash,
		Institution:       recipient.Institution,
		AccountIdentifier: recipient.AccountIdentifier,
		AccountName:       recipient.AccountName,
		Sender:            event.Sender,
		ProviderID:        recipient.ProviderID,
		Memo:              recipient.Memo,
		MessageHash:       event.MessageHash,
		Metadata:          recipient.Metadata,
		ProvisionBucket:   provisionBucket,
		OrderType:         "regular",
	}

	if isLessThanMin {
		err := HandleCancellation(ctx, nil, paymentOrderFields, "Amount is less than the minimum bucket", refundOrder)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to handle cancellation: %w", err)
		}
		return nil, nil, nil, nil, nil, nil
	}

	// Validate rate
	rateResult, rateErr := utils.ValidateRate(
		ctx,
		token,
		currency,
		event.Amount,
		paymentOrderFields.ProviderID,
		token.Edges.Network.Identifier,
	)

	if rateResult.Rate == decimal.NewFromInt(1) && paymentOrderFields.Rate != decimal.NewFromInt(1) {
		err := HandleCancellation(ctx, nil, paymentOrderFields, "Rate validation failed", refundOrder)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to handle cancellation: %w", err)
		}
		return nil, nil, nil, nil, nil, nil
	}

	if rateErr != nil {
		err := HandleCancellation(ctx, nil, paymentOrderFields, fmt.Sprintf("Rate validation failed: %s", rateErr.Error()), refundOrder)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to handle cancellation: %w", err)
		}
		return nil, nil, nil, nil, nil, nil
	}

	// Check if event rate is within 0.1% tolerance of validated rate
	tolerance := rateResult.Rate.Mul(decimal.NewFromFloat(0.001)) // 0.1% tolerance
	rateDiff := event.Rate.Sub(rateResult.Rate).Abs()

	if rateDiff.GreaterThan(tolerance) {
		err := HandleCancellation(ctx, nil, paymentOrderFields, "Rate validation failed", refundOrder)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to handle cancellation: %w", err)
		}
		return nil, nil, nil, nil, nil, nil
	}

	// Use order type from ValidateRate result
	paymentOrderFields.OrderType = rateResult.OrderType.String()

	// If order type is OTC, set provider ID from rate result
	if paymentOrderFields.OrderType == "otc" && rateResult.ProviderID != "" {
		paymentOrderFields.ProviderID = rateResult.ProviderID
	}

	// Handle private order checks
	isPrivate := false
	if paymentOrderFields.ProviderID != "" {
		orderToken, err := db.Client.ProviderOrderToken.
			Query().
			Where(
				providerordertoken.NetworkEQ(token.Edges.Network.Identifier),
				providerordertoken.HasProviderWith(
					providerprofile.IDEQ(paymentOrderFields.ProviderID),
					providerprofile.HasProviderCurrenciesWith(
						providercurrencies.HasCurrencyWith(fiatcurrency.CodeEQ(institution.Edges.FiatCurrency.Code)),
						providercurrencies.IsAvailableEQ(true),
					),
					providerprofile.HasUserWith(user.KybVerificationStatusEQ(user.KybVerificationStatusApproved)),
				),
				providerordertoken.HasTokenWith(tokenent.IDEQ(token.ID)),
				providerordertoken.HasCurrencyWith(
					fiatcurrency.CodeEQ(institution.Edges.FiatCurrency.Code),
				),
				providerordertoken.AddressNEQ(""),
			).
			WithProvider().
			Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				// Provider could not be available for several reasons
				// 1. Provider is not available
				// 2. Provider does not support the token
				// 3. Provider does not support the network
				// 4. Provider does not support the currency
				// 5. Provider have not configured a settlement address for the network
				_ = HandleCancellation(ctx, nil, paymentOrderFields, "Provider not available", refundOrder)
				return nil, nil, nil, nil, nil, nil
			} else {
				return nil, nil, nil, nil, nil, fmt.Errorf("%s - failed to fetch provider: %w", paymentOrderFields.GatewayID, err)
			}
		}

		// Check if provider is private - private orders don't require provision buckets
		if orderToken != nil && orderToken.Edges.Provider != nil && orderToken.Edges.Provider.VisibilityMode == providerprofile.VisibilityModePrivate {
			isPrivate = true
		}
	}

	if provisionBucket == nil && !isPrivate {
		err := HandleCancellation(ctx, nil, paymentOrderFields, "Amount is larger than the maximum bucket", refundOrder)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("failed to handle cancellation: %w", err)
		}
		return nil, nil, nil, nil, nil, nil
	}

	return paymentOrderFields, token, institution, currency, provisionBucket, nil
}

// createBasicPaymentOrderAndCancel creates a basic payment order and cancels it with the given reason
func createBasicPaymentOrderAndCancel(
	ctx context.Context,
	event *types.OrderCreatedEvent,
	network *ent.Network,
	token *ent.Token,
	recipient *types.PaymentOrderRecipient,
	cancellationReason string,
	refundOrder func(context.Context, *ent.Network, string) error,
) error {
	// Apply token decimal adjustment to amount and protocol fee
	adjustedAmount := event.Amount.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(token.Decimals))))
	adjustedProtocolFee := event.ProtocolFee.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(token.Decimals))))

	// Create a basic payment order for cancellation
	paymentOrder := types.PaymentOrderFields{
		Token:       token,
		Network:     network,
		GatewayID:   event.OrderId,
		Amount:      adjustedAmount,
		Rate:        event.Rate,
		ProtocolFee: adjustedProtocolFee,
		AmountInUSD: func() decimal.Decimal {
			if recipient == nil {
				return decimal.Zero
			}
			institution, err := utils.GetInstitutionByCode(ctx, recipient.Institution, true)
			if err != nil {
				return decimal.Zero
			}
			return utils.CalculatePaymentOrderAmountInUSD(adjustedAmount, token, institution)
		}(),
		BlockNumber: int64(event.BlockNumber),
		TxHash:      event.TxHash,
		Sender:      event.Sender,
		MessageHash: event.MessageHash,
	}

	// Add recipient fields if available
	if recipient != nil {
		paymentOrder.Institution = recipient.Institution
		paymentOrder.AccountIdentifier = recipient.AccountIdentifier
		paymentOrder.AccountName = recipient.AccountName
		paymentOrder.ProviderID = recipient.ProviderID
		paymentOrder.Memo = recipient.Memo
		paymentOrder.Metadata = recipient.Metadata
	}

	err := HandleCancellation(ctx, nil, &paymentOrder, cancellationReason, refundOrder)
	if err != nil {
		return fmt.Errorf("failed to handle cancellation due to %s: %w", cancellationReason, err)
	}
	return nil
}
