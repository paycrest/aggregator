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
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/provisionbucket"
	"github.com/paycrest/aggregator/ent/receiveaddress"
	tokenent "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/transactionlog"
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

// CreateLockPaymentOrder saves a lock payment order in the database
func CreateLockPaymentOrder(
	ctx context.Context,
	network *ent.Network,
	event *types.OrderCreatedEvent,
	refundOrder func(context.Context, *ent.Network, string) error,
	assignLockPaymentOrder func(context.Context, types.LockPaymentOrderFields) error,
) error {
	// Check for existing address with txHash
	orderCount, err := db.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.Or(
				lockpaymentorder.TxHashEQ(event.TxHash),
				lockpaymentorder.GatewayIDEQ(event.OrderId),
			),
			lockpaymentorder.HasTokenWith(
				tokenent.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		Count(ctx)
	if err != nil {
		return fmt.Errorf("CreateLockPaymentOrder.db: %v", err)
	}

	if orderCount > 0 {
		// This transfer has already been indexed
		return nil
	}

	go func() {
		timeToWait := 2 * time.Second

		time.Sleep(timeToWait)
		_ = utils.Retry(10, timeToWait, func() error {
			// Update payment order with the gateway ID
			paymentOrder, err := db.Client.PaymentOrder.
				Query().
				Where(
					paymentorder.TxHashEQ(event.TxHash),
				).
				Only(ctx)
			if err != nil {
				if ent.IsNotFound(err) {
					// Payment order does not exist, retry
					return fmt.Errorf("trigger retry")
				} else {
					return fmt.Errorf("CreateLockPaymentOrder.db: %v", err)
				}
			}

			_, err = db.Client.PaymentOrder.
				Update().
				Where(paymentorder.IDEQ(paymentOrder.ID)).
				SetBlockNumber(int64(event.BlockNumber)).
				SetGatewayID(event.OrderId).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("CreateLockPaymentOrder.db: %v", err)
			}

			return nil
		})
	}()

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
		return nil
	}

	// Get order recipient from message hash
	recipient, err := cryptoUtils.GetOrderRecipientFromMessageHash(event.MessageHash)
	if err != nil {
		return nil
	}

	// Get provision bucket
	institution, err := utils.GetInstitutionByCode(ctx, recipient.Institution, true)
	if err != nil {
		return nil
	}

	currency, err := db.Client.FiatCurrency.
		Query().
		Where(
			fiatcurrency.IsEnabledEQ(true),
			fiatcurrency.CodeEQ(institution.Edges.FiatCurrency.Code),
		).
		Only(ctx)
	if err != nil {
		return nil
	}

	provisionBucket, isLessThanMin, err := GetProvisionBucket(ctx, event.Amount.Mul(event.Rate), currency)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":    fmt.Sprintf("%v", err),
			"Amount":   event.Amount,
			"Currency": currency,
		}).Errorf("failed to fetch provision bucket when creating lock payment order")
	}

	// Create lock payment order fields
	lockPaymentOrder := types.LockPaymentOrderFields{
		Token:             token,
		Network:           network,
		GatewayID:         event.OrderId,
		Amount:            event.Amount,
		Rate:              event.Rate,
		BlockNumber:       int64(event.BlockNumber),
		TxHash:            event.TxHash,
		Institution:       recipient.Institution,
		AccountIdentifier: recipient.AccountIdentifier,
		AccountName:       recipient.AccountName,
		ProviderID:        recipient.ProviderID,
		Memo:              recipient.Memo,
		Metadata:          recipient.Metadata,
		ProvisionBucket:   provisionBucket,
	}

	if isLessThanMin {
		err := HandleCancellation(ctx, nil, &lockPaymentOrder, "Amount is less than the minimum bucket", refundOrder)
		if err != nil {
			return fmt.Errorf("failed to handle cancellation: %w", err)
		}
		return nil
	}

	// Handle private order checks
	isPrivate := false
	if lockPaymentOrder.ProviderID != "" {
		orderToken, err := db.Client.ProviderOrderToken.
			Query().
			Where(
				providerordertoken.NetworkEQ(token.Edges.Network.Identifier),
				providerordertoken.HasProviderWith(
					providerprofile.IDEQ(lockPaymentOrder.ProviderID),
					providerprofile.IsAvailableEQ(true),
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
				_ = HandleCancellation(ctx, nil, &lockPaymentOrder, "Provider not available", refundOrder)
				return nil
			} else {
				return fmt.Errorf("%s - failed to fetch provider: %w", lockPaymentOrder.GatewayID, err)
			}
		}

		if orderToken.Edges.Provider.VisibilityMode == providerprofile.VisibilityModePrivate {
			normalizedAmount := lockPaymentOrder.Amount
			if strings.EqualFold(token.BaseCurrency, institution.Edges.FiatCurrency.Code) && token.BaseCurrency != "USD" {
				rateResponse, err := utils.GetTokenRateFromQueue("USDT", normalizedAmount, institution.Edges.FiatCurrency.Code, currency.MarketRate)
				if err != nil {
					return fmt.Errorf("failed to get token rate: %w", err)
				}
				normalizedAmount = lockPaymentOrder.Amount.Div(rateResponse)
			}

			if normalizedAmount.GreaterThan(orderToken.MaxOrderAmount) {
				err := HandleCancellation(ctx, nil, &lockPaymentOrder, "Amount is greater than the maximum order amount of the provider", refundOrder)
				if err != nil {
					return fmt.Errorf("%s - failed to cancel order: %w", lockPaymentOrder.GatewayID, err)
				}
				return nil
			} else if normalizedAmount.LessThan(orderToken.MinOrderAmount) {
				err := HandleCancellation(ctx, nil, &lockPaymentOrder, "Amount is less than the minimum order amount of the provider", refundOrder)
				if err != nil {
					return fmt.Errorf("%s - failed to cancel order: %w", lockPaymentOrder.GatewayID, err)
				}
				return nil
			}
		}
	}

	if provisionBucket == nil && !isPrivate {
		// TODO: Activate this when split order is tested and working
		// Split lock payment order into multiple orders
		// err = s.splitLockPaymentOrder(
		// 	ctx, client, lockPaymentOrder, currency,
		// )
		// if err != nil {
		// 	return fmt.Errorf("%s - failed to split lock payment order: %w", lockPaymentOrder.GatewayID, err)
		// }

		err = HandleCancellation(ctx, nil, &lockPaymentOrder, "Amount is larger than the maximum bucket", refundOrder)
		if err != nil {
			return fmt.Errorf("failed to handle cancellation: %w", err)
		}
		return nil
	} else {
		// Create LockPaymentOrder and recipient in a transaction
		tx, err := db.Client.Tx(ctx)
		if err != nil {
			return fmt.Errorf("%s failed to initiate db transaction %w", lockPaymentOrder.GatewayID, err)
		}

		var transactionLog *ent.TransactionLog
		_, err = tx.TransactionLog.
			Query().
			Where(
				transactionlog.StatusEQ(transactionlog.StatusOrderCreated),
				transactionlog.TxHashEQ(lockPaymentOrder.TxHash),
				transactionlog.GatewayIDEQ(lockPaymentOrder.GatewayID),
			).
			Only(ctx)
		if err != nil {
			if !ent.IsNotFound(err) {
				return fmt.Errorf("%s - failed to fetch transaction Log: %w", lockPaymentOrder.GatewayID, err)
			} else {
				transactionLog, err = tx.TransactionLog.
					Create().
					SetStatus(transactionlog.StatusOrderCreated).
					SetTxHash(lockPaymentOrder.TxHash).
					SetNetwork(network.Identifier).
					SetGatewayID(lockPaymentOrder.GatewayID).
					SetMetadata(
						map[string]interface{}{
							"Token":           lockPaymentOrder.Token,
							"GatewayID":       lockPaymentOrder.GatewayID,
							"Amount":          lockPaymentOrder.Amount,
							"Rate":            lockPaymentOrder.Rate,
							"Memo":            lockPaymentOrder.Memo,
							"Metadata":        lockPaymentOrder.Metadata,
							"ProviderID":      lockPaymentOrder.ProviderID,
							"ProvisionBucket": lockPaymentOrder.ProvisionBucket,
						}).
					Save(ctx)
				if err != nil {
					return fmt.Errorf("%s - failed to create transaction Log : %w", lockPaymentOrder.GatewayID, err)
				}
			}
		}

		// Create lock payment order in db
		orderBuilder := tx.LockPaymentOrder.
			Create().
			SetToken(lockPaymentOrder.Token).
			SetGatewayID(lockPaymentOrder.GatewayID).
			SetAmount(lockPaymentOrder.Amount).
			SetRate(lockPaymentOrder.Rate).
			SetOrderPercent(decimal.NewFromInt(100)).
			SetBlockNumber(lockPaymentOrder.BlockNumber).
			SetTxHash(lockPaymentOrder.TxHash).
			SetInstitution(lockPaymentOrder.Institution).
			SetAccountIdentifier(lockPaymentOrder.AccountIdentifier).
			SetAccountName(lockPaymentOrder.AccountName).
			SetMemo(lockPaymentOrder.Memo).
			SetMetadata(lockPaymentOrder.Metadata).
			SetProvisionBucket(lockPaymentOrder.ProvisionBucket)

		if lockPaymentOrder.ProviderID != "" {
			orderBuilder = orderBuilder.SetProviderID(lockPaymentOrder.ProviderID)
		}

		if transactionLog != nil {
			orderBuilder = orderBuilder.AddTransactions(transactionLog)
		}

		orderCreated, err := orderBuilder.Save(ctx)
		if err != nil {
			return fmt.Errorf("%s - failed to create lock payment order: %w", lockPaymentOrder.GatewayID, err)
		}

		// Commit the transaction
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("%s - failed to create lock payment order: %w", lockPaymentOrder.GatewayID, err)
		}

		// Check AML compliance
		if serverConf.Environment == "production" && !strings.HasPrefix(network.Identifier, "tron") {
			ok, err := CheckAMLCompliance(network.RPCEndpoint, event.TxHash)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":    fmt.Sprintf("%v", err),
					"endpoint": network.RPCEndpoint,
					"TxHash":   event.TxHash,
				}).Errorf("Failed to check AML Compliance")
			}

			if !ok && err == nil {
				err := HandleCancellation(ctx, orderCreated, nil, "AML compliance check failed", refundOrder)
				if err != nil {
					return fmt.Errorf("checkAMLCompliance.RefundOrder: %w", err)
				}
				return nil
			}
		}

		// Assign the lock payment order to a provider
		lockPaymentOrder.ID = orderCreated.ID
		_ = assignLockPaymentOrder(ctx, lockPaymentOrder)
	}

	return nil
}

// UpdateOrderStatusRefunded updates the status of a payment order to refunded
func UpdateOrderStatusRefunded(ctx context.Context, network *ent.Network, event *types.OrderRefundedEvent) error {
	// Fetch payment order
	paymentOrderExists := true
	paymentOrder, err := db.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.GatewayIDEQ(event.OrderId),
			paymentorder.HasTokenWith(
				tokenent.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		WithSenderProfile().
		WithLinkedAddress().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			// Payment order does not exist, no need to update
			paymentOrderExists = false
		} else {
			return fmt.Errorf("UpdateOrderStatusRefunded.fetchOrder: %v", err)
		}
	}

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

	// Aggregator side status update
	lockPaymentOrderUpdate := tx.LockPaymentOrder.
		Update().
		Where(
			lockpaymentorder.GatewayIDEQ(event.OrderId),
			lockpaymentorder.HasTokenWith(
				tokenent.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		SetBlockNumber(event.BlockNumber).
		SetTxHash(event.TxHash).
		SetStatus(lockpaymentorder.StatusRefunded)

	if transactionLog != nil {
		lockPaymentOrderUpdate = lockPaymentOrderUpdate.AddTransactions(transactionLog)
	}

	_, err = lockPaymentOrderUpdate.Save(ctx)
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusRefunded.aggregator: %v", err)
	}

	// Sender side status update
	if paymentOrderExists && paymentOrder.Status != paymentorder.StatusRefunded {
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
			SetTxHash(event.TxHash).
			SetStatus(paymentorder.StatusRefunded)

		if paymentOrder.Edges.LinkedAddress != nil {
			paymentOrderUpdate = paymentOrderUpdate.SetGatewayID("")
		}

		if transactionLog != nil {
			paymentOrderUpdate = paymentOrderUpdate.AddTransactions(transactionLog)
		}

		_, err = paymentOrderUpdate.Save(ctx)
		if err != nil {
			return fmt.Errorf("UpdateOrderStatusRefunded.sender: %v", err)
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("UpdateOrderStatusRefunded.commit %v", err)
	}

	if paymentOrderExists && paymentOrder.Status != paymentorder.StatusRefunded {
		paymentOrder.Status = paymentorder.StatusRefunded
		paymentOrder.TxHash = event.TxHash

		// Send webhook notification to sender
		err = utils.SendPaymentOrderWebhook(ctx, paymentOrder)
		if err != nil {
			return fmt.Errorf("UpdateOrderStatusRefunded.webhook: %v", err)
		}
	}

	return nil
}

// UpdateOrderStatusSettled updates the status of a payment order to settled
func UpdateOrderStatusSettled(ctx context.Context, network *ent.Network, event *types.OrderSettledEvent) error {
	// Fetch payment order
	paymentOrderExists := true
	paymentOrder, err := db.Client.PaymentOrder.
		Query().
		Where(
			paymentorder.GatewayIDEQ(event.OrderId),
			paymentorder.HasTokenWith(
				tokenent.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		WithSenderProfile().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			// Payment order does not exist, no need to update
			paymentOrderExists = false
		} else {
			return fmt.Errorf("UpdateOrderStatusSettled.fetchOrder: %v", err)
		}
	}

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
			"GatewayID":       event.OrderId,
			"TransactionData": event,
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
				"GatewayID":       event.OrderId,
				"TransactionData": event,
			}).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("UpdateOrderStatusSettled.create: %v", err)
		}
	}

	// Aggregator side status update
	splitOrderId, err := uuid.Parse(string(ethcommon.FromHex(event.SplitOrderId)))
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusSettled.splitOrderId: %v", err)
	}

	lockPaymentOrderUpdate := tx.LockPaymentOrder.
		Update().
		Where(
			lockpaymentorder.IDEQ(splitOrderId),
			lockpaymentorder.HasTokenWith(
				tokenent.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		SetBlockNumber(int64(event.BlockNumber)).
		SetTxHash(event.TxHash).
		SetStatus(lockpaymentorder.StatusSettled)

	if transactionLog != nil {
		lockPaymentOrderUpdate = lockPaymentOrderUpdate.AddTransactions(transactionLog)
	}

	_, err = lockPaymentOrderUpdate.Save(ctx)
	if err != nil {
		return fmt.Errorf("UpdateOrderStatusSettled.aggregator: %v", err)
	}

	settledPercent := decimal.NewFromInt(0)
	// Sender side status update
	if paymentOrderExists && paymentOrder.Status != paymentorder.StatusSettled {
		paymentOrderUpdate := tx.PaymentOrder.
			Update().
			Where(
				paymentorder.GatewayIDEQ(event.OrderId),
			).
			SetBlockNumber(int64(event.BlockNumber)).
			SetTxHash(event.TxHash)

		// Convert settled percent to BPS and update
		settledPercent = paymentOrder.PercentSettled.Add(event.SettlePercent.Div(decimal.NewFromInt(1000)))

		// If settled percent is 100%, mark order as settled
		if settledPercent.GreaterThanOrEqual(decimal.NewFromInt(100)) {
			settledPercent = decimal.NewFromInt(100)
			paymentOrderUpdate = paymentOrderUpdate.SetStatus(paymentorder.StatusSettled)
		}

		if transactionLog != nil {
			paymentOrderUpdate = paymentOrderUpdate.AddTransactions(transactionLog)
		}

		_, err = paymentOrderUpdate.
			SetPercentSettled(settledPercent).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("UpdateOrderStatusSettled.sender: %v", err)
		}

		paymentOrder.BlockNumber = int64(event.BlockNumber)
		paymentOrder.TxHash = event.TxHash
		paymentOrder.PercentSettled = settledPercent
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("UpdateOrderStatusSettled.sender %v", err)
	}

	if paymentOrderExists && paymentOrder.Status != paymentorder.StatusSettled {
		if settledPercent.GreaterThanOrEqual(decimal.NewFromInt(100)) {
			paymentOrder.Status = paymentorder.StatusSettled
		}
		paymentOrder.TxHash = event.TxHash

		// Send webhook notification to sender
		err = utils.SendPaymentOrderWebhook(ctx, paymentOrder)
		if err != nil {
			return fmt.Errorf("UpdateOrderStatusSettled.webhook: %v", err)
		}
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

// HandleCancellation handles the cancellation of a lock payment order.
func HandleCancellation(ctx context.Context, createdLockPaymentOrder *ent.LockPaymentOrder, lockPaymentOrder *types.LockPaymentOrderFields, cancellationReason string, refundOrder func(context.Context, *ent.Network, string) error) error {
	// lockPaymentOrder and createdLockPaymentOrder are mutually exclusive
	if (createdLockPaymentOrder == nil && lockPaymentOrder == nil) || (createdLockPaymentOrder != nil && lockPaymentOrder != nil) {
		return nil
	}

	if lockPaymentOrder != nil {
		orderBuilder := db.Client.LockPaymentOrder.
			Create().
			SetToken(lockPaymentOrder.Token).
			SetGatewayID(lockPaymentOrder.GatewayID).
			SetAmount(lockPaymentOrder.Amount).
			SetRate(lockPaymentOrder.Rate).
			SetOrderPercent(decimal.NewFromInt(100)).
			SetBlockNumber(lockPaymentOrder.BlockNumber).
			SetTxHash(lockPaymentOrder.TxHash).
			SetInstitution(lockPaymentOrder.Institution).
			SetAccountIdentifier(lockPaymentOrder.AccountIdentifier).
			SetAccountName(lockPaymentOrder.AccountName).
			SetMemo(lockPaymentOrder.Memo).
			SetMetadata(lockPaymentOrder.Metadata).
			SetProvisionBucket(lockPaymentOrder.ProvisionBucket).
			SetCancellationCount(3).
			SetCancellationReasons([]string{cancellationReason}).
			SetStatus(lockpaymentorder.StatusCancelled)

		if lockPaymentOrder.ProviderID != "" {
			orderBuilder = orderBuilder.
				SetProviderID(lockPaymentOrder.ProviderID)
		}

		order, err := orderBuilder.Save(ctx)
		if err != nil {
			return fmt.Errorf("%s - failed to create lock payment order: %w", lockPaymentOrder.GatewayID, err)
		}

		network, err := lockPaymentOrder.Token.QueryNetwork().Only(ctx)
		if err != nil {
			return fmt.Errorf("%s - failed to fetch network: %w", lockPaymentOrder.GatewayID, err)
		}

		err = refundOrder(ctx, network, lockPaymentOrder.GatewayID)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":        fmt.Sprintf("%v", err),
				"OrderID":      order.ID.String(),
				"OrderTrxHash": order.TxHash,
				"GatewayID":    order.GatewayID,
			}).Errorf("Handle cancellation failed to refund order")
		}

	} else if createdLockPaymentOrder != nil {
		_, err := db.Client.LockPaymentOrder.
			Update().
			Where(
				lockpaymentorder.IDEQ(createdLockPaymentOrder.ID),
			).
			SetCancellationCount(3).
			SetCancellationReasons([]string{cancellationReason}).
			SetStatus(lockpaymentorder.StatusCancelled).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("%s - failed to update lock payment order: %w", createdLockPaymentOrder.GatewayID, err)
		}

		network, err := createdLockPaymentOrder.QueryToken().QueryNetwork().Only(ctx)
		if err != nil {
			return fmt.Errorf("%s - failed to fetch network: %w", createdLockPaymentOrder.GatewayID, err)
		}

		err = refundOrder(ctx, network, createdLockPaymentOrder.GatewayID)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":        fmt.Sprintf("%v", err),
				"OrderID":      fmt.Sprintf("0x%v", hex.EncodeToString(createdLockPaymentOrder.ID[:])),
				"OrderTrxHash": createdLockPaymentOrder.TxHash,
				"GatewayID":    createdLockPaymentOrder.GatewayID,
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
func HandleReceiveAddressValidity(ctx context.Context, receiveAddress *ent.ReceiveAddress, paymentOrder *ent.PaymentOrder) error {
	if receiveAddress.ValidUntil.IsZero() {
		return nil
	}

	if receiveAddress.Status != receiveaddress.StatusUsed {
		validUntilIsFarGone := receiveAddress.ValidUntil.Before(time.Now().Add(-(5 * time.Minute)))
		isExpired := receiveAddress.ValidUntil.Before(time.Now())

		if validUntilIsFarGone {
			_, err := receiveAddress.
				Update().
				SetValidUntil(time.Now().Add(orderConf.ReceiveAddressValidity)).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("HandleReceiveAddressValidity.db: %v", err)
			}
		} else if isExpired && !strings.HasPrefix(paymentOrder.Edges.Recipient.Memo, "P#P") {
			// Receive address hasn't received payment after validity period, mark status as expired
			_, err := receiveAddress.
				Update().
				SetStatus(receiveaddress.StatusExpired).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("HandleReceiveAddressValidity.db: %v", err)
			}

			// Expire payment order
			_, err = paymentOrder.
				Update().
				SetStatus(paymentorder.StatusExpired).
				Save(ctx)
			if err != nil {
				return fmt.Errorf("HandleReceiveAddressValidity.db: %v", err)
			}
		}
	}

	return nil
}
