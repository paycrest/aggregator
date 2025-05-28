package order

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/google/uuid"
	fastshot "github.com/opus-domini/fast-shot"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/services"
	"github.com/paycrest/aggregator/services/contracts"
	db "github.com/paycrest/aggregator/storage"
	"github.com/shopspring/decimal"

	"github.com/paycrest/aggregator/ent/fiatcurrency"
	"github.com/paycrest/aggregator/ent/institution"
	"github.com/paycrest/aggregator/ent/linkedaddress"
	"github.com/paycrest/aggregator/ent/lockorderfulfillment"
	"github.com/paycrest/aggregator/ent/lockpaymentorder"
	networkent "github.com/paycrest/aggregator/ent/network"
	"github.com/paycrest/aggregator/ent/paymentorder"
	"github.com/paycrest/aggregator/ent/providerordertoken"
	"github.com/paycrest/aggregator/ent/providerprofile"
	"github.com/paycrest/aggregator/ent/provisionbucket"
	"github.com/paycrest/aggregator/ent/receiveaddress"
	"github.com/paycrest/aggregator/ent/senderprofile"
	tokenent "github.com/paycrest/aggregator/ent/token"
	"github.com/paycrest/aggregator/ent/transactionlog"
	"github.com/paycrest/aggregator/ent/user"
	"github.com/paycrest/aggregator/types"
	"github.com/paycrest/aggregator/utils"
	cryptoUtils "github.com/paycrest/aggregator/utils/crypto"
	"github.com/paycrest/aggregator/utils/logger"
)

// OrderEVM provides functionality related to on-chain interactions for payment orders
type OrderEVM struct {
	priorityQueue *services.PriorityQueueService
}

// NewOrderEVM creates a new instance of OrderEVM.
func NewOrderEVM() types.OrderService {
	priorityQueue := services.NewPriorityQueueService()

	return &OrderEVM{
		priorityQueue: priorityQueue,
	}
}

var orderConf = config.OrderConfig()
var serverConf = config.ServerConfig()
var cryptoConf = config.CryptoConfig()
var engineConf = config.EngineConfig()

// ProcessTransfer processes a transfer event for a receive address.
func (s *OrderEVM) ProcessTransfer(ctx context.Context, receiveAddress string, token *ent.Token) error {
	// Wait for transfer event to be received
	timeout := orderConf.ReceiveAddressValidity
	start := time.Now()
	result := []interface{}{}

	for {
		// Get transfer event data
		res, err := fastshot.NewClient(engineConf.BaseURL).
			Config().SetTimeout(15 * time.Second).
			Auth().BearerToken(engineConf.AccessToken).
			Header().AddAll(map[string]string{
			"Content-Type": "application/json",
		}).Build().POST(fmt.Sprintf("/contract/%d/%s/events/get", token.Edges.Network.ChainID, token.ContractAddress)).
			Body().AsJSON(map[string]interface{}{
			"eventName": "Transfer",
			"fromBlock": "latest",
			"toBlock":   "latest",
			"order":     "asc",
			"filters": map[string]interface{}{
				"to": receiveAddress,
			},
		}).Send()
		if err != nil {
			return fmt.Errorf("ProcessTransfer.getTransferEventData: %w", err)
		}

		data, err := utils.ParseJSONResponse(res.RawResponse)
		if err != nil {
			return fmt.Errorf("ProcessTransfer.parseJSONResponse: %w", err)
		}

		result = data["result"].([]interface{})
		if len(result) == 0 {
			elapsed := time.Since(start)
			if elapsed >= timeout {
				return fmt.Errorf("ProcessTransfer.timeout: %w", err)
			}
			time.Sleep(2 * time.Second)
			continue
		}

		break
	}

	transferData := result[0].(map[string]interface{})["data"]
	transferTransaction := result[0].(map[string]interface{})["transaction"]
	transferValue := utils.HexToDecimal(transferData.(map[string]interface{})["value"].(map[string]interface{})["hex"].(string))

	transferEvent := &types.TokenTransferEvent{
		BlockNumber: int64(transferTransaction.(map[string]interface{})["blockNumber"].(float64)),
		TxHash:      transferTransaction.(map[string]interface{})["transactionHash"].(string),
		From:        transferData.(map[string]interface{})["from"].(string),
		To:          transferData.(map[string]interface{})["to"].(string),
		Value:       transferValue.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(token.Decimals)))),
	}

	if strings.EqualFold(transferEvent.From, token.Edges.Network.GatewayContractAddress) {
		return nil
	}

	linkedAddress, err := db.Client.LinkedAddress.
		Query().
		Where(
			linkedaddress.AddressEQ(transferEvent.To),
		).
		Only(ctx)
	if err != nil {
		if !ent.IsNotFound(err) {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"Address": transferEvent.To,
			}).Errorf("Failed to query linked address when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
		}
	}

	// Create a new payment order from the transfer event to the linked address
	if linkedAddress != nil {
		orderAmount := transferEvent.Value
		// Check if the payment order already exists
		paymentOrderExists := true
		_, err := db.Client.PaymentOrder.
			Query().
			Where(
				paymentorder.FromAddress(transferEvent.From),
				paymentorder.AmountEQ(orderAmount),
				paymentorder.HasLinkedAddressWith(
					linkedaddress.AddressEQ(linkedAddress.Address),
					linkedaddress.LastIndexedBlockEQ(int64(transferEvent.BlockNumber)),
				),
			).
			WithSenderProfile().
			Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				// Payment order does not exist, no need to update
				paymentOrderExists = false
			} else {
				return fmt.Errorf("IndexERC20Transfer.fetchOrder: %v", err)
			}
		}

		if paymentOrderExists {
			return nil
		}

		// Create payment order
		institution, err := utils.GetInstitutionByCode(ctx, linkedAddress.Institution, true)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":                    fmt.Sprintf("%v", err),
				"LinkedAddress":            linkedAddress.Address,
				"LinkedAddressInstitution": linkedAddress.Institution,
			}).Errorf("Failed to get institution when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
			return nil
		}

		// Get rate from priority queue
		if !strings.EqualFold(token.BaseCurrency, institution.Edges.FiatCurrency.Code) && !strings.EqualFold(token.BaseCurrency, "USD") {
			return nil
		}
		var rateResponse decimal.Decimal
		if !strings.EqualFold(token.BaseCurrency, institution.Edges.FiatCurrency.Code) {
			rateResponse, err = utils.GetTokenRateFromQueue(token.Symbol, orderAmount, institution.Edges.FiatCurrency.Code, institution.Edges.FiatCurrency.MarketRate)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":                    fmt.Sprintf("%v", err),
					"Token":                    token.Symbol,
					"LinkedAddressInstitution": linkedAddress.Institution,
					"Code":                     institution.Edges.FiatCurrency.Code,
				}).Errorf("Failed to get token rate when indexing ERC20 transfers for %s from queue", token.Edges.Network.Identifier)
				return nil
			}
		} else {
			rateResponse = decimal.NewFromInt(1)
		}

		tx, err := db.Client.Tx(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":         fmt.Sprintf("%v", err),
				"LinkedAddress": linkedAddress.Address,
			}).Errorf("Failed to create transaction when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
			return nil
		}

		// transactionLog, err := tx.TransactionLog.
		// 	Create().
		// 	SetStatus(transactionlog.StatusOrderInitiated).
		// 	SetMetadata(
		// 		map[string]interface{}{
		// 			"LinkedAddress": linkedAddress.Address,
		// 		},
		// 	).
		// 	SetNetwork(token.Edges.Network.Identifier).
		// 	Save(ctx)
		// if err != nil {
		// 	logger.Errorf("IndexERC20Transfer.CreateTransactionLog: %v", err)
		// 	_ = tx.Rollback()
		// 	continue
		// }

		order, err := db.Client.PaymentOrder.
			Create().
			SetAmount(orderAmount).
			SetAmountPaid(orderAmount).
			SetAmountReturned(decimal.NewFromInt(0)).
			SetPercentSettled(decimal.NewFromInt(0)).
			SetNetworkFee(token.Edges.Network.Fee).
			SetProtocolFee(decimal.NewFromInt(0)).
			SetSenderFee(decimal.NewFromInt(0)).
			SetToken(token).
			SetRate(rateResponse).
			SetTxHash(transferEvent.TxHash).
			SetBlockNumber(int64(transferEvent.BlockNumber)).
			SetFromAddress(transferEvent.From).
			SetLinkedAddress(linkedAddress).
			SetReceiveAddressText(linkedAddress.Address).
			SetFeePercent(decimal.NewFromInt(0)).
			SetReturnAddress(linkedAddress.Address).
			// AddTransactions(transactionLog).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":         fmt.Sprintf("%v", err),
				"LinkedAddress": linkedAddress.Address,
			}).Errorf("Failed to create payment order when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
			_ = tx.Rollback()
			return nil
		}

		_, err = tx.PaymentOrderRecipient.
			Create().
			SetInstitution(linkedAddress.Institution).
			SetAccountIdentifier(linkedAddress.AccountIdentifier).
			SetAccountName(linkedAddress.AccountName).
			SetMetadata(linkedAddress.Metadata).
			SetPaymentOrder(order).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":         fmt.Sprintf("%v", err),
				"LinkedAddress": linkedAddress.Address,
			}).Errorf("Failed to create payment order recipient when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
			_ = tx.Rollback()
			return nil
		}

		_, err = tx.LinkedAddress.
			UpdateOneID(linkedAddress.ID).
			SetTxHash(transferEvent.TxHash).
			SetLastIndexedBlock(int64(transferEvent.BlockNumber)).
			Save(ctx)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":         fmt.Sprintf("%v", err),
				"LinkedAddress": linkedAddress.Address,
			}).Errorf("Failed to update linked address when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
			_ = tx.Rollback()
			return nil
		}

		if err := tx.Commit(); err != nil {
			logger.WithFields(logger.Fields{
				"Error":         fmt.Sprintf("%v", err),
				"LinkedAddress": linkedAddress.Address,
			}).Errorf("Failed to commit transaction when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
			return nil
		}

		err = s.CreateOrder(ctx, order.ID)
		if err != nil {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"OrderID": order.ID.String(),
			}).Errorf("Failed to create order when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
			return nil
		}

	} else if receiveAddress != "" {
		order, err := db.Client.PaymentOrder.
			Query().
			Where(
				paymentorder.HasReceiveAddressWith(
					receiveaddress.StatusEQ(receiveaddress.StatusUnused),
					receiveaddress.ValidUntilGT(time.Now()),
					receiveaddress.AddressEQ(receiveAddress),
				),
				paymentorder.StatusEQ(paymentorder.StatusInitiated),
			).
			WithToken(func(tq *ent.TokenQuery) {
				tq.WithNetwork()
			}).
			WithReceiveAddress().
			WithRecipient().
			Only(ctx)
		if err != nil {
			return fmt.Errorf("ProcessTransfer.fetchOrders: %w", err)
		}

		// Process transfer event for receive address
		done, err := s.UpdateReceiveAddressStatus(ctx, order.Edges.ReceiveAddress, order, transferEvent)
		if err != nil {
			if !strings.Contains(fmt.Sprintf("%v", err), "Duplicate payment order") {
				logger.WithFields(logger.Fields{
					"Error":   fmt.Sprintf("%v", err),
					"OrderID": order.ID.String(),
				}).Errorf("Failed to update receive address status when indexing ERC20 transfers for %s", token.Edges.Network.Identifier)
			}
			return nil
		}
		if done {
			return nil
		}
	}

	return nil
}

// UpdateReceiveAddressStatus updates the status of a receive address. if `done` is true, the indexing process is complete for the given receive address
func (s *OrderEVM) UpdateReceiveAddressStatus(
	ctx context.Context, receiveAddress *ent.ReceiveAddress, paymentOrder *ent.PaymentOrder, event *types.TokenTransferEvent,
) (done bool, err error) {
	if event.To == receiveAddress.Address {
		// Check for existing address with txHash
		count, err := db.Client.ReceiveAddress.
			Query().
			Where(receiveaddress.TxHashEQ(event.TxHash)).
			Count(ctx)
		if err != nil {
			return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
		}

		if count > 0 && receiveAddress.Status != receiveaddress.StatusUnused {
			// This transfer has already been indexed
			return false, nil
		}

		// Check for existing payment order with txHash
		if paymentOrder.TxHash == event.TxHash {
			// This transfer has already been indexed
			return false, nil
		}

		// This is a transfer to the receive address to create an order on-chain
		// Compare the transferred value with the expected order amount + fees
		fees := paymentOrder.NetworkFee.Add(paymentOrder.SenderFee).Add(paymentOrder.ProtocolFee)
		orderAmountWithFees := paymentOrder.Amount.Add(fees).Round(int32(paymentOrder.Edges.Token.Decimals))
		transferMatchesOrderAmount := event.Value.Equal(orderAmountWithFees)

		tx, err := db.Client.Tx(ctx)
		if err != nil {
			return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
		}

		paymentOrderUpdate := tx.PaymentOrder.Update().Where(paymentorder.IDEQ(paymentOrder.ID))
		if paymentOrder.ReturnAddress == "" {
			paymentOrderUpdate = paymentOrderUpdate.SetReturnAddress(event.From)
		}

		orderRecipient := paymentOrder.Edges.Recipient
		if !transferMatchesOrderAmount {
			// Update the order amount will be updated to whatever amount was sent to the receive address
			newOrderAmount := event.Value.Sub(fees.Round(int32(paymentOrder.Edges.Token.Decimals)))
			paymentOrderUpdate = paymentOrderUpdate.SetAmount(newOrderAmount.Round(int32(paymentOrder.Edges.Token.Decimals)))
			// Update the rate with the current rate if order is older than 30 mins for a P2P order from the sender dashboard
			if strings.HasPrefix(orderRecipient.Memo, "P#P") && orderRecipient.ProviderID != "" && paymentOrder.CreatedAt.Before(time.Now().Add(-30*time.Minute)) {
				providerProfile, err := db.Client.ProviderProfile.
					Query().
					Where(
						providerprofile.HasUserWith(
							user.HasSenderProfileWith(
								senderprofile.HasPaymentOrdersWith(
									paymentorder.IDEQ(paymentOrder.ID),
								),
							),
						),
					).
					Only(ctx)
				if err != nil {
					return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
				}

				institution, err := utils.GetInstitutionByCode(ctx, orderRecipient.Institution, true)
				if err != nil {
					return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
				}

				rate, err := s.priorityQueue.GetProviderRate(ctx, providerProfile, paymentOrder.Edges.Token.Symbol, institution.Edges.FiatCurrency.Code)
				if err != nil {
					return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
				}
				paymentOrderUpdate = paymentOrderUpdate.SetRate(rate)
			}
			transferMatchesOrderAmount = true
		}

		if paymentOrder.AmountPaid.GreaterThanOrEqual(decimal.Zero) && paymentOrder.AmountPaid.LessThan(orderAmountWithFees) {
			transactionLog, err := tx.TransactionLog.
				Create().
				SetStatus(transactionlog.StatusCryptoDeposited).
				SetGatewayID(paymentOrder.GatewayID).
				SetTxHash(event.TxHash).
				SetNetwork(paymentOrder.Edges.Token.Edges.Network.Identifier).
				SetMetadata(map[string]interface{}{
					"GatewayID":       paymentOrder.GatewayID,
					"transactionData": event,
				}).
				Save(ctx)
			if err != nil {
				return true, fmt.Errorf("UpdateReceiveAddressStatus.transactionlog: %v", err)
			}

			_, err = paymentOrderUpdate.
				SetFromAddress(event.From).
				SetTxHash(event.TxHash).
				SetBlockNumber(int64(event.BlockNumber)).
				AddAmountPaid(event.Value).
				AddTransactions(transactionLog).
				Save(ctx)
			if err != nil {
				return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
			}

			// Commit the transaction
			if err := tx.Commit(); err != nil {
				return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
			}
		}

		if transferMatchesOrderAmount {
			// Transfer value equals order amount with fees
			_, err = receiveAddress.
				Update().
				SetStatus(receiveaddress.StatusUsed).
				SetLastUsed(time.Now()).
				SetTxHash(event.TxHash).
				SetLastIndexedBlock(int64(event.BlockNumber)).
				Save(ctx)
			if err != nil {
				return true, fmt.Errorf("UpdateReceiveAddressStatus.db: %v", err)
			}

			err = s.CreateOrder(ctx, paymentOrder.ID)
			if err != nil {
				return true, fmt.Errorf("UpdateReceiveAddressStatus.CreateOrder: %v", err)
			}

			return true, nil
		}

		err = s.HandleReceiveAddressValidity(ctx, receiveAddress, paymentOrder)
		if err != nil {
			return true, fmt.Errorf("UpdateReceiveAddressStatus.HandleReceiveAddressValidity: %v", err)
		}
	}

	return false, nil
}

// HandleReceiveAddressValidity checks the validity of a receive address
func (s *OrderEVM) HandleReceiveAddressValidity(ctx context.Context, receiveAddress *ent.ReceiveAddress, paymentOrder *ent.PaymentOrder) error {
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

// CreateOrder creates a new payment order on-chain.
func (s *OrderEVM) CreateOrder(ctx context.Context, orderID uuid.UUID) error {
	var err error
	orderIDPrefix := strings.Split(orderID.String(), "-")[0]

	// Fetch payment order from db
	order, err := db.Client.PaymentOrder.
		Query().
		Where(paymentorder.IDEQ(orderID)).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithSenderProfile().
		WithRecipient().
		WithReceiveAddress().
		WithLinkedAddress().
		Only(ctx)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.fetchOrder: %w", orderIDPrefix, err)
	}

	var address string
	if order.Edges.ReceiveAddress != nil {
		address = order.Edges.ReceiveAddress.Address
	} else if order.Edges.LinkedAddress != nil {
		address = order.Edges.LinkedAddress.Address

		// Update the rate
		institution, err := db.Client.Institution.
			Query().
			Where(institution.CodeEQ(order.Edges.Recipient.Institution)).
			WithFiatCurrency().
			Only(ctx)
		if err != nil {
			return fmt.Errorf("%s - CreateOrder.fetchInstitution: %w", orderIDPrefix, err)
		}

		rate, err := utils.GetTokenRateFromQueue(order.Edges.Token.Symbol, order.Amount, institution.Edges.FiatCurrency.Code, institution.Edges.FiatCurrency.MarketRate)
		if err != nil {
			return fmt.Errorf("%s - CreateOrder.getRate: %w", orderIDPrefix, err)
		}

		if rate != order.Rate {
			// Update order rate
			order.Rate = rate

			// Refresh order from db
			order, err = db.Client.PaymentOrder.
				Query().
				Where(paymentorder.IDEQ(orderID)).
				WithToken(func(tq *ent.TokenQuery) {
					tq.WithNetwork()
				}).
				WithSenderProfile().
				WithRecipient().
				WithReceiveAddress().
				WithLinkedAddress().
				Only(ctx)
			if err != nil {
				return fmt.Errorf("%s - CreateOrder.refreshOrder: %w", orderIDPrefix, err)
			}
		}
	}

	// Create createOrder data
	encryptedOrderRecipient, err := cryptoUtils.EncryptOrderRecipient(order.Edges.Recipient)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.encryptOrderRecipient: %w", orderIDPrefix, err)
	}

	createOrderData, err := s.createOrderCallData(order, encryptedOrderRecipient)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.createOrderCallData: %w", orderIDPrefix, err)
	}

	// Create approve data for gateway contract
	approveGatewayData, err := s.approveCallData(
		common.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
		utils.ToSubunit(order.Amount.Add(order.ProtocolFee).Add(order.SenderFee), order.Edges.Token.Decimals),
	)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.approveCallData: %w", orderIDPrefix, err)
	}

	// Create order
	txPayload := []map[string]interface{}{
		{
			"toAddress": order.Edges.Token.ContractAddress,
			"data":      fmt.Sprintf("0x%x", approveGatewayData),
			"value":     "0",
		},
		{
			"toAddress": order.Edges.Token.Edges.Network.GatewayContractAddress,
			"data":      fmt.Sprintf("0x%x", createOrderData),
			"value":     "0",
		},
	}

	res, err := fastshot.NewClient(engineConf.BaseURL).
		Config().SetTimeout(30*time.Second).
		Auth().BearerToken(engineConf.AccessToken).
		Header().Add("Accept", "application/json").
		Header().Add("Content-Type", "application/json").
		Header().Add("x-backend-wallet-address", address).
		Build().POST(fmt.Sprintf("/backend-wallet/%d/send-transaction-batch", order.Edges.Token.Edges.Network.ChainID)).
		Body().AsJSON(txPayload).
		Send()
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.sendTransactionBatch: %w", orderIDPrefix, err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.parseJSONResponse: %w", orderIDPrefix, err)
	}

	queueIds := data["result"].(map[string]interface{})["queueIds"].([]string)
	if len(queueIds) == 0 {
		return fmt.Errorf("%s - CreateOrder.noQueueIds: %w", orderIDPrefix, err)
	}
	queueId := queueIds[1] // queueId[0] is the approval tx, queueId[1] is the createOrder tx

	// Wait for createOrder tx to be mined
	timeout := 5 * time.Minute
	start := time.Now()
	result := map[string]interface{}{}

	for {
		res, err = fastshot.NewClient(engineConf.BaseURL).
			Config().SetTimeout(15*time.Second).
			Auth().BearerToken(engineConf.AccessToken).
			Header().Add("Content-Type", "application/json").
			Build().GET(fmt.Sprintf("/transaction/status/%s", queueId)).
			Send()
		if err != nil {
			return fmt.Errorf("CreateOrder.getTransactionStatus: %w", err)
		}

		data, err = utils.ParseJSONResponse(res.RawResponse)
		if err != nil {
			return fmt.Errorf("CreateOrder.parseJSONResponse: %w", err)
		}

		result = data["result"].(map[string]interface{})
		if result["status"] != "mined" {
			elapsed := time.Since(start)
			if elapsed >= timeout {
				return fmt.Errorf("CreateOrder.timeout: %w", err)
			}
			time.Sleep(2 * time.Second)
			continue
		}

		break
	}

	txHash := result["txHash"].(string)
	blockNumber := result["blockNumber"].(float64)

	// Get OrderCreated event data
	res, err = fastshot.NewClient(engineConf.BaseURL).
		Config().SetTimeout(15 * time.Second).
		Auth().BearerToken(engineConf.AccessToken).
		Header().AddAll(map[string]string{
		"Content-Type": "application/json",
	}).Build().POST(fmt.Sprintf("/contract/%d/%s/events/get", order.Edges.Token.Edges.Network.ChainID, order.Edges.Token.Edges.Network.GatewayContractAddress)).
		Body().AsJSON(map[string]interface{}{
		"eventName": "OrderCreated",
		"fromBlock": blockNumber,
		"toBlock":   blockNumber,
		"order":     "desc",
		"filters": map[string]interface{}{
			"sender": address,
		},
	}).Send()
	if err != nil {
		return fmt.Errorf("CreateOrder.getEvents: %w", err)
	}

	data, err = utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return fmt.Errorf("CreateOrder.parseJSONResponse: %w", err)
	}

	for _, r := range data["result"].([]interface{}) {
		result = r.(map[string]interface{})["data"].(map[string]interface{})
		messageHash := result["messageHash"].(string)
		rTxHash := r.(map[string]interface{})["transaction"].(map[string]interface{})["transactionHash"].(string)
		if messageHash != encryptedOrderRecipient || rTxHash != txHash {
			continue
		}

		break
	}

	orderAmount := utils.HexToDecimal(result["amount"].(map[string]interface{})["hex"].(string))
	protocolFee := utils.HexToDecimal(result["protocolFee"].(map[string]interface{})["hex"].(string))
	createdEvent := &types.OrderCreatedEvent{
		BlockNumber: int64(blockNumber),
		TxHash:      txHash,
		Token:       result["token"].(string),
		Amount:      orderAmount.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(order.Edges.Token.Decimals)))),
		ProtocolFee: protocolFee.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(order.Edges.Token.Decimals)))),
		OrderId:     result["orderId"].(string),
		Rate:        utils.HexToDecimal(result["rate"].(map[string]interface{})["hex"].(string)).Div(decimal.NewFromInt(100)),
		MessageHash: result["messageHash"].(string),
		Sender:      result["sender"].(string),
	}

	err = s.createLockPaymentOrder(ctx, order.Edges.Token.Edges.Network, createdEvent)
	if err != nil {
		if !strings.Contains(fmt.Sprintf("%v", err), "duplicate key value violates unique constraint") {
			logger.WithFields(logger.Fields{
				"Error":   fmt.Sprintf("%v", err),
				"OrderID": createdEvent.OrderId,
			}).Errorf("Failed to create lock payment order when indexing order created events for %s", order.Edges.Token.Edges.Network.Identifier)
		}
		return fmt.Errorf("CreateOrder.createLockPaymentOrder: %w", err)
	}

	// Update payment order with txHash
	_, err = order.Update().
		SetTxHash(txHash).
		SetBlockNumber(int64(blockNumber)).
		SetGatewayID(result["orderId"].(string)).
		SetRate(order.Rate).
		SetStatus(paymentorder.StatusPending).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.updateTxHash: %w", orderIDPrefix, err)
	}

	// Refetch payment order
	paymentOrder, err := db.Client.PaymentOrder.
		Query().
		Where(paymentorder.IDEQ(orderID)).
		WithSenderProfile().
		Only(ctx)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.refetchOrder: %w", orderIDPrefix, err)
	}

	// Send webhook notifcation to sender
	err = utils.SendPaymentOrderWebhook(ctx, paymentOrder)
	if err != nil {
		return fmt.Errorf("%s - CreateOrder.webhook: %w", orderIDPrefix, err)
	}

	return nil
}

// CreateLockPaymentOrder saves a lock payment order in the database
func (s *OrderEVM) createLockPaymentOrder(ctx context.Context, client types.RPCClient, network *ent.Network, event *types.OrderCreatedEvent) error {
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

	provisionBucket, isLessThanMin, err := s.getProvisionBucket(ctx, event.Amount.Mul(event.Rate), currency)
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
		err := s.handleCancellation(ctx, client, nil, &lockPaymentOrder, "Amount is less than the minimum bucket")
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
				_ = s.handleCancellation(ctx, client, nil, &lockPaymentOrder, "Provider not available")
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
				err := s.handleCancellation(ctx, client, nil, &lockPaymentOrder, "Amount is greater than the maximum order amount of the provider")
				if err != nil {
					return fmt.Errorf("%s - failed to cancel order: %w", lockPaymentOrder.GatewayID, err)
				}
				return nil
			} else if normalizedAmount.LessThan(orderToken.MinOrderAmount) {
				err := s.handleCancellation(ctx, client, nil, &lockPaymentOrder, "Amount is less than the minimum order amount of the provider")
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

		err = s.handleCancellation(ctx, client, nil, &lockPaymentOrder, "Amount is larger than the maximum bucket")
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
			ok, err := s.checkAMLCompliance(network.RPCEndpoint, event.TxHash)
			if err != nil {
				logger.WithFields(logger.Fields{
					"Error":    fmt.Sprintf("%v", err),
					"endpoint": network.RPCEndpoint,
					"TxHash":   event.TxHash,
				}).Errorf("Failed to check AML Compliance")
			}

			if !ok && err == nil {
				err := s.handleCancellation(ctx, client, orderCreated, nil, "AML compliance check failed")
				if err != nil {
					return fmt.Errorf("checkAMLCompliance.RefundOrder: %w", err)
				}
				return nil
			}
		}

		// Assign the lock payment order to a provider
		lockPaymentOrder.ID = orderCreated.ID
		_ = s.priorityQueue.AssignLockPaymentOrder(ctx, lockPaymentOrder)
	}

	return nil
}

// getProvisionBucket returns the provision bucket for a lock payment order
func (s *OrderEVM) getProvisionBucket(ctx context.Context, amount decimal.Decimal, currency *ent.FiatCurrency) (*ent.ProvisionBucket, bool, error) {
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

// handleCancellation handles the cancellation of a lock payment order
func (s *OrderEVM) handleCancellation(ctx context.Context, client types.RPCClient, createdLockPaymentOrder *ent.LockPaymentOrder, lockPaymentOrder *types.LockPaymentOrderFields, cancellationReason string) error {
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

		err = s.RefundOrder(ctx, network, lockPaymentOrder.GatewayID)
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

		err = s.RefundOrder(ctx, client, network, createdLockPaymentOrder.GatewayID)
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

// checkAMLCompliance checks if a transaction is compliant with AML rules
func (s *OrderEVM) checkAMLCompliance(rpcUrl string, txHash string) (bool, error) {
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

// RefundOrder refunds sender on canceled lock order
func (s *OrderEVM) RefundOrder(ctx context.Context, network *ent.Network, orderID string) error {
	orderIDPrefix := strings.Split(orderID, "-")[0]

	// Fetch lock order from db
	lockOrder, err := db.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.GatewayIDEQ(orderID),
			lockpaymentorder.HasTokenWith(
				tokenent.HasNetworkWith(
					networkent.IdentifierEQ(network.Identifier),
				),
			),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		First(ctx)
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.fetchLockOrder: %w", orderIDPrefix, err)
	}

	// Create refundOrder data
	fee := utils.ToSubunit(decimal.NewFromInt(0), lockOrder.Edges.Token.Decimals)
	refundOrderData, err := s.refundCallData(fee, lockOrder.GatewayID)
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.refundCallData: %w", orderIDPrefix, err)
	}

	// Refund order
	txPayload := map[string]interface{}{
		"toAddress": lockOrder.Edges.Token.ContractAddress,
		"data":      fmt.Sprintf("0x%x", refundOrderData),
		"value":     "0",
	}

	res, err := fastshot.NewClient(engineConf.BaseURL).
		Config().SetTimeout(30*time.Second).
		Auth().BearerToken(engineConf.AccessToken).
		Header().Add("Content-Type", "application/json").
		Header().Add("x-backend-wallet-address", cryptoConf.AggregatorSmartAccount).
		Build().POST(fmt.Sprintf("/backend-wallet/%d/send-transaction", lockOrder.Edges.Token.Edges.Network.ChainID)).
		Body().AsJSON(txPayload).
		Send()
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.sendTransaction: %w", orderIDPrefix, err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return fmt.Errorf("%s - RefundOrder.parseJSONResponse: %w", orderIDPrefix, err)
	}

	queueId := data["result"].(map[string]interface{})["queueId"].(string)

	// Wait for refundOrder tx to be mined
	timeout := 5 * time.Minute
	start := time.Now()
	result := map[string]interface{}{}

	for {
		res, err = fastshot.NewClient(engineConf.BaseURL).
			Config().SetTimeout(15*time.Second).
			Auth().BearerToken(engineConf.AccessToken).
			Header().Add("Content-Type", "application/json").
			Build().GET(fmt.Sprintf("/transaction/status/%s", queueId)).
			Send()
		if err != nil {
			return fmt.Errorf("RefundOrder.getTransactionStatus: %w", err)
		}

		data, err = utils.ParseJSONResponse(res.RawResponse)
		if err != nil {
			return fmt.Errorf("RefundOrder.parseJSONResponse: %w", err)
		}

		result = data["result"].(map[string]interface{})
		if result["status"] != "mined" {
			elapsed := time.Since(start)
			if elapsed >= timeout {
				return fmt.Errorf("RefundOrder.timeout: %w", err)
			}
			time.Sleep(2 * time.Second)
			continue
		}

		break
	}

	txHash := result["txHash"].(string)
	blockNumber := result["blockNumber"].(float64)

	// Get OrderRefunded event data
	res, err = fastshot.NewClient(engineConf.BaseURL).
		Config().SetTimeout(15 * time.Second).
		Auth().BearerToken(engineConf.AccessToken).
		Header().AddAll(map[string]string{
		"Content-Type": "application/json",
	}).Build().POST(fmt.Sprintf("/contract/%d/%s/events/get", lockOrder.Edges.Token.Edges.Network.ChainID, lockOrder.Edges.Token.Edges.Network.GatewayContractAddress)).
		Body().AsJSON(map[string]interface{}{
		"eventName": "OrderRefunded",
		"fromBlock": blockNumber,
		"toBlock":   blockNumber,
		"order":     "desc",
		"filters": map[string]interface{}{
			"orderId": lockOrder.GatewayID,
		},
	}).Send()
	if err != nil {
		return fmt.Errorf("RefundOrder.getEvents: %w", err)
	}

	data, err = utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return fmt.Errorf("RefundOrder.parseJSONResponse: %w", err)
	}

	for _, r := range data["result"].([]interface{}) {
		result = r.(map[string]interface{})["data"].(map[string]interface{})
		rTxHash := r.(map[string]interface{})["transaction"].(map[string]interface{})["transactionHash"].(string)
		if rTxHash != txHash {
			continue
		}

		break
	}

	refundFee := utils.HexToDecimal(result["fee"].(map[string]interface{})["hex"].(string))
	refundedEvent := &types.OrderRefundedEvent{
		BlockNumber: int64(blockNumber),
		TxHash:      txHash,
		Fee:         refundFee.Div(decimal.NewFromInt(10).Pow(decimal.NewFromInt(int64(lockOrder.Edges.Token.Decimals)))),
		OrderId:     lockOrder.GatewayID,
	}

	err = s.updateOrderStatusRefunded(ctx, lockOrder.Edges.Token.Edges.Network, refundedEvent)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":   fmt.Sprintf("%v", err),
			"OrderID": refundedEvent.OrderId,
			"TxHash":  refundedEvent.TxHash,
		}).Errorf("Failed to update order status refund when indexing order refunded events for %s", lockOrder.Edges.Token.Edges.Network.Identifier)
	}

	return nil
}

// UpdateOrderStatusRefunded updates the status of a payment order to refunded
func (s *OrderEVM) updateOrderStatusRefunded(ctx context.Context, network *ent.Network, event *types.OrderRefundedEvent) error {
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

// SettleOrder settles a payment order on-chain.
func (s *OrderEVM) SettleOrder(ctx context.Context, orderID uuid.UUID) error {
	var err error

	orderIDPrefix := strings.Split(orderID.String(), "-")[0]

	// Fetch payment order from db
	order, err := db.Client.LockPaymentOrder.
		Query().
		Where(
			lockpaymentorder.IDEQ(orderID),
			lockpaymentorder.StatusEQ(lockpaymentorder.StatusValidated),
			lockpaymentorder.HasFulfillmentsWith(
				lockorderfulfillment.ValidationStatusEQ(lockorderfulfillment.ValidationStatusSuccess),
			),
		).
		WithToken(func(tq *ent.TokenQuery) {
			tq.WithNetwork()
		}).
		WithProvider().
		Only(ctx)
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.fetchOrder: %w", orderIDPrefix, err)
	}

	// Create settleOrder data
	settleOrderData, err := s.settleCallData(ctx, order)
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.settleCallData: %w", orderIDPrefix, err)
	}

	// Settle order
	txPayload := map[string]interface{}{
		"toAddress": order.Edges.Token.ContractAddress,
		"data":      fmt.Sprintf("0x%x", settleOrderData),
		"value":     "0",
	}

	res, err := fastshot.NewClient(engineConf.BaseURL).
		Config().SetTimeout(30*time.Second).
		Auth().BearerToken(engineConf.AccessToken).
		Header().Add("Content-Type", "application/json").
		Header().Add("x-backend-wallet-address", cryptoConf.AggregatorSmartAccount).
		Build().POST(fmt.Sprintf("/backend-wallet/%d/send-transaction", order.Edges.Token.Edges.Network.ChainID)).
		Body().AsJSON(txPayload).
		Send()
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.sendTransaction: %w", orderIDPrefix, err)
	}

	data, err := utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return fmt.Errorf("%s - SettleOrder.parseJSONResponse: %w", orderIDPrefix, err)
	}

	queueId := data["result"].(map[string]interface{})["queueId"].(string)

	// Wait for settleOrder tx to be mined
	timeout := 5 * time.Minute
	start := time.Now()
	result := map[string]interface{}{}

	for {
		res, err = fastshot.NewClient(engineConf.BaseURL).
			Config().SetTimeout(15*time.Second).
			Auth().BearerToken(engineConf.AccessToken).
			Header().Add("Content-Type", "application/json").
			Build().GET(fmt.Sprintf("/transaction/status/%s", queueId)).
			Send()
		if err != nil {
			return fmt.Errorf("SettleOrder.getTransactionStatus: %w", err)
		}

		data, err = utils.ParseJSONResponse(res.RawResponse)
		if err != nil {
			return fmt.Errorf("SettleOrder.parseJSONResponse: %w", err)
		}

		result = data["result"].(map[string]interface{})
		if result["status"] != "mined" {
			elapsed := time.Since(start)
			if elapsed >= timeout {
				return fmt.Errorf("SettleOrder.timeout: %w", err)
			}
			time.Sleep(2 * time.Second)
			continue
		}

		break
	}

	txHash := result["txHash"].(string)
	blockNumber := result["blockNumber"].(float64)

	// Get OrderSettled event data
	res, err = fastshot.NewClient(engineConf.BaseURL).
		Config().SetTimeout(15 * time.Second).
		Auth().BearerToken(engineConf.AccessToken).
		Header().AddAll(map[string]string{
		"Content-Type": "application/json",
	}).Build().POST(fmt.Sprintf("/contract/%d/%s/events/get", order.Edges.Token.Edges.Network.ChainID, order.Edges.Token.Edges.Network.GatewayContractAddress)).
		Body().AsJSON(map[string]interface{}{
		"eventName": "OrderSettled",
		"fromBlock": blockNumber,
		"toBlock":   blockNumber,
		"order":     "desc",
		"filters": map[string]interface{}{
			"orderId": order.GatewayID,
		},
	}).Send()
	if err != nil {
		return fmt.Errorf("SettleOrder.getEvents: %w", err)
	}

	data, err = utils.ParseJSONResponse(res.RawResponse)
	if err != nil {
		return fmt.Errorf("SettleOrder.parseJSONResponse: %w", err)
	}

	for _, r := range data["result"].([]interface{}) {
		result = r.(map[string]interface{})["data"].(map[string]interface{})
		splitOrderId := result["splitOrderId"].(string)
		rTxHash := r.(map[string]interface{})["transaction"].(map[string]interface{})["transactionHash"].(string)

		if splitOrderId != strings.ReplaceAll(order.ID.String(), "-", "") || rTxHash != txHash {
			continue
		}

		break
	}

	settledEvent := &types.OrderSettledEvent{
		BlockNumber:       int64(blockNumber),
		TxHash:            txHash,
		SplitOrderId:      result["splitOrderId"].(string),
		OrderId:           result["orderId"].(string),
		LiquidityProvider: result["liquidityProvider"].(string),
		SettlePercent:     utils.HexToDecimal(result["settlePercent"].(map[string]interface{})["hex"].(string)),
	}

	// Update order status
	err = s.updateOrderStatusSettled(ctx, order.Edges.Token.Edges.Network, settledEvent)
	if err != nil {
		logger.WithFields(logger.Fields{
			"Error":   fmt.Sprintf("%v", err),
			"OrderID": settledEvent.OrderId,
		}).Errorf("Failed to update order status settlement when indexing order settled events for %s", order.Edges.Token.Edges.Network.Identifier)
		return fmt.Errorf("SettleOrder.updateOrderStatusSettled: %w", err)
	}

	return nil
}

// UpdateOrderStatusSettled updates the status of a payment order to settled
func (s *OrderEVM) updateOrderStatusSettled(ctx context.Context, network *ent.Network, event *types.OrderSettledEvent) error {
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
	splitOrderId, _ := uuid.Parse(event.SplitOrderId)
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

// executeBatchTransferCallData creates the transfer calldata for the execute batch method in the smart account.
func (s *OrderEVM) executeBatchTransferCallData(order *ent.PaymentOrder, to common.Address, amount *big.Int) ([]byte, error) {
	// Fetch paymaster account
	paymasterAccount, err := utils.GetPaymasterAccount(order.Edges.Token.Edges.Network.ChainID)
	if err != nil {
		return nil, fmt.Errorf("failed to get paymaster account: %w", err)
	}

	if serverConf.Environment != "staging" && serverConf.Environment != "production" {
		time.Sleep(5 * time.Second)
	}

	// Create approve data for paymaster contract
	approvePaymasterData, err := s.approveCallData(
		common.HexToAddress(paymasterAccount),
		big.NewInt(0).Add(amount, order.Edges.Token.Edges.Network.Fee.BigInt()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create paymaster approve calldata : %w", err)
	}

	// Create transfer data
	transferData, err := s.transferCallData(to, amount)
	if err != nil {
		return nil, fmt.Errorf("failed to create transfer calldata: %w", err)
	}

	simpleAccountABI, err := abi.JSON(strings.NewReader(contracts.SimpleAccountMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse smart account ABI: %w", err)
	}

	executeBatchCallData, err := simpleAccountABI.Pack(
		"executeBatch",
		[]common.Address{
			common.HexToAddress(order.Edges.Token.ContractAddress),
			common.HexToAddress(order.Edges.Token.ContractAddress),
		},
		[][]byte{approvePaymasterData, transferData},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack execute ABI: %w", err)
	}

	return executeBatchCallData, nil
}

// executeBatchCreateOrderCallData creates the calldata for the execute batch method in the smart account.
func (s *OrderEVM) executeBatchCreateOrderCallData(order *ent.PaymentOrder) ([]byte, error) {
	orderAmountWithFees := order.Amount.Add(order.ProtocolFee).Add(order.SenderFee)

	// Create approve data for gateway contract
	approveGatewayData, err := s.approveCallData(
		common.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
		utils.ToSubunit(orderAmountWithFees.Mul(decimal.NewFromInt(2)), order.Edges.Token.Decimals),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gateway approve calldata: %w", err)
	}

	// Create createOrder data
	encryptedOrderRecipient, err := cryptoUtils.EncryptOrderRecipient(order.Edges.Recipient)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt order recipient: %w", err)
	}

	createOrderData, err := s.createOrderCallData(order, encryptedOrderRecipient)
	if err != nil {
		return nil, fmt.Errorf("failed to create createOrder calldata: %w", err)
	}

	// Initialize calls array with gateway approve and create order
	addresses := []common.Address{
		common.HexToAddress(order.Edges.Token.ContractAddress),
		common.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
	}
	calls := [][]byte{approveGatewayData, createOrderData}

	simpleAccountABI, err := abi.JSON(strings.NewReader(contracts.SimpleAccountMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse smart account ABI: %w", err)
	}

	executeBatchCreateOrderCallData, err := simpleAccountABI.Pack(
		"executeBatch",
		addresses,
		calls,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack execute ABI: %w", err)
	}

	return executeBatchCreateOrderCallData, nil
}

// approveCallData creates the data for the ERC20 approve method
func (s *OrderEVM) approveCallData(spender common.Address, amount *big.Int) ([]byte, error) {
	// Create ABI
	erc20ABI, err := abi.JSON(strings.NewReader(contracts.ERC20TokenMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse erc20 ABI: %w", err)
	}

	// Create calldata
	calldata, err := erc20ABI.Pack("approve", spender, amount)
	if err != nil {
		return nil, fmt.Errorf("failed to pack approve ABI: %w", err)
	}

	return calldata, nil
}

// transferCallData creates the data for the ERC20 token transfer method
func (s *OrderEVM) transferCallData(recipient common.Address, amount *big.Int) ([]byte, error) {
	// Create ABI
	erc20ABI, err := abi.JSON(strings.NewReader(contracts.ERC20TokenMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse erc20 ABI: %w", err)
	}

	// Create calldata
	calldata, err := erc20ABI.Pack("transfer", recipient, amount)
	if err != nil {
		return nil, fmt.Errorf("failed to pack transfer ABI: %w", err)
	}

	return calldata, nil
}

// // executeCallData creates the data for the execute method in the smart account.
// func (s *OrderEVM) executeCallData(dest common.Address, value *big.Int, data []byte) ([]byte, error) {
// 	simpleAccountABI, err := abi.JSON(strings.NewReader(contracts.SimpleAccountMetaData.ABI))
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse smart account ABI: %w", err)
// 	}

// 	executeCallData, err := simpleAccountABI.Pack(
// 		"execute",
// 		dest,
// 		value,
// 		data,
// 	)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to pack execute ABI: %w", err)
// 	}

// 	return executeCallData, nil
// }

// createOrderCallData creates the data for the createOrder method
func (s *OrderEVM) createOrderCallData(order *ent.PaymentOrder, encryptedOrderRecipient string) ([]byte, error) {
	amountWithProtocolFee := order.Amount.Add(order.ProtocolFee)

	// Define params
	params := &types.CreateOrderParams{
		Token:              common.HexToAddress(order.Edges.Token.ContractAddress),
		Amount:             utils.ToSubunit(amountWithProtocolFee, order.Edges.Token.Decimals),
		Rate:               order.Rate.Mul(decimal.NewFromInt(100)).BigInt(),
		SenderFeeRecipient: common.HexToAddress(order.FeeAddress),
		SenderFee:          utils.ToSubunit(order.SenderFee, order.Edges.Token.Decimals),
		RefundAddress:      common.HexToAddress(order.ReturnAddress),
		MessageHash:        encryptedOrderRecipient,
	}

	// Create ABI
	gatewayABI, err := abi.JSON(strings.NewReader(contracts.GatewayMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse GatewayOrder ABI: %w", err)
	}

	// Generate call data
	data, err := gatewayABI.Pack(
		"createOrder",
		params.Token,
		params.Amount,
		params.Rate,
		params.SenderFeeRecipient,
		params.SenderFee,
		params.RefundAddress,
		params.MessageHash,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack createOrder ABI: %w", err)
	}

	return data, nil
}

// executeBatchRefundCallData creates the refund calldata for the execute batch method in the smart account.
func (s *OrderEVM) executeBatchRefundCallData(order *ent.LockPaymentOrder) ([]byte, error) {
	var err error
	var client types.RPCClient

	// Connect to RPC endpoint
	retryErr := utils.Retry(3, 1*time.Second, func() error {
		client, err = types.NewEthClient(order.Edges.Token.Edges.Network.RPCEndpoint)
		return err
	})
	if retryErr != nil {
		return nil, retryErr
	}

	// Fetch onchain order details
	instance, err := contracts.NewGateway(common.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress), client.(bind.ContractBackend))
	if err != nil {
		return nil, err
	}

	orderID, err := hex.DecodeString(order.GatewayID[2:])
	if err != nil {
		return nil, err
	}

	orderInfo, err := instance.GetOrderInfo(nil, utils.StringToByte32(string(orderID)))
	if err != nil {
		return nil, err
	}

	// Create approve data for gateway contract
	approveGatewayData, err := s.approveCallData(
		common.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
		orderInfo.Amount,
	)
	if err != nil {
		return nil, fmt.Errorf("executeBatchRefundCallData.approveOrderContract: %w", err)
	}

	// Create refund data
	fee := utils.ToSubunit(decimal.NewFromInt(0), order.Edges.Token.Decimals)
	refundData, err := s.refundCallData(fee, order.GatewayID)
	if err != nil {
		return nil, fmt.Errorf("executeBatchRefundCallData.refundData: %w", err)
	}

	simpleAccountABI, err := abi.JSON(strings.NewReader(contracts.SimpleAccountMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("executeBatchRefundCallData.simpleAccountABI: %w", err)
	}

	contractAddresses := []common.Address{
		common.HexToAddress(order.Edges.Token.ContractAddress),
		common.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
	}

	data := [][]byte{approveGatewayData, refundData}

	executeBatchRefundCallData, err := simpleAccountABI.Pack(
		"executeBatch",
		contractAddresses,
		data,
	)
	if err != nil {
		return nil, fmt.Errorf("executeBatchRefundCallData: %w", err)
	}

	return executeBatchRefundCallData, nil
}

// refundCallData creates the data for the refund method
func (s *OrderEVM) refundCallData(fee *big.Int, orderId string) ([]byte, error) {
	gatewayABI, err := abi.JSON(strings.NewReader(contracts.GatewayMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse GatewayOrder ABI: %w", err)
	}

	decodedOrderID, err := hex.DecodeString(orderId[2:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode orderId: %w", err)
	}

	// Generate calldata for refund, orderID, and label should be byte32
	data, err := gatewayABI.Pack(
		"refund",
		fee,
		utils.StringToByte32(string(decodedOrderID)),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to pack refund ABI: %w", err)
	}

	return data, nil
}

// executeBatchSettleCallData creates the settle calldata for the execute batch method in the smart account.
func (s *OrderEVM) executeBatchSettleCallData(ctx context.Context, order *ent.LockPaymentOrder) ([]byte, error) {
	// Create approve data for gateway contract
	approveGatewayData, err := s.approveCallData(
		common.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
		utils.ToSubunit(order.Amount, order.Edges.Token.Decimals),
	)
	if err != nil {
		return nil, fmt.Errorf("approveOrderContract: %w", err)
	}

	contractAddresses := []common.Address{
		common.HexToAddress(order.Edges.Token.ContractAddress),
	}

	data := [][]byte{approveGatewayData}

	// Create settle data
	settleData, err := s.settleCallData(ctx, order)
	if err != nil {
		return nil, fmt.Errorf("settleData: %w", err)
	}

	simpleAccountABI, err := abi.JSON(strings.NewReader(contracts.SimpleAccountMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("simpleAccountABI: %w", err)
	}

	contractAddresses = append(
		contractAddresses,
		common.HexToAddress(order.Edges.Token.Edges.Network.GatewayContractAddress),
	)
	data = append(data, settleData)

	executeBatchSettleCallData, err := simpleAccountABI.Pack(
		"executeBatch",
		contractAddresses,
		data,
	)
	if err != nil {
		return nil, fmt.Errorf("executeBatchSettledCallData: %w", err)
	}

	return executeBatchSettleCallData, nil
}

// settleCallData creates the data for the settle method in the gateway contract
func (s *OrderEVM) settleCallData(ctx context.Context, order *ent.LockPaymentOrder) ([]byte, error) {
	gatewayABI, err := abi.JSON(strings.NewReader(contracts.GatewayMetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse GatewayOrder ABI: %w", err)
	}

	institution, err := utils.GetInstitutionByCode(ctx, order.Institution, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get institution: %w", err)
	}

	// Fetch provider address from db
	token, err := db.Client.ProviderOrderToken.
		Query().
		Where(
			providerordertoken.NetworkEQ(order.Edges.Token.Edges.Network.Identifier),
			providerordertoken.HasProviderWith(
				providerprofile.IDEQ(order.Edges.Provider.ID),
			),
			providerordertoken.HasTokenWith(
				tokenent.IDEQ(order.Edges.Token.ID),
			),
			providerordertoken.HasCurrencyWith(
				fiatcurrency.CodeEQ(institution.Edges.FiatCurrency.Code),
			),
			providerordertoken.AddressNEQ(""),
		).
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch provider order token: %w", err)
	}

	orderPercent, _ := order.OrderPercent.
		Mul(decimal.NewFromInt(1000)). // convert percent to BPS
		Float64()

	orderID, err := hex.DecodeString(order.GatewayID[2:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode orderID: %w", err)
	}

	splitOrderID := strings.ReplaceAll(order.ID.String(), "-", "")

	// Generate calldata for settlement
	data, err := gatewayABI.Pack(
		"settle",
		utils.StringToByte32(splitOrderID),
		utils.StringToByte32(string(orderID)),
		common.HexToAddress(token.Address),
		uint64(orderPercent),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack settle ABI: %w", err)
	}

	return data, nil
}
