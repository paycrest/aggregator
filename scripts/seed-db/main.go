package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"

	"github.com/paycrest/protocol/config"
	"github.com/paycrest/protocol/ent"
	"github.com/paycrest/protocol/ent/fiatcurrency"
	"github.com/paycrest/protocol/storage"
	"github.com/paycrest/protocol/types"
	"github.com/paycrest/protocol/utils/crypto"
	"github.com/paycrest/protocol/utils/logger"
	"github.com/paycrest/protocol/utils/token"
	"github.com/shopspring/decimal"
)

func main() {
	// Connect to the database
	DSN := config.DBConfig()

	if err := storage.DBConnection(DSN); err != nil {
		logger.Fatalf("database DBConnection: %s", err)
	}

	client := storage.GetClient()

	defer client.Close()
	ctx := context.Background()

	// Delete existing data
	_ = client.Network.Delete().ExecX(ctx)
	_ = client.Token.Delete().ExecX(ctx)
	_ = client.FiatCurrency.Delete().ExecX(ctx)
	_ = client.ProvisionBucket.Delete().ExecX(ctx)
	_ = client.User.Delete().ExecX(ctx)
	_ = client.ProviderProfile.Delete().ExecX(ctx)
	_ = client.ProviderOrderToken.Delete().ExecX(ctx)
	_ = client.SenderProfile.Delete().ExecX(ctx)
	_ = client.ReceiveAddress.Delete().ExecX(ctx)

	// Seed Network
	fmt.Println("seeding network...")
	network, err := client.Network.
		Create().
		SetIdentifier("polygon-mumbai").
		SetChainID(80001).
		SetRPCEndpoint("wss://polygon-mumbai.infura.io/ws/v3/4458cf4d1689497b9a38b1d6bbf05e78").
		SetIsTestnet(true).
		Save(ctx)
	if err != nil {
		logger.Fatalf("failed seeding network: %s", err)
	}

	// Seed Tokens
	fmt.Println("seeding tokens...")
	_, err = client.Token.
		Create().
		SetSymbol("USDC").
		SetContractAddress("0x9999f7Fea5938fD3b1E26A12c3f2fb024e194f97").
		SetDecimals(6).
		SetNetwork(network).
		SetIsEnabled(true).
		Save(ctx)
	if err != nil {
		logger.Fatalf("failed seeding USDC: %s", err)
	}

	_, err = client.Token.
		Create().
		SetSymbol("6TEST").
		SetContractAddress("0x3870419Ba2BBf0127060bCB37f69A1b1C090992B").
		SetDecimals(6).
		SetNetwork(network).
		SetIsEnabled(true).
		Save(ctx)
	if err != nil {
		logger.Fatalf("failed seeding 6TEST: %s", err)
	}

	// Seed Fiat Currencies and Provision Buckets
	fmt.Println("fiat currencies and provision buckets...")
	currencies := []types.SupportedCurrencies{
		{Code: "NGN", Decimals: 2, Name: "Nigerian Naira", ShortName: "Naira", Symbol: "₦", MarketRate: decimal.NewFromFloat(1050.00)},
		// {Code: "KES", Decimals: 2, Name: "Kenyan Shilling", ShortName: "Swahili", Symbol: "KSh", MarketRate: decimal.NewFromFloat(151.45)},
	}
	sampleBuckets := make([]*ent.ProvisionBucketCreate, 0, 6)

	for _, currencyVal := range currencies {
		currency, err := client.FiatCurrency.
			Query().
			Where(
				fiatcurrency.IsEnabledEQ(true),
				fiatcurrency.CodeEQ(currencyVal.Code),
			).
			Only(ctx)
		if ent.IsNotFound(err) {
			currency, _ = client.FiatCurrency.
				Create().
				SetCode(currencyVal.Code).
				SetShortName(currencyVal.ShortName).
				SetSymbol(currencyVal.Symbol).
				SetName(currencyVal.Name).
				SetMarketRate(currencyVal.MarketRate).
				SetIsEnabled(true).
				Save(ctx)
		}

		createProvisionBucket := func(min, max float64) *ent.ProvisionBucketCreate {
			return client.ProvisionBucket.
				Create().
				SetMinAmount(decimal.NewFromFloat(min)).
				SetMaxAmount(decimal.NewFromFloat(max)).
				SetCurrency(currency)
		}

		sampleBuckets = append(sampleBuckets, createProvisionBucket(5001.00, 50000.00))
		sampleBuckets = append(sampleBuckets, createProvisionBucket(1001.00, 5000.00))
		sampleBuckets = append(sampleBuckets, createProvisionBucket(0.00, 1000.00))
	}

	fmt.Println("seed users, profiles, and order tokens...")

	// Seed a user with sender scope and create sender profile
	fmt.Println("\n==================================\nSample Senders - COPY THE KEYS\n==================================")

	randomNo := rand.New(rand.NewSource(time.Now().UnixNano())).Intn(10)
	email, clientID, secretKey, err := seedSender(ctx, client, fmt.Sprint(randomNo))
	if err != nil {
		logger.Fatalf("failed seeding sender: %s", err)
	}

	fmt.Printf("Email: %s, API Client ID: %s, API Secret Key: %s\n\n", email, clientID, secretKey)

	// Seed users with provider scope and create provider profiles
	fmt.Println("\n==================================\nSample Providers - COPY THE KEYS\n==================================")

	for i, sampleBucket := range sampleBuckets {
		bucket, err := sampleBucket.Save(ctx)
		if err != nil {
			logger.Fatalf("failed seeding provision bucket: %s", err)
		}

		for j := 0; j < 2; j++ {
			email, clientID, secretKey, err := seedProvider(ctx, client, bucket, fmt.Sprintf("%d_%d", i, j))
			if err != nil {
				logger.Fatalf("failed seeding provider: %s", err)
			}

			fmt.Printf("Email: %s, API Client ID: %s, API Secret Key: %s\n\n", email, clientID, secretKey)
		}
	}
}

func initAPIKeyCreate(ctx context.Context, client *ent.Client) (*ent.APIKeyCreate, string, string, error) {
	secretKey, err := token.GeneratePrivateKey()
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate API key: %s", err)
	}
	encryptedSecret, _ := crypto.EncryptPlain([]byte(secretKey))
	encodedSecret := base64.StdEncoding.EncodeToString(encryptedSecret)

	return client.APIKey.Create(), secretKey, encodedSecret, nil
}

func seedSender(ctx context.Context, client *ent.Client, serial string) (string, string, string, error) {
	user, err := client.User.
		Create().
		SetFirstName("John").
		SetLastName("Doe").
		SetEmail(fmt.Sprintf("sender_%s@example.com", serial)).
		SetPassword("password").
		SetScope("sender").
		SetIsEmailVerified(true).
		Save(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("failed creating user: %s", err)
	}

	sender, err := client.SenderProfile.
		Create().
		SetUser(user).
		SetWebhookURL("https://example.com/webhook").
		SetFeePerTokenUnit(decimal.NewFromFloat(10)).
		SetFeeAddress("0x409689E3008d43a9eb439e7B275749D4a71D8E2D").
		SetRefundAddress("0x409689E3008d43a9eb439e7B275749D4a71D8E2D").
		SetDomainWhitelist([]string{"https://example.com"}).
		SetIsActive(true).
		Save(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("failed creating sender profile: %s", err)
	}

	apiKeyCreate, secretKey, encodedSecret, err := initAPIKeyCreate(ctx, client)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to initialize sender API key: %s", err)
	}

	apiKey, err := apiKeyCreate.
		SetSecret(encodedSecret).
		SetSenderProfile(sender).
		Save(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create sender API key: %s", err)
	}

	return user.Email, apiKey.ID.String(), secretKey, nil
}

func seedProvider(ctx context.Context, client *ent.Client, bucket *ent.ProvisionBucket, serial string) (string, string, string, error) {
	user, err := client.User.
		Create().
		SetFirstName("John").
		SetLastName("Doe").
		SetEmail(fmt.Sprintf("user_%s@example.com", serial)).
		SetPassword("password").
		SetScope("provider").
		SetIsEmailVerified(true).
		Save(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("failed creating provider user: %s", err)
	}

	currency := bucket.QueryCurrency().OnlyX(ctx)

	provider, err := client.ProviderProfile.
		Create().
		SetTradingName(fmt.Sprintf("Provider_%s", serial)).
		SetHostIdentifier("http://localhost:8001").
		SetUser(user).
		SetIsActive(true).
		SetIsAvailable(true).
		SetCurrencyID(currency.ID).
		SetAddress("123 Main St").
		SetMobileNumber("+2348063000000").
		SetDateOfBirth(time.Date(1990, time.January, 1, 0, 0, 0, 0, time.UTC)).
		SetBusinessName("ABC Corporation").
		SetIdentityDocumentType("passport").
		SetIdentityDocument("https://example.com/identity_document.jpg").
		SetBusinessDocument("https://example.com/business_document.pdf").
		AddProvisionBuckets(bucket).
		Save(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("failed creating provider: %s", err)
	}

	apiKeyCreate, secretKey, encodedSecret, err := initAPIKeyCreate(ctx, client)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to initialize provider API key: %s", err)
	}

	apiKey, err := apiKeyCreate.
		SetSecret(encodedSecret).
		SetProviderProfile(provider).
		Save(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create provider API key: %s", err)
	}

	// Configure tokens
	addresses := []struct {
		Address string `json:"address"`
		Network string `json:"network"`
	}{
		{Address: "0x409689E3008d43a9eb439e7B275749D4a71D8E2D", Network: "polygon-mumbai"},
	}

	_, err = client.ProviderOrderToken.
		Create().
		SetSymbol("USDC").
		SetConversionRateType("floating").
		SetFixedConversionRate(decimal.NewFromFloat(0)).
		SetFloatingConversionRate(decimal.NewFromFloat(1)).
		SetMinOrderAmount(bucket.MinAmount).
		SetMaxOrderAmount(bucket.MaxAmount).
		SetAddresses(addresses).
		SetProvider(provider).
		Save(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to configure order tokens: %s", err)
	}

	_, err = client.ProviderOrderToken.
		Create().
		SetSymbol("6TEST").
		SetConversionRateType("floating").
		SetFixedConversionRate(decimal.NewFromFloat(0)).
		SetFloatingConversionRate(decimal.NewFromFloat(1)).
		SetMinOrderAmount(bucket.MinAmount).
		SetMaxOrderAmount(bucket.MaxAmount).
		SetAddresses(addresses).
		SetProvider(provider).
		Save(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to configure order tokens: %s", err)
	}

	return user.Email, apiKey.ID.String(), secretKey, nil
}
