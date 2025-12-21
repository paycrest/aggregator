package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/common"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/paycrest/aggregator/config"
	"github.com/paycrest/aggregator/ent"
	"github.com/paycrest/aggregator/types"
	tronWallet "github.com/paycrest/tron-wallet"
	tronEnums "github.com/paycrest/tron-wallet/enums"
	"golang.org/x/crypto/bcrypt"
)

var authConf = config.AuthConfig()
var cryptoConf = config.CryptoConfig()
var serverConf = config.ServerConfig()

// CheckPasswordHash is a function to compare provided password with the hashed password
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// EncryptPlain encrypts plaintext using AES encryption algorithm with Galois Counter Mode
func EncryptPlain(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(authConf.Secret))
	if err != nil {
		return nil, err
	}

	// Create GCM with 12 byte nonce
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and append nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// DecryptPlain decrypts ciphertext using AES encryption algorithm with Galois Counter Mode
func DecryptPlain(ciphertext []byte) ([]byte, error) {

	block, err := aes.NewCipher([]byte(authConf.Secret))
	if err != nil {
		return nil, err
	}

	// Create GCM with nonce
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Parse nonce from ciphertext
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]

	// Decrypt and return plaintext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptJSON encrypts JSON serializable data using AES encryption algorithm with Galois Counter Mode
func EncryptJSON(data interface{}) ([]byte, error) {

	// Encode data to JSON
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	// Encrypt as normal
	ciphertext, err := EncryptPlain(plaintext)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// DecryptJSON decrypts JSON serializable data using AES encryption algorithm with Galois Counter Mode
func DecryptJSON(ciphertext []byte) (interface{}, error) {

	// Decrypt as normal
	plaintext, err := DecryptPlain(ciphertext)
	if err != nil {
		return nil, err
	}

	// Decode JSON back to dynamic type
	var data interface{}
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, err
	}

	return data, nil

}

// PublicKeyEncryptPlain encrypts plaintext using RSA 2048 encryption algorithm
func PublicKeyEncryptPlain(plaintext []byte, publicKeyPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	var publicKey rsa.PublicKey

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKey = *pub
	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, &publicKey, plaintext)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

// PublicKeyEncryptJSON encrypts JSON serializable data using RSA 2048 encryption algorithm
func PublicKeyEncryptJSON(data interface{}, publicKeyPEM string) ([]byte, error) {

	// Encode data to JSON
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	// Encrypt as normal
	ciphertext, err := PublicKeyEncryptPlain(plaintext, publicKeyPEM)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// PublicKeyDecryptPlain decrypts ciphertext using RSA 2048 encryption algorithm
func PublicKeyDecryptPlain(ciphertext []byte, privateKeyPEM string) ([]byte, error) {
	privateKeyBlock, _ := pem.Decode([]byte(privateKeyPEM))
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// PublicKeyDecryptJSON decrypts JSON serializable data using RSA 2048 encryption algorithm
func PublicKeyDecryptJSON(ciphertext []byte, privateKeyPEM string) (interface{}, error) {

	// Decrypt as normal
	plaintext, err := PublicKeyDecryptPlain(ciphertext, privateKeyPEM)
	if err != nil {
		return nil, err
	}

	// Decode JSON back to dynamic type
	var data interface{}
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, err
	}

	return data, nil
}

// GenerateAccountFromIndex generates a crypto wallet account from HD wallet mnemonic
func GenerateAccountFromIndex(accountIndex int) (*common.Address, *ecdsa.PrivateKey, error) {
	mnemonic := cryptoConf.HDWalletMnemonic

	wallet, err := hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create wallet from mnemonic: %w", err)
	}

	path, err := hdwallet.ParseDerivationPath(fmt.Sprintf("m/44'/60'/0'/0/%d", accountIndex))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse derivation path: %w", err)
	}

	account, err := wallet.Derive(path, false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive account: %w", err)
	}

	privateKey, err := wallet.PrivateKey(account)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get private key: %w", err)
	}
	privateKey.Curve = btcec.S256()

	return &account.Address, privateKey, nil
}

// GenerateTronAccountFromIndex generates a Tron wallet account from HD wallet mnemonic
func GenerateTronAccountFromIndex(accountIndex int) (wallet *tronWallet.TronWallet, err error) {
	mnemonic := cryptoConf.HDWalletMnemonic

	var nodeUrl tronEnums.Node
	if serverConf.Environment == "production" {
		nodeUrl = tronEnums.MAIN_NODE
	} else {
		nodeUrl = tronEnums.SHASTA_NODE
	}

	wallet, err = tronWallet.MnemonicToTronWallet(nodeUrl, mnemonic, fmt.Sprintf("m/44'/195'/3'/0/%d", accountIndex), "")
	if err != nil {
		return nil, fmt.Errorf("failed to create wallet from mnemonic: %w", err)
	}

	return wallet, nil
}

// EncryptOrderRecipient encrypts the recipient details using the aggregator's public key
func EncryptOrderRecipient(order *ent.PaymentOrder) (string, error) {
	// Generate a cryptographically secure random nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	var providerID string
	if order.Edges.Provider != nil {
		providerID = order.Edges.Provider.ID
	}
	message := struct {
		Nonce             string
		AccountIdentifier string
		AccountName       string
		Institution       string
		ProviderID        string
		Memo              string
		Metadata          map[string]interface{}
	}{
		base64.StdEncoding.EncodeToString(nonce), order.AccountIdentifier, order.AccountName, order.Institution, providerID, order.Memo, order.Metadata,
	}

	// Encrypt with the public key of the aggregator
	messageCipher, err := PublicKeyEncryptJSON(message, cryptoConf.AggregatorPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt message: %w", err)
	}

	return base64.StdEncoding.EncodeToString(messageCipher), nil
}

// GetOrderRecipientFromMessageHash decrypts the message hash and returns the order recipient
func GetOrderRecipientFromMessageHash(messageHash string) (*types.PaymentOrderRecipient, error) {
	messageCipher, err := base64.StdEncoding.DecodeString(messageHash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode message hash: %w", err)
	}

	// Decrypt with the private key of the aggregator
	message, err := PublicKeyDecryptJSON(messageCipher, config.CryptoConfig().AggregatorPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message hash: %w", err)
	}

	messageBytes, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}

	var recipient *types.PaymentOrderRecipient
	err = json.Unmarshal(messageBytes, &recipient)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return recipient, nil
}

func NormalizeStarknetAddress(address string) string {
	// Remove 0x prefix if present
	addr := strings.TrimPrefix(address, "0x")
	
	// Starknet addresses should be 64 hex characters (excluding 0x)
	// Pad with leading zeros if shorter
	if len(addr) < 64 {
		addr = strings.Repeat("0", 64-len(addr)) + addr
	}
	
	// Add 0x prefix back
	return "0x" + addr
}


// generateSecureSeed generates a cryptographically secure random seed
func GenerateSecureSeed() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
