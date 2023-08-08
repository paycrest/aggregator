package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/paycrest/paycrest-protocol/config"
	"golang.org/x/crypto/bcrypt"
)

var authConf = config.AuthConfig()
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

// GenerateAccountFromIndex generates a crypto wallet account from HD wallet mnemonic
func GenerateAccountFromIndex(accountIndex int) (string, string, error) {
	//added code to test generate addrress
	mnemonic := serverConf.HDWalletMnemonic

	wallet, err := hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		return "", "", fmt.Errorf("failed to create wallet from mnemonic: %w", err)
	}

	path, err := hdwallet.ParseDerivationPath(fmt.Sprintf("m/44'/60'/0'/0/%d", accountIndex))
	if err != nil {
		return "", "", fmt.Errorf("failed to parse derivation path: %w", err)
	}

	account, err := wallet.Derive(path, false)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive account: %w", err)
	}

	privateKey, err := wallet.PrivateKey(account)
	if err != nil {
		return "", "", fmt.Errorf("failed to get private key: %w", err)
	}

	privateKeyHex := hexutil.Encode(crypto.FromECDSA(privateKey))
	address := account.Address.Hex()

	return address, privateKeyHex, nil
}
