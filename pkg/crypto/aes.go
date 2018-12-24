package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"strings"

	"crypto/hmac"

	"github.com/keylockerbv/secrethub-go/pkg/crypto/hashing"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

// Errors
var (
	ErrInvalidCipher = errCrypto.Code("aes_cipher_invalid").ErrorPref("cipher is invalid: %v")
	ErrAESDecrypt    = errCrypto.Code("aes_decrypt_failed").ErrorPref("could not decrypt data: %s")
	ErrAESEncrypt    = errCrypto.Code("aes_encrypt_failed").ErrorPref("could not encrypt data: %s")
)

const (
	// HMACByteSize is a constant that contains the size of an hmac byte slice.
	HMACByteSize = 32
)

// AESKey provides all cryptographic functions for a directory.
// The AESKey contains the directory key.
type AESKey struct {
	key []byte
}

// NewAESKey is used to create a new AESKey.
func NewAESKey(keyData []byte) *AESKey {
	return &AESKey{
		key: keyData,
	}
}

// GenerateAESKey generates a 256-bit AES-key.
func GenerateAESKey() (*AESKey, error) {
	key := make([]byte, 32)
	_, err := rand.Reader.Read(key)
	if err != nil {
		return nil, errio.Error(err)
	}

	return &AESKey{
		key: key,
	}, nil
}

// Decrypt decrypts the encryptedData with AES-GCM using the AESKey and the provided nonce.
func (k *AESKey) Decrypt(encryptedData, nonce []byte) ([]byte, error) {
	key, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, ErrInvalidCipher(err)
	}

	gcm, err := cipher.NewGCM(key)
	if err != nil {
		return nil, ErrInvalidCipher(err)
	}

	output, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, ErrAESDecrypt(err)
	}

	// We do not use a destination []byte, but a return value.
	return output, nil
}

// Encrypt encrypts the data with AES-GCM using the AESKey.
// Returns the encrypted data and the nonce as []byte.
func (k *AESKey) Encrypt(data []byte) ([]byte, []byte, error) {
	key, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, nil, ErrInvalidCipher(err)
	}

	gcm, err := cipher.NewGCM(key)
	if err != nil {
		return nil, nil, ErrInvalidCipher(err)
	}

	nonce, err := GenerateNonce(gcm.NonceSize())
	if err != nil {
		return nil, nil, ErrAESEncrypt(err)
	}

	// We do not use a destination []byte, but a return value.
	encData := gcm.Seal(nil, *nonce, data, nil)

	return encData, *nonce, nil
}

// HMAC creates an HMAC of the data.
func (k AESKey) HMAC(data []byte) ([]byte, error) {
	mac := hmac.New(hashing.New, k.key)
	_, err := mac.Write(data)
	if err != nil {
		return nil, errio.Error(err)
	}
	return mac.Sum(nil), nil
}

// Export will export the AESKey.
// No format is used.
func (k *AESKey) Export() []byte {
	return k.key
}

// IsWrongKey returns true when the error can be
// the result of a wrong key being used for decryption.
func IsWrongKey(err error) bool {
	return err != nil && strings.Contains(err.Error(), "cipher: message authentication failed")
}
