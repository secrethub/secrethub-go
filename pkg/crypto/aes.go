package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"crypto/hmac"

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

// Encrypt encrypts the data with AES-GCM using the AESKey.
func (k *AESKey) Encrypt(data []byte) (CiphertextAES, error) {
	key, err := aes.NewCipher(k.key)
	if err != nil {
		return CiphertextAES{}, ErrInvalidCipher(err)
	}

	gcm, err := cipher.NewGCM(key)
	if err != nil {
		return CiphertextAES{}, ErrInvalidCipher(err)
	}

	nonce, err := generateNonce(gcm.NonceSize())
	if err != nil {
		return CiphertextAES{}, ErrAESEncrypt(err)
	}

	// We do not use a destination []byte, but a return value.
	encData := gcm.Seal(nil, *nonce, data, nil)

	return CiphertextAES{
		Data:  encData,
		Nonce: *nonce,
	}, nil
}

// Decrypt decrypts the encryptedData with AES-GCM using the AESKey and the provided nonce.
func (k *AESKey) Decrypt(ciphertext CiphertextAES) ([]byte, error) {
	if len(ciphertext.Data) == 0 {
		return []byte{}, nil
	}

	if len(ciphertext.Nonce) == 0 {
		return nil, ErrInvalidCiphertext
	}

	return k.decrypt(ciphertext.Data, ciphertext.Nonce)
}

// HMAC creates an HMAC of the data.
func (k AESKey) HMAC(data []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, k.key)
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

func (k AESKey) decrypt(data, nonce []byte) ([]byte, error) {
	key, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, ErrInvalidCipher(err)
	}

	gcm, err := cipher.NewGCM(key)
	if err != nil {
		return nil, ErrInvalidCipher(err)
	}

	output, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, ErrAESDecrypt(err)
	}

	// We do not use a destination []byte, but a return value.
	return output, nil
}

// IsWrongKey returns true when the error can be
// the result of a wrong key being used for decryption.
func IsWrongKey(err error) bool {
	return err != nil && strings.Contains(err.Error(), "cipher: message authentication failed")
}

// CiphertextAES represents data encrypted with AES-GCM.
type CiphertextAES struct {
	Data  []byte
	Nonce []byte
}

// MarshalJSON encodes the ciphertext in a string.
func (ct CiphertextAES) MarshalJSON() ([]byte, error) {
	data := base64.StdEncoding.EncodeToString(ct.Data)

	metadata := newEncodedCiphertextMetadata(map[string]string{
		"nonce": base64.StdEncoding.EncodeToString(ct.Nonce),
	})

	return json.Marshal(fmt.Sprintf("%s$%s$%s", algorithmAES, data, metadata))
}

// UnmarshalJSON decodes a string into a ciphertext.
func (ct *CiphertextAES) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	if s == "" {
		return nil
	}

	encoded, err := newEncodedCiphertext(s)
	if err != nil {
		return err
	}

	algorithm, err := encoded.algorithm()
	if err != nil {
		return errio.Error(err)
	}

	if algorithm != algorithmAES {
		return ErrWrongAlgorithm
	}

	encryptedData, err := encoded.data()
	if err != nil {
		return errio.Error(err)
	}

	metadata, err := encoded.metadata()
	if err != nil {
		return errio.Error(err)
	}

	aesNonce, err := metadata.getDecodedValue("nonce")
	if err != nil {
		return errio.Error(err)
	}

	ct.Data = encryptedData
	ct.Nonce = aesNonce

	return nil
}

// generateNonce generates a Nonce of a particular size.
func generateNonce(size int) (*[]byte, error) {
	nonce := make([]byte, size)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errio.Error(err)
	}
	return &nonce, nil
}
