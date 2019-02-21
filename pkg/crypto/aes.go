package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

// Decrypt decrypts the encryptedData with AES-GCM using the AESKey and the provided nonce.
func (k *AESKey) Decrypt(encodedCiphertextAES EncodedCiphertextAES) ([]byte, error) {
	ciphertext, err := encodedCiphertextAES.decode()
	if err != nil {
		return nil, err
	}

	return k.decrypt(ciphertext.Data, ciphertext.Nonce)
}

// Encrypt encrypts the data with AES-GCM using the AESKey.
func (k *AESKey) Encrypt(data []byte) (EncodedCiphertextAES, error) {
	ciphertext, err := k.encrypt(data)
	if err != nil {
		return "", err
	}
	return ciphertext.Encode(), nil
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
func (k *AESKey) encrypt(data []byte) (*ciphertextAES, error) {
	key, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, ErrInvalidCipher(err)
	}

	gcm, err := cipher.NewGCM(key)
	if err != nil {
		return nil, ErrInvalidCipher(err)
	}

	nonce, err := GenerateNonce(gcm.NonceSize())
	if err != nil {
		return nil, ErrAESEncrypt(err)
	}

	// We do not use a destination []byte, but a return value.
	encData := gcm.Seal(nil, *nonce, data, nil)

	return &ciphertextAES{
		Data:  encData,
		Nonce: *nonce,
	}, nil
}


// IsWrongKey returns true when the error can be
// the result of a wrong key being used for decryption.
func IsWrongKey(err error) bool {
	return err != nil && strings.Contains(err.Error(), "cipher: message authentication failed")
}

// ciphertextAES represents data encrypted with AES-GCM.
type ciphertextAES struct {
	Data  []byte
	Nonce []byte
}

// Decrypt decrypts the data in ciphertextAES with AES-GCM using the provided key.
func (b *ciphertextAES) Decrypt(k Key) ([]byte, error) {
	aesKey, ok := k.(*AESKey)
	if !ok {
		return nil, ErrWrongKeyType
	}

	if b.Data == nil || b.Nonce == nil {
		return nil, ErrInvalidCiphertext
	}

	return aesKey.Decrypt(b.Encode())
}

// Encode encodes the ciphertext in a string.
func (b ciphertextAES) Encode() EncodedCiphertextAES {
	return EncodedCiphertextAES(
		NewEncodedCiphertext(
			AlgorithmAES,
			b.Data,
			map[string]string{
				"nonce": base64.StdEncoding.EncodeToString(b.Nonce),
			},
		),
	)
}
