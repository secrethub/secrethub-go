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
	// HMACSize defines the number of bytes in the resulting hash,
	//  i.e. the number of bits divided by 8.
	HMACSize = SymmetricKeyLength

	// SymmetricKeyLength defines number of bytes to use as key length (256 bits)
	// for symmetric encryption, i.e. the number of bits divided by 8.
	SymmetricKeyLength = 32
)

// SymmetricKey provides symmetric encryption functions that use the AES algorithm.
type SymmetricKey struct {
	key []byte
}

// NewSymmetricKey is used to construct a symmetric AES key from given bytes. Make sure
// the key bytes have enough entropy. When in doubt, use GenerateSymmetricKey instead.
func NewSymmetricKey(key []byte) *SymmetricKey {
	return &SymmetricKey{
		key: key,
	}
}

// GenerateSymmetricKey generates a 256-bit AES-key.
func GenerateSymmetricKey() (*SymmetricKey, error) {
	key := make([]byte, SymmetricKeyLength)
	_, err := rand.Reader.Read(key)
	if err != nil {
		return nil, errio.Error(err)
	}

	return &SymmetricKey{
		key: key,
	}, nil
}

// Encrypt uses the key to encrypt given data with the AES-GCM algorithm,
// returning the resulting ciphertext.
func (k *SymmetricKey) Encrypt(data []byte) (CiphertextAES, error) {
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

// Decrypt uses the key to decrypt a given ciphertext with teh AES-GCM algorithm,
// returning the decrypted bytes.
func (k *SymmetricKey) Decrypt(ciphertext CiphertextAES) ([]byte, error) {
	if len(ciphertext.Data) == 0 {
		return []byte{}, nil
	}

	if len(ciphertext.Nonce) == 0 {
		return nil, ErrInvalidCiphertext
	}

	return k.decrypt(ciphertext.Data, ciphertext.Nonce)
}

// HMAC uses the key to create a Hash-based Message Authentication Code of the
// given data with the SHA256 hashing algorithm, returning the given hash bytes.
func (k SymmetricKey) HMAC(data []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, k.key)
	_, err := mac.Write(data)
	if err != nil {
		return nil, errio.Error(err)
	}
	return mac.Sum(nil), nil
}

// Export returns the bytes that form the basis of the symmetric key.
// After using Export, make sure to keep the result private.
func (k *SymmetricKey) Export() []byte {
	return k.key
}

// decrypt is a helper function that uses the key to decrypt given
// data with the AES-GCM algorithm and a given nonce.
func (k SymmetricKey) decrypt(data, nonce []byte) ([]byte, error) {
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

// generateNonce generates a nonce of a given length.
//
// TODO: why does it return a pointer to bytes?
func generateNonce(size int) (*[]byte, error) {
	nonce := make([]byte, size)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errio.Error(err)
	}
	return &nonce, nil
}
