package crypto

import (
	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

// Errors
var (
	ErrWrongKeyType      = errCrypto.Code("wrong_key_type").Error("received wrong key type")
	ErrInvalidCiphertext = errCrypto.Code("invalid_ciphertext").Error("ciphertext contains invalid data")
)

// Key represents a key that can be used to decrypt data.
type Key interface{}

// Ciphertext is an interface for to decrypt encrypted data.
type Ciphertext interface {
	Decrypt(k Key) ([]byte, error)
	ReEncrypt(decryptKey, encryptKey Key) (Ciphertext, error)
}

// CiphertextRSAAES represents data encrypted with AES-GCM, where the AES-key is encrypted with RSA-OAEP.
type CiphertextRSAAES struct {
	*CiphertextAES
	*CiphertextRSA
}

// CiphertextAES represents data encrypted with AES-GCM.
type CiphertextAES struct {
	Data  []byte
	Nonce []byte
}

// CiphertextRSA represents data encrypted with RSA-OAEP.
type CiphertextRSA struct {
	Data []byte
}

// EncryptRSAAES encrypts provided data with AES-GCM.
// The used AES-key is then encrypted with RSA-OAEP.
func EncryptRSAAES(data []byte, k *RSAPublicKey) (*CiphertextRSAAES, error) {
	aesKey, err := GenerateAESKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	aesData, err := EncryptAES(data, aesKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	rsaData, err := EncryptRSA(aesKey.key, k)
	if err != nil {
		return nil, errio.Error(err)
	}

	return &CiphertextRSAAES{
		CiphertextAES: aesData,
		CiphertextRSA: rsaData,
	}, nil
}

// Decrypt decrypts the key in CiphertextRSAAES with RSA-OAEP and then decrypts the data in CiphertextRSAAES with AES-GCM.
func (b *CiphertextRSAAES) Decrypt(k Key) ([]byte, error) {
	if b.CiphertextRSA == nil || b.CiphertextAES == nil {
		return nil, ErrInvalidCiphertext
	}

	aesKeyData, err := b.CiphertextRSA.Decrypt(k)
	if err != nil {
		return nil, errio.Error(err)
	}

	aesKey := &AESKey{aesKeyData}

	return b.CiphertextAES.Decrypt(aesKey)
}

// ReEncrypt reencrypts the ciphertext using RSA+AES for the given encryption key.
func (b *CiphertextRSAAES) ReEncrypt(decryptKey, encryptKey Key) (Ciphertext, error) {
	decrypted, err := b.Decrypt(decryptKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	rsaKey, ok := encryptKey.(*RSAPublicKey)
	if !ok {
		return nil, ErrWrongKeyType
	}

	return EncryptRSAAES(decrypted, rsaKey)
}

// EncryptAES encrypts the provided data with AES-GCM.
func EncryptAES(data []byte, k *AESKey) (*CiphertextAES, error) {
	encryptedData, nonce, err := k.Encrypt(data)
	if err != nil {
		return nil, errio.Error(err)
	}

	return &CiphertextAES{
		Data:  encryptedData,
		Nonce: nonce,
	}, nil
}

// Decrypt decrypts the data in CiphertextAES with AES-GCM using the provided key.
func (b *CiphertextAES) Decrypt(k Key) ([]byte, error) {
	aesKey, ok := k.(*AESKey)
	if !ok {
		return nil, ErrWrongKeyType
	}

	if b.Data == nil || b.Nonce == nil {
		return nil, ErrInvalidCiphertext
	}

	return aesKey.Decrypt(b.Data, b.Nonce)
}

// ReEncrypt reencrypts the ciphertext using AES for the given encryption key.
func (b *CiphertextAES) ReEncrypt(decryptKey, encryptKey Key) (Ciphertext, error) {
	decrypted, err := b.Decrypt(decryptKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	aesKey, ok := encryptKey.(*AESKey)
	if !ok {
		return nil, ErrWrongKeyType
	}

	return EncryptAES(decrypted, aesKey)
}

// EncryptRSA encrypts the provided data with RSA-OAEP.
func EncryptRSA(data []byte, k *RSAPublicKey) (*CiphertextRSA, error) {
	encryptedData, err := k.Encrypt(data)
	if err != nil {
		return nil, errio.Error(err)
	}

	return &CiphertextRSA{
		Data: encryptedData,
	}, nil
}

// Decrypt decrypts the data in CiphertextRSA with RSA-OAEP using the provided key.
func (b *CiphertextRSA) Decrypt(k Key) ([]byte, error) {
	rsaKey, ok := k.(*RSAKey)
	if !ok {
		return nil, ErrWrongKeyType
	}

	if b.Data == nil {
		return nil, ErrInvalidCiphertext
	}

	return rsaKey.Decrypt(b.Data)
}

// ReEncrypt reencrypts the ciphertext using RSA for the given encryption key.
func (b *CiphertextRSA) ReEncrypt(decryptKey, encryptKey Key) (Ciphertext, error) {
	decrypted, err := b.Decrypt(decryptKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	rsaKey, ok := encryptKey.(*RSAPublicKey)
	if !ok {
		return nil, ErrWrongKeyType
	}

	return EncryptRSA(decrypted, rsaKey)
}
