package crypto

import (
	"github.com/keylockerbv/secrethub-go/pkg/errio"
	"golang.org/x/crypto/scrypt"
)

// Errors
var (
	ErrInvalidKeyLength = errCrypto.Code("invalid_key_length").Error("key length must be either 16, 24, or 32 bytes long (128, 196 or 256 bits)")
	ErrInvalidN         = errCrypto.Code("invalid_n").Error("scrypt parameter N must be a power of 2 and at least 2^15")
	ErrInvalidR         = errCrypto.Code("invalid_r").Error("scrypt parameter r must be 8")
	ErrInvalidP         = errCrypto.Code("invalid_p").Error("scrypt parameter p must be 1")
)

const (
	// DefaultScryptKeyLength defines the default key length (256 bits) of the derived key.
	DefaultScryptKeyLength = 32

	// DefaultScryptN is the work factor of the scrypt key derivation
	// function. Changing the work factor N linearly scales the memory
	// and CPU usage of the key derivation function. N must be a power
	// of 2 to allow for optimizations inside the algorithm using bit
	// masking.
	//
	// The value has been set to 2^15, which is the biggest power of two
	// that will run the scrypt key derivation function in approximately
	// 100ms on "most commodity workstations". The 100ms is the recommended
	// time cost for interactive use cases that won't bother the user, e.g.
	// typing in CLI commands and providing a passphrase each time which is
	// used to derive a key.
	//
	// Read more about the parameters, how they work and how to determine their values
	// in this blog post: https://blog.filippo.io/the-scrypt-parameters/
	//
	// Also, this the value recommented in the official GoDocs.
	DefaultScryptN = 1 << 15

	// DefaultScryptR determines the sequential read size of the scrypt
	// key derivation function. Together with the N parameter, the r
	// parameter determines the memory block size and number of hashing
	// iterations. However, it is recommended to only change the r parameter
	// if you know what you're doing and if you have custom hardware with
	// different memory characteristics. Use the N parameter instead to
	// increase or decrease work.
	//
	// The value has been set to 8, which is the value recommented in
	// the official GoDocs.
	DefaultScryptR = 8

	// DefaultScryptP determines the number of parallelizable iterations
	// if the scrypt key derivation function. Increasing the value of p
	// can be used to optimize for processing or memory cost, but it cannot
	// be used to decrease the wall-clock-time of the key derivation
	// function. Use the N parameter for that.
	//
	// The value has been set to 1, which is the value recommented in
	// the official GoDocs.
	DefaultScryptP = 1
)

// ScryptKey is a key derived using the scrypt algorithm
// with configured parameters.
type ScryptKey struct {
	key    *AESKey
	KeyLen int
	Salt   Salt
	N      int
	R      int
	P      int
}

// GenerateScryptKey generates a key from a passphras and
// overrides default values when opts is not nil.
func GenerateScryptKey(passphrase []byte) (*ScryptKey, error) {
	keyLen := DefaultScryptKeyLength
	saltLen := DefaultSaltLength
	N := DefaultScryptN
	r := DefaultScryptR
	p := DefaultScryptP

	algo := saltAlgoForKeyLen(keyLen)
	salt, err := generateSalt(saltLen, algo, SaltOperationLocalCredentialEncryption)
	if err != nil {
		return nil, errio.Error(err)
	}

	return DeriveScryptKey(passphrase, salt, N, r, p, keyLen)
}

// DeriveScryptKey derives a key using the scrypt algorithm with the given parameters.
func DeriveScryptKey(passphrase []byte, salt Salt, N, r, p, keyLen int) (*ScryptKey, error) {
	err := ValidatePassphrase(passphrase)
	if err != nil {
		return nil, errio.Error(err)
	}

	key := &ScryptKey{
		KeyLen: keyLen,
		Salt:   salt,
		N:      N,
		R:      r,
		P:      p,
	}

	err = key.Validate()
	if err != nil {
		return nil, errio.Error(err)
	}

	derived, err := scrypt.Key(passphrase, salt, N, r, p, keyLen)
	if err != nil {
		return nil, errio.Error(err)
	}

	key.key = NewAESKey(derived)

	return key, nil
}

// Validate validates the key parameters.
func (k ScryptKey) Validate() error {
	if k.KeyLen != 16 && k.KeyLen != 24 && k.KeyLen != 32 {
		return ErrInvalidKeyLength
	}

	if len(k.Salt) < MinSaltLength+1 {
		return ErrInvalidSalt
	}

	err := k.Salt.Validate()
	if err != nil {
		return errio.Error(err)
	}

	err = k.Salt.Purpose().VerifyAlgo(k.KeyLen, "aesgcm")
	if err != nil {
		return errio.Error(err)
	}

	if k.N < DefaultScryptN || !isPowerOf2(k.N) {
		return ErrInvalidN
	}

	if k.R != DefaultScryptR {
		return ErrInvalidR
	}

	if k.P != DefaultScryptP {
		return ErrInvalidP
	}

	return nil
}

// ValidatePassphrase validates a passphrase.
func ValidatePassphrase(passphrase []byte) error {
	if len(passphrase) == 0 {
		return ErrEmptyPassphrase
	}

	return nil
}

// isPowerOf2 returns true when n is a power of two.
func isPowerOf2(n int) bool {
	return ((n & (n - 1)) == 0) && (n > 0)
}

// Decrypt decrypts the encryptedData with AES-GCM using the AESKey and the provided nonce.
func (k *ScryptKey) Decrypt(encryptedData, nonce []byte, operation SaltOperation) ([]byte, error) {
	err := k.Salt.Purpose().Verify(k.KeyLen, "aesgcm", operation)
	if err != nil {
		return nil, errio.Error(err)
	}

	return k.key.decrypt(encryptedData, nonce)
}

// Encrypt encrypts the data with AES-GCM using the AESKey.
// Returns the encrypted ciphertext.
func (k *ScryptKey) Encrypt(data []byte, operation SaltOperation) (CiphertextAES, error) {
	err := k.Salt.Purpose().Verify(k.KeyLen, "aesgcm", operation)
	if err != nil {
		return CiphertextAES{}, errio.Error(err)
	}

	cipher, err := k.key.Encrypt(data)
	if err != nil {
		return CiphertextAES{}, err
	}

	return cipher, nil
}
