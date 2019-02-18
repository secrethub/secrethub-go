package crypto

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
