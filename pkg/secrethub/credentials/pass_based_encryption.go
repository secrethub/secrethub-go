package credentials

import (
	"encoding/json"

	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
)

// PassBasedKey can encrypt a Credential into token values.
type PassBasedKey interface {
	// Name returns the name of the key derivation algorithm.
	Name() string
	// Encrypt encrypts a given payload with the passphrase derived key and returns encrypted bytes and header with encryption parameter values.
	Encrypt(payload []byte) ([]byte, map[string]interface{}, error)
	// Decrypt decrypts a payload with the key and accepts the raw JSON header to read values from.
	Decrypt(payload []byte, header []byte) ([]byte, error)
}

// passbasedKeyHeader is a helper type to help encoding
// and decoding header values for the Scrypt encryption.
type passbasedKeyHeader struct {
	KeyLen int    `json:"klen"`
	Salt   []byte `json:"salt"`
	N      int    `json:"n"`
	R      int    `json:"r"`
	P      int    `json:"p"`
	Nonce  []byte `json:"nonce"`
}

// passBasedKey wraps an scrypt derived key and implements
// the PassBasedKey interface.
type passBasedKey struct {
	key        *crypto.ScryptKey
	passphrase []byte
}

// NewPassBasedKey generates a new key from a passphrase.
func NewPassBasedKey(passphrase []byte) (PassBasedKey, error) {
	key, err := crypto.GenerateScryptKey(passphrase)
	if err != nil {
		return nil, errio.Error(err)
	}

	return passBasedKey{
		key:        key,
		passphrase: passphrase,
	}, nil
}

// Encrypt implements the PassBasedKey interface and encrypts a payload,
// returning the encrypted payload and header values.
func (p passBasedKey) Encrypt(payload []byte) ([]byte, map[string]interface{}, error) {
	ciphertext, err := p.key.Encrypt(payload, crypto.SaltOperationLocalCredentialEncryption)
	if err != nil {
		return nil, nil, errio.Error(err)
	}

	header := passbasedKeyHeader{
		KeyLen: p.key.KeyLen,
		Salt:   p.key.Salt,
		N:      p.key.N,
		R:      p.key.R,
		P:      p.key.P,
		Nonce:  ciphertext.Nonce,
	}
	raw, err := json.Marshal(header)
	if err != nil {
		return nil, nil, errio.Error(err)
	}

	headerMap := make(map[string]interface{})
	err = json.Unmarshal(raw, &headerMap)
	if err != nil {
		return nil, nil, errio.Error(err)
	}

	return ciphertext.Data, headerMap, nil
}

// Name implements the PassBasedKey interface.
func (p passBasedKey) Name() string {
	return "scrypt"
}

// Decrypt decrypts an encrypted payload and reads values from the header when necessary.
func (p passBasedKey) Decrypt(payload []byte, rawHeader []byte) ([]byte, error) {
	header := passbasedKeyHeader{}
	err := json.Unmarshal(rawHeader, &header)
	if err != nil {
		return nil, errio.Error(err)
	}

	key, err := crypto.DeriveScryptKey(p.passphrase, header.Salt, header.N, header.R, header.P, header.KeyLen)
	if err != nil {
		return nil, errio.Error(err)
	}

	return key.Decrypt(
		crypto.CiphertextAES{
			Data:  payload,
			Nonce: header.Nonce,
		},
		crypto.SaltOperationLocalCredentialEncryption,
	)
}
