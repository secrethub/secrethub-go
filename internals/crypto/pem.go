package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
)

// Errors
var (
	ErrCannotDecryptKey       = errCrypto.Code("decrypt_error").ErrorPref("cannot decrypt key: %s")
	ErrIncorrectPassphrase    = errCrypto.Code("incorrect_passphrase").Error("cannot decrypt key: passphrase is incorrect")
	ErrNoPassphraseProvided   = errCrypto.Code("no_passphrase_provided").Error("cannot decode key: no passphrase provided")
	ErrDecryptionUnarmoredKey = errCrypto.Code("decryption_unarmored_key").Error("cannot decode key: trying to decrypt unarmored key")
)

// PEMKey contains a PEM encoded key and provides decode functions to RSAPrivateKey.
// Note that PEM encoded keys will be deprecated, so only decoding functions
// remain in the code base. To encode keys, check out RSAPrivateKey.Export instead.
type PEMKey struct {
	block *pem.Block
}

// ReadPEM reads a single PEM key from a []byte.
func ReadPEM(key []byte) (*PEMKey, error) {
	pemBlock, rest := pem.Decode(key)
	if pemBlock == nil {
		return nil, ErrNoKeyInFile

	} else if len(rest) > 0 {
		return nil, ErrMultipleKeysInFile
	}

	return &PEMKey{
		block: pemBlock,
	}, nil
}

// IsEncrypted checks if the key is encrypted or not.
// This can be useful for determining whether to Decrypt
// or Decode the key.
func (k PEMKey) IsEncrypted() bool {
	procType := k.block.Headers["Proc-Type"]
	if procType == "" {
		return false
	}
	// First element is PEM RFC version.
	procTypeSplit := strings.Split(procType, ",")[1:]

	for _, value := range procTypeSplit {
		if value == "ENCRYPTED" {
			return true
		}
	}
	return false
}

// Decrypt decrypts the key using the password and decodes the PEM key to an RSA Key.
// If the key is not encrypted it returns ErrDecryptionUnarmoredKey and Decode should
// have been called instead. Use IsEncrypted to determine whether to Decrypt or only
// Decode the key.
func (k *PEMKey) Decrypt(password []byte) (RSAPrivateKey, error) {
	if !k.IsEncrypted() {
		return RSAPrivateKey{}, ErrDecryptionUnarmoredKey
	}

	bytes, err := x509.DecryptPEMBlock(k.block, password)
	if err == x509.IncorrectPasswordError {
		return RSAPrivateKey{}, ErrIncorrectPassphrase
	} else if err != nil {
		return RSAPrivateKey{}, ErrCannotDecryptKey(err)
	}

	key, err := x509.ParsePKCS1PrivateKey(bytes)
	if err != nil {
		return RSAPrivateKey{}, ErrNotPKCS1Format
	}

	return NewRSAPrivateKey(key), nil
}

// Decode decodes the pem key to an RSA Key. If the key is encrypted it returns
// ErrNoPassphraseProvided and Decrypt should have been called. Use IsEncrypted
// to determine whether to Decrypt or only Decode the key.
func (k PEMKey) Decode() (RSAPrivateKey, error) {
	if k.IsEncrypted() {
		return RSAPrivateKey{}, ErrNoPassphraseProvided
	}

	key, err := x509.ParsePKCS1PrivateKey(k.block.Bytes)
	if err != nil {
		return RSAPrivateKey{}, ErrNotPKCS1Format
	}

	return NewRSAPrivateKey(key), nil
}
