package credentials

import (
	"errors"

	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

// Key is a credential that uses a local key for all its operations.
type Key struct {
	key              *RSACredential
	exportPassphrase PassphraseReader
}

// Verifier returns a Verifier that can be used for creating a new credential from this Key.
func (k Key) Verifier() Verifier {
	return k.key
}

// Encrypter returns a Encrypter that can be used to encrypt data with this Key.
func (k Key) Encrypter() Encrypter {
	return k.key
}

// Provide implements the Provider interface for a Key.
func (k Key) Provide(httpClient *http.Client) (auth.Authenticator, Decrypter, error) {
	return k.key, k.key, nil
}

// Passphrase returns a new Key that uses the provided passphraseReader to obtain a passphrase that is used for
// encryption when Export() is called.
func (k Key) Passphrase(passphraseReader PassphraseReader) Key {
	k.exportPassphrase = passphraseReader
	return k
}

// Export the key of this credential to string format to save for later use.
// If a passphrase was set with Passphrase(), this passphrase is used for encrypting the key.
func (k Key) Export() ([]byte, error) {
	if k.key == nil {
		return nil, errors.New("key has not yet been generated created. Use KeyCreator before calling Export()")
	}
	if k.exportPassphrase != nil {
		passphrase, err := k.exportPassphrase.Read()
		if err != nil {
			return nil, err
		}
		passBasedKey, err := NewPassBasedKey(passphrase)
		if err != nil {
			return nil, err
		}
		return EncodeEncryptedCredential(k.key, passBasedKey)
	}
	return EncodeCredential(k.key)
}

type KeyDecoder interface {
	Decode([]byte) (Key, error)
}

func DefaultKeyDecoder() KeyDecoder {
	return credentialDecoder{}
}

func KeyDecoderWithPassphrase(passphraseReader PassphraseReader) KeyDecoder {
	return credentialDecoder{
		passphraseReader: passphraseReader,
	}
}

type credentialDecoder struct {
	passphraseReader PassphraseReader
}

func (d credentialDecoder) Decode(bytes []byte) (Key, error) {
	encoded, err := defaultParser.parse(bytes)
	if err != nil {
		return Key{}, err
	}
	if encoded.IsEncrypted() {
		if d.passphraseReader == nil {
			return Key{}, ErrNeedPassphrase
		}

		// Try up to three times to get the correct passphrase.
		for i := 0; i < 3; i++ {
			passphrase, err := d.passphraseReader.Read()
			if err != nil {
				return Key{}, err
			}
			if len(passphrase) == 0 {
				continue
			}

			credential, err := decryptKey(passphrase, encoded)
			if crypto.IsWrongKey(err) {
				continue
			} else if err != nil {
				return Key{}, err
			}

			return Key{key: credential}, nil
		}

		return Key{}, ErrCannotDecryptCredential
	}
	credential, err := encoded.Decode()
	if err != nil {
		return Key{}, err
	}

	return Key{key: credential}, nil
}

func decryptKey(passphrase []byte, encoded *encodedCredential) (*RSACredential, error) {
	key, err := NewPassBasedKey(passphrase)
	if err != nil {
		return nil, err
	}
	return encoded.DecodeEncrypted(key)
}
