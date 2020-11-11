package credentials

import (
	"errors"
	"fmt"
	"os"

	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

type ErrLoadingCredential struct {
	Location string
	Err      error
}

func (e ErrLoadingCredential) Error() string {
	return fmt.Sprintf("error loading credential loaded from '%s': %v", e.Location, e.Err)
}

// Key is a credential that uses a local key for all its operations.
type Key struct {
	key              *RSACredential
	exportPassphrase Reader
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
func (k Key) Passphrase(passphraseReader Reader) Key {
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

// ImportKey returns a Key by loading it from the provided credentialReader.
// If the key is encrypted with a passphrase, passphraseReader should be provided. This is used to read a passphrase
// from that is used for decryption. If the passphrase is incorrect, a new passphrase will be read up to 3 times.
func ImportKey(credentialReader, passphraseReader Reader) (Key, error) {
	bytes, err := credentialReader.Read()
	if err != nil {
		return Key{}, err
	}
	encoded, err := defaultParser.parse(bytes)
	if err != nil {
		return Key{}, err
	}
	if encoded.IsEncrypted() {
		envPassphrase := os.Getenv("SECRETHUB_CREDENTIAL_PASSPHRASE")
		if passphraseReader == nil && envPassphrase == "" {
			return Key{}, ErrNeedPassphrase
		}
		if passphraseReader == nil {
			credential, err := decryptKey([]byte(envPassphrase), encoded)
			if err != nil {
				return Key{}, err
			}
			return Key{key: credential}, nil
		}

		// Try up to three times to get the correct passphrase.
		for i := 0; i < 3; i++ {
			passphrase, err := passphraseReader.Read()
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
