package credentials

import (
	"errors"

	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

type Key struct {
	key              *RSACredential
	exportPassphrase Reader
}

func (k Key) Verifier() Verifier {
	return k.key
}

func (k Key) Encrypter() Encrypter {
	return k.key
}

func (k Key) Provide(httpClient *http.Client) (auth.Authenticator, Decrypter, error) {
	return k.key, k.key, nil
}

func (k Key) Passphrase(passphraseReader Reader) Key {
	k.exportPassphrase = passphraseReader
	return k
}

// Export the key of this credential to string format to save for later use.
// This can only be called after Create() is executed, for example by secrethub.UserService.Create([...])
// or secrethub.ServiceService.Create([...])
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
		if passphraseReader == nil {
			return Key{}, errors.New("need passphrase")
		}

		// Try up to three times to get the correct passphrase.
		for i := 0; i < 3; i++ {
			passphrase, err := passphraseReader.Read()
			if err != nil {
				return Key{}, err
			}
			if len(passphrase) == 0 {
				return Key{}, errors.New("no passphrase given")
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
