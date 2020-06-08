package credentials

import (
	"github.com/secrethub/secrethub-go/internals/crypto"
)

// Creator is an interface is accepted by functions that need a new credential to be created.
type Creator interface {
	// Create creates the actual credential (e.g. by generating a key).
	Create() error
	// Verifier returns information that the server can use to verify a request authenticated with the credential.
	Verifier() Verifier
	// Encrypter returns a wrapper that is used to encrypt data, typically an account key.
	Encrypter() Encrypter
	// Metadata returns a set of metadata about the credential. The result can be empty if no metadata is provided.
	Metadata() map[string]string
}

// CreateKey returns a Creator that creates a key based credential.
// After use, the key can be accessed with the Export() method.
// The user of CreateKey() is responsible for saving the exported key.
// If this is not done, the credential will be unusable.
func CreateKey() *KeyCreator {
	return &KeyCreator{}
}

// KeyCreator is used to create a new key-based credential.
type KeyCreator struct {
	Key
}

// Create generates a new key and stores it in the KeyCreator.
func (kc *KeyCreator) Create() error {
	key, err := GenerateRSACredential(crypto.RSAKeyLength)
	if err != nil {
		return err
	}
	kc.key = key
	return nil
}

// Metadata returns a set of metadata associated with this credential.
func (kc *KeyCreator) Metadata() map[string]string {
	return map[string]string{}
}
