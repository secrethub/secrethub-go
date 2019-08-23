package credentials

import (
	"errors"

	awssdk "github.com/aws/aws-sdk-go/aws"

	"github.com/secrethub/secrethub-go/internals/aws"
	"github.com/secrethub/secrethub-go/internals/crypto"
)

// Creator is an interface is accepted by functions that need a new credential to be created.
type Creator interface {
	Create() (Verifier, Encrypter, error)
}

// KeyCreator is used to create a new key-based credential.
type KeyCreator struct {
	key *RSACredential
}

// CreateKey returns a Creator that creates a key based credential.
// After use, the key can be accessed with the Export() method.
// The user of CreateKey() is responsible for saving the exported key.
// If this is not done, the credential will be unusable.
func CreateKey() *KeyCreator {
	return &KeyCreator{}
}

// Create generates a new key and stores it in the KeyCreator.
func (c *KeyCreator) Create() (Verifier, Encrypter, error) {
	key, err := GenerateRSACredential(crypto.RSAKeyLength)
	if err != nil {
		return nil, nil, err
	}
	c.key = key
	return c.key, c.key, nil
}

// Export the key of this credential to string format to save for later use.
// This can only be called after Create() is executed, for example by secrethub.UserService.Create([...])
// or secrethub.ServiceService.Create([...])
func (c *KeyCreator) Export() (string, error) {
	if c.key == nil {
		return "", errors.New("key has not yet been generated created. Use KeyCreator before calling Export()")
	}
	return EncodeCredential(c.key)
}

// CreateAWS returns a Creator that creates an AWS-based credential.
// The kmsKeyID is the ID of the key in KMS that is used to encrypt the account key.SS
// The roleARN is for the IAM role that should be assumed to use this credential.
// The role should have decryption permission on the provided KMS key.
// awsCfg can be used to optionally configure the used AWS client. For example to set the region.
func CreateAWS(kmsKeyID string, roleARN string, awsCfg ...*awssdk.Config) Creator {
	return creatorFunc(func() (Verifier, Encrypter, error) {
		creator, err := aws.NewCredentialCreator(kmsKeyID, roleARN, awsCfg...)
		if err != nil {
			return nil, nil, err
		}
		return creator, creator, nil
	})
}

// creatorFunc is a helper type that can transform any func() (CreatedCredential, error) into a Creator.
type creatorFunc func() (Verifier, Encrypter, error)

// Create is implemented to let creatorFunc implement the Creator interface.
func (f creatorFunc) Create() (Verifier, Encrypter, error) {
	return f()
}