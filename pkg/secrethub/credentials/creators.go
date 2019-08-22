package credentials

import (
	awssdk "github.com/aws/aws-sdk-go/aws"

	"github.com/secrethub/secrethub-go/internals/aws"
)

type Creator interface {
	Create() (Verifier, Encrypter, error)
}

type KeyCreator struct {
	key *RSACredential
}

func CreateKey() *KeyCreator {
	return &KeyCreator{}
}

func (c *KeyCreator) Create() (Verifier, Encrypter, error) {
	key, err := GenerateCredential()
	if err != nil {
		return nil, nil, err
	}
	c.key = key
	return c.key, c.key, nil
}

func (c *KeyCreator) Export() []byte {
	if c.key == nil {
		return nil
	}
	return c.key.Export()
}

func CreateAWS(kmsKeyID string, roleARN string, awsCfg ...*awssdk.Config) Creator {
	return creatorFunc(func() (Verifier, Encrypter, error) {
		creator, err := aws.NewCredentialCreator(kmsKeyID, roleARN, awsCfg...)
		if err != nil {
			return nil, nil, err
		}
		return creator, creator, nil
	})
}

type creatorFunc func() (Verifier, Encrypter, error)

func (f creatorFunc) Create() (Verifier, Encrypter, error) {
	return f()
}
