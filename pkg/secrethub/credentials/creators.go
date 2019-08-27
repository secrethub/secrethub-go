package credentials

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/aws"
	"github.com/secrethub/secrethub-go/internals/crypto"

	awssdk "github.com/aws/aws-sdk-go/aws"
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

// CreateAWS returns a Creator that creates an AWS-based credential.
// The kmsKeyID is the ID of the key in KMS that is used to encrypt the account key.
// The roleARN is for the IAM role that should be assumed to use this credential.
// The role should have decryption permission on the provided KMS key.
// awsCfg can be used to optionally configure the used AWS client. For example to set the region.
// The KMS key id and role are returned in the credentials metadata.
func CreateAWS(kmsKeyID string, roleARN string, awsCfg ...*awssdk.Config) Creator {
	return &awsCreator{
		kmsKeyID: kmsKeyID,
		roleARN:  roleARN,
		awsCfg:   awsCfg,
	}
}

type awsCreator struct {
	kmsKeyID string
	roleARN  string
	awsCfg   []*awssdk.Config

	credentialCreator *aws.CredentialCreator
}

func (ac *awsCreator) Create() error {
	creator, err := aws.NewCredentialCreator(ac.kmsKeyID, ac.roleARN, ac.awsCfg...)
	if err != nil {
		return err
	}
	ac.credentialCreator = creator
	return nil
}

func (ac *awsCreator) Verifier() Verifier {
	return ac.credentialCreator
}

func (ac *awsCreator) Encrypter() Encrypter {
	return ac.credentialCreator
}

func (ac *awsCreator) Metadata() map[string]string {
	return map[string]string{
		api.CredentialMetadataAWSKMSKey: ac.kmsKeyID,
		api.CredentialMetadataAWSRole:   ac.roleARN,
	}
}
