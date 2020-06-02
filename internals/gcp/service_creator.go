package gcp

import (
	"context"
	"fmt"

	"github.com/secrethub/secrethub-go/internals/api"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
)

// CredentialCreator is an implementation of the secrethub.Verifier and secrethub.Encrypter interface that can be used
// to create an AWS service account.
type CredentialCreator struct {
	keyResourceID       string
	serviceAccountEmail string

	encryptFunc func(name string, plaintext string) (*cloudkms.EncryptResponse, error)
}

// NewCredentialCreator returns a CredentialCreator that uses the provided AWS KMS key and IAM role to create a new credential.
// The AWS credential is configured with the optionally provided aws.Config.
func NewCredentialCreator(serviceAccountEmail, keyResourceID string, gcpOptions ...option.ClientOption) (*CredentialCreator, map[string]string, error) {
	kmsClient, err := cloudkms.NewService(context.Background(), gcpOptions...)
	if err != nil {
		return nil, nil, fmt.Errorf("creating kms client: %v", HandleError(err))
	}

	return &CredentialCreator{
			keyResourceID:       keyResourceID,
			serviceAccountEmail: serviceAccountEmail,
			encryptFunc: func(name, plaintext string) (*cloudkms.EncryptResponse, error) {
				return kmsClient.Projects.Locations.KeyRings.CryptoKeys.Encrypt(name, &cloudkms.EncryptRequest{
					Plaintext: plaintext,
				}).Do()
			},
		}, map[string]string{
			api.CredentialMetadataGCPKMSKeyResourceID:    keyResourceID,
			api.CredentialMetadataGCPServiceAccountEmail: serviceAccountEmail,
		}, nil
}

func (c CredentialCreator) Wrap(plaintext []byte) (*api.EncryptedData, error) {
	resp, err := c.encryptFunc(c.keyResourceID, string(plaintext))
	if err != nil {
		return nil, HandleError(err)
	}
	return api.NewEncryptedDatGCPKMS([]byte(resp.Ciphertext), api.NewEncryptionKeyGCP(c.keyResourceID)), nil
}

func (c CredentialCreator) Export() ([]byte, string, error) {
	verifierBytes := []byte(c.serviceAccountEmail)
	return verifierBytes, api.GetFingerprint(api.CredentialTypeGCPServiceAccount, verifierBytes), nil
}

func (c CredentialCreator) Type() api.CredentialType {
	return api.CredentialTypeGCPServiceAccount
}

func (c CredentialCreator) AddProof(req *api.CreateCredentialRequest) error {
	req.Proof = &api.CredentialProofGCPServiceAccount{}
	return nil
}
