package gcp

import (
	"context"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"

	"github.com/secrethub/secrethub-go/internals/api"
)

// CredentialCreator is an implementation of the secrethub.Verifier and secrethub.Encrypter interface that can be used
// to create an GCP service account.
type CredentialCreator struct {
	keyResourceID       string
	serviceAccountEmail string

	encryptFunc func(name string, plaintext []byte) (*kmspb.EncryptResponse, error)
}

// NewCredentialCreator returns a CredentialCreator that uses the provided GCP KMS key and Service Account Email to create a new credential.
// The GCP client is configured with the optionally provided option.ClientOption.
func NewCredentialCreator(serviceAccountEmail, keyResourceID string, gcpOptions ...option.ClientOption) (*CredentialCreator, map[string]string, error) {
	kmsClient, err := kms.NewKeyManagementClient(context.Background(), gcpOptions...)
	if err != nil {
		return nil, nil, fmt.Errorf("creating kms client: %v", HandleError(err))
	}

	return &CredentialCreator{
			keyResourceID:       keyResourceID,
			serviceAccountEmail: serviceAccountEmail,
			encryptFunc: func(name string, plaintext []byte) (*kmspb.EncryptResponse, error) {
				return kmsClient.Encrypt(context.Background(), &kmspb.EncryptRequest{
					Name:      name,
					Plaintext: plaintext,
				})
			},
		}, map[string]string{
			api.CredentialMetadataGCPKMSKeyResourceID:    keyResourceID,
			api.CredentialMetadataGCPServiceAccountEmail: serviceAccountEmail,
		}, nil
}

func (c CredentialCreator) Wrap(plaintext []byte) (*api.EncryptedData, error) {
	resp, err := c.encryptFunc(c.keyResourceID, plaintext)
	if err != nil {
		return nil, HandleError(err)
	}
	return api.NewEncryptedDataGCPKMS(resp.Ciphertext, api.NewEncryptionKeyGCP(c.keyResourceID)), nil
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
