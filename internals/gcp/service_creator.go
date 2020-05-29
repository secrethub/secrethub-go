package gcp

import (
	"context"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/secrethub/secrethub-go/internals/api"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// CredentialCreator is an implementation of the secrethub.Verifier and secrethub.Encrypter interface that can be used
// to create an AWS service account.
type CredentialCreator struct {
	keyResourceID       string
	serviceAccountEmail string

	kmsClient *kms.KeyManagementClient
}

// NewCredentialCreator returns a CredentialCreator that uses the provided AWS KMS key and IAM role to create a new credential.
// The AWS credential is configured with the optionally provided aws.Config.
func NewCredentialCreator(serviceAccountEmail, keyResourceID string, gcpOptions ...option.ClientOption) (*CredentialCreator, map[string]string, error) {
	kmsClient, err := kms.NewKeyManagementClient(context.Background(), gcpOptions...)
	if err != nil {
		return nil, nil, fmt.Errorf("creating kms client: %v", gcp.HandleError(err))
	}

	return &CredentialCreator{
			keyResourceID:       keyResourceID,
			serviceAccountEmail: serviceAccountEmail,
			kmsClient:           kmsClient,
		}, map[string]string{
			api.CredentialMetadataGCPKMSKeyResourceID:    keyResourceID,
			api.CredentialMetadataGCPServiceAccountEmail: serviceAccountEmail,
		}, nil
}

func (c CredentialCreator) Wrap(plaintext []byte) (*api.EncryptedData, error) {
	resp, err := c.kmsClient.Encrypt(context.Background(), &kmspb.EncryptRequest{
		Name:      c.keyResourceID,
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, HandleError(err)
	}
	return api.NewEncryptedDatGCPKMS(resp.Ciphertext, api.NewEncryptionKeyGCP(c.keyResourceID)), nil
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
