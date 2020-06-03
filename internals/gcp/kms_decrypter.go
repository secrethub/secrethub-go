package gcp

import (
	"context"

	kms "cloud.google.com/go/kms/apiv1"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"

	"github.com/secrethub/secrethub-go/internals/api"
)

// KMSDecrypter is an implementation of the secrethub.Decrypter interface that uses GCP KMS for decryption.
type KMSDecrypter struct {
	decryptFunc func(name string, ciphertext []byte) (*kmspb.DecryptResponse, error)
}

// NewKMSDecrypter returns a new KMSDecrypter that uses the provided configuration to configure the GCP session.
func NewKMSDecrypter(options ...option.ClientOption) (*KMSDecrypter, error) {
	kmsClient, err := kms.NewKeyManagementClient(context.Background(), options...)
	if err != nil {
		return nil, HandleError(err)
	}
	return &KMSDecrypter{
		decryptFunc: func(name string, ciphertext []byte) (*kmspb.DecryptResponse, error) {
			return kmsClient.Decrypt(context.Background(), &kmspb.DecryptRequest{
				Name:       name,
				Ciphertext: ciphertext,
			})
		},
	}, nil
}

// Unwrap the provided ciphertext using GCP KMS.
func (d KMSDecrypter) Unwrap(ciphertext *api.EncryptedData) ([]byte, error) {
	key, ok := ciphertext.Key.(*api.EncryptionKeyGCP)
	if !ok {
		return nil, api.ErrInvalidKeyType
	}
	resp, err := d.decryptFunc(key.ID, ciphertext.Ciphertext)
	if err != nil {
		return nil, HandleError(err)
	}
	return resp.Plaintext, nil
}
