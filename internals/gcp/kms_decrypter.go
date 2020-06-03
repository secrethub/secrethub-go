package gcp

import (
	"context"

	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"

	"github.com/secrethub/secrethub-go/internals/api"
)

// KMSDecrypter is an implementation of the secrethub.Decrypter interface that uses GCP KMS for decryption.
type KMSDecrypter struct {
	decryptFunc func(name string, ciphertext string) (*cloudkms.DecryptResponse, error)
}

// NewKMSDecrypter returns a new KMSDecrypter that uses the provided configuration to configure the GCP session.
func NewKMSDecrypter(options ...option.ClientOption) (*KMSDecrypter, error) {
	kmsClient, err := cloudkms.NewService(context.Background(), options...)
	if err != nil {
		return nil, HandleError(err)
	}
	return &KMSDecrypter{
		decryptFunc: func(name, ciphertext string) (*cloudkms.DecryptResponse, error) {
			return kmsClient.Projects.Locations.KeyRings.CryptoKeys.Decrypt(name, &cloudkms.DecryptRequest{
				Ciphertext: ciphertext,
			}).Do()
		},
	}, nil
}

// Unwrap the provided ciphertext using GCP KMS.
func (d KMSDecrypter) Unwrap(ciphertext *api.EncryptedData) ([]byte, error) {
	key, ok := ciphertext.Key.(*api.EncryptionKeyGCP)
	if !ok {
		return nil, api.ErrInvalidKeyType
	}
	resp, err := d.decryptFunc(key.ID, string(ciphertext.Ciphertext))
	if err != nil {
		return nil, HandleError(err)
	}
	return []byte(resp.Plaintext), nil
}
