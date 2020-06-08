package gcp

import (
	"testing"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"

	"github.com/secrethub/secrethub-go/internals/api"

	"github.com/secrethub/secrethub-go/internals/assert"
)

func TestServiceCreator_Wrap(t *testing.T) {
	kmsKeyID := "123456"
	ciphertext := []byte("ciphertext")

	cases := map[string]struct {
		encryptErr error

		expectedErr error
		expected    *api.EncryptedData
	}{
		"success": {
			expected: api.NewEncryptedDataGCPKMS(ciphertext, api.NewEncryptionKeyGCP(kmsKeyID)),
		},
		"encrypt error": {
			encryptErr:  errTest,
			expectedErr: errTest,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			plaintext := []byte("plaintext")

			sc := CredentialCreator{
				encryptFunc: func(name string, pt []byte) (*kmspb.EncryptResponse, error) {
					assert.Equal(t, name, kmsKeyID)
					assert.Equal(t, pt, plaintext)
					return &kmspb.EncryptResponse{
						Ciphertext: ciphertext,
					}, tc.encryptErr
				},
			}
			sc.keyResourceID = kmsKeyID

			res, err := sc.Wrap(plaintext)
			assert.Equal(t, err, tc.expectedErr)

			if tc.expectedErr == nil {
				assert.Equal(t, res, tc.expected)
			}

		})
	}
}
