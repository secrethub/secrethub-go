package aws

import (
	"testing"

	"github.com/secrethub/secrethub-go/internals/assert"

	"github.com/secrethub/secrethub-go/internals/api"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

type kmsDecryptMock struct {
	kmsiface.KMSAPI
	resp *kms.DecryptOutput
	err  error

	ciphertext []byte
}

func (m *kmsDecryptMock) Decrypt(in *kms.DecryptInput) (*kms.DecryptOutput, error) {
	m.ciphertext = in.CiphertextBlob
	return m.resp, m.err
}

func TestKMSDecrypter_Unwrap(t *testing.T) {
	defaultCiphertext := []byte("ciphertext")
	defaultRegion := "eu-west-1"
	defaultKMSKey := "arn:aws:kms:" + defaultRegion + ":111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	defaultPlaintext := []byte("plaintext")

	cases := map[string]struct {
		input           *api.EncryptedData
		decryptResponse *kms.DecryptOutput
		decryptErr      error
		expectedRegion  string
		expected        []byte
		expectedErr     error
	}{
		"success": {
			input: api.NewEncryptedDataAWSKMS(defaultCiphertext, api.NewEncryptionKeyAWS(defaultKMSKey)),
			decryptResponse: &kms.DecryptOutput{
				KeyId:     &defaultKMSKey,
				Plaintext: defaultPlaintext,
			},
			expectedRegion: defaultRegion,
			expected:       defaultPlaintext,
		},
		"invalid EncryptedData": {
			input:       api.NewEncryptedDataAESGCM(defaultCiphertext, []byte("nonce"), 10, api.NewEncryptionKeyLocal(256)),
			expectedErr: api.ErrInvalidKeyType,
		},
		"invalid keyID": {
			input:       api.NewEncryptedDataAWSKMS(defaultCiphertext, api.NewEncryptionKeyAWS("not-an-arn")),
			expectedErr: api.ErrInvalidCiphertext,
		},
		"decryption error": {
			input:       api.NewEncryptedDataAWSKMS(defaultCiphertext, api.NewEncryptionKeyAWS(defaultKMSKey)),
			decryptErr:  defaultTestErr,
			expectedErr: defaultTestErr,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var usedRegion string

			decrypter := KMSDecrypter{
				kmsSvcGetter: func(region string) kmsiface.KMSAPI {
					usedRegion = region
					return &kmsDecryptMock{
						resp: tc.decryptResponse,
						err:  tc.decryptErr,
					}
				},
			}

			res, err := decrypter.Unwrap(tc.input)
			assert.Equal(t, err, tc.expectedErr)
			if tc.expectedErr == nil {
				assert.Equal(t, res, tc.expected)
				assert.Equal(t, usedRegion, tc.expectedRegion)
			}
		})
	}
}
