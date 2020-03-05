package aws

import (
	"errors"
	"testing"

	"github.com/secrethub/secrethub-go/internals/api"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"

	"github.com/secrethub/secrethub-go/internals/assert"
)

var errTest = errors.New("test-error")

type kmsEncryptMock struct {
	kmsiface.KMSAPI
	resp *kms.EncryptOutput
	err  error

	plaintext []byte
}

func (m *kmsEncryptMock) Encrypt(in *kms.EncryptInput) (*kms.EncryptOutput, error) {
	m.plaintext = in.Plaintext
	return m.resp, m.err
}

func TestServiceCreator_AddProof(t *testing.T) {
	defaultRequest := []byte("request")
	defaultRegion := "eu-west-1"

	cases := map[string]struct {
		encryptRequest       []byte
		getEncryptRequestErr error
		signingRegion        string

		expectedErr error
		expected    *api.CredentialProofAWS
	}{
		"success": {
			encryptRequest: defaultRequest,
			signingRegion:  defaultRegion,

			expected: &api.CredentialProofAWS{
				Region:  defaultRegion,
				Request: defaultRequest,
			},
		},
		"getEncryptRequest error": {
			encryptRequest:       defaultRequest,
			signingRegion:        defaultRegion,
			getEncryptRequestErr: errTest,
			expectedErr:          errTest,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {

			var usedPlaintext string

			sc := CredentialCreator{
				kmsSvc: &kmsEncryptMock{},
				getEncryptRequest: func(plaintext string, keyID string, kms kmsiface.KMSAPI) ([]byte, error) {
					usedPlaintext = plaintext
					return tc.encryptRequest, tc.getEncryptRequestErr
				},
				signingRegion: tc.signingRegion,
				role:          "roleName",
			}

			req := api.CreateCredentialRequest{}

			err := sc.AddProof(&req)
			assert.Equal(t, err, tc.expectedErr)

			if tc.expectedErr == nil {
				assert.Equal(t, usedPlaintext, api.CredentialProofPrefixAWS+sc.role)

				proof, ok := req.Proof.(*api.CredentialProofAWS)
				assert.Equal(t, ok, true)
				assert.Equal(t, proof, tc.expected)
			}
		})
	}
}

func TestServiceCreator_Wrap(t *testing.T) {
	kmsKeyID := "123456"
	ciphertext := []byte("ciphertext")

	cases := map[string]struct {
		encryptResponse *kms.EncryptOutput
		encryptErr      error

		expectedErr error
		expected    *api.EncryptedData
	}{
		"success": {
			encryptResponse: &kms.EncryptOutput{
				CiphertextBlob: ciphertext,
				KeyId:          &kmsKeyID,
			},
			expected: api.NewEncryptedDataAWSKMS(ciphertext, api.NewEncryptionKeyAWS(kmsKeyID)),
		},
		"encrypt error": {
			encryptErr:  errTest,
			expectedErr: errTest,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			plaintext := []byte("plaintext")

			kmsMock := kmsEncryptMock{
				resp: tc.encryptResponse,
				err:  tc.encryptErr,
			}

			sc := CredentialCreator{
				kmsSvc: &kmsMock,
			}

			res, err := sc.Wrap(plaintext)
			assert.Equal(t, err, tc.expectedErr)

			if tc.expectedErr == nil {
				assert.Equal(t, kmsMock.plaintext, plaintext)
				assert.Equal(t, res, tc.expected)
			}

		})
	}
}

func Test_parseRole(t *testing.T) {
	defaultAccountID := "1234567890"
	defaultARN := "arn:aws:iam::" + defaultAccountID + ":role/RoleName"

	cases := map[string]struct {
		role      string
		accountID string
		expected  string
	}{
		"role name only": {
			role:      "RoleName",
			accountID: "1234567890",
			expected:  defaultARN,
		},
		"with role prefix": {
			role:      "role/RoleName",
			accountID: "1234567890",
			expected:  defaultARN,
		},
		"complete ARN": {
			role:      defaultARN,
			accountID: "1234567890",
			expected:  defaultARN,
		},
		"complete ARN different account": {
			role:      defaultARN,
			accountID: "0987654321",
			expected:  defaultARN,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := parseRole(tc.role, tc.accountID)
			assert.Equal(t, actual, tc.expected)
		})
	}
}

func Test_parseKey(t *testing.T) {
	cases := map[string]struct {
		key       string
		accountID string
		region    string
		expected  string
	}{
		"key id only": {
			key:       "12345678-1234-1234-1234-123456789012",
			accountID: "123456789012",
			region:    "us-east-1",
			expected:  "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		},
		"with key prefix": {
			key:       "key/12345678-1234-1234-1234-123456789012",
			accountID: "123456789012",
			region:    "us-east-1",
			expected:  "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		},
		"complete ARN": {
			key:       "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
			accountID: "123456789012",
			region:    "us-east-1",
			expected:  "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		},
		"complete ARN different account": {
			key:       "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
			accountID: "0987654321",
			region:    "us-east-1",
			expected:  "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		},
		"complete ARN different region": {
			key:       "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
			accountID: "123456789012",
			region:    "eu-west-1",
			expected:  "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		},
		"complete alias ARN": {
			key:       "arn:aws:kms:us-east-1:123456789012:alias/my-key",
			accountID: "123456789012",
			region:    "us-east-1",
			expected:  "arn:aws:kms:us-east-1:123456789012:alias/my-key",
		},
		"alias": {
			key:       "alias/my-key",
			accountID: "123456789012",
			region:    "us-east-1",
			expected:  "arn:aws:kms:us-east-1:123456789012:alias/my-key",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual := parseKey(tc.key, tc.accountID, tc.region)
			assert.Equal(t, actual, tc.expected)
		})
	}
}
