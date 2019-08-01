package aws

import (
	"errors"
	"fmt"
	"testing"

	"github.com/secrethub/secrethub-go/internals/api"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"

	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/aws/aws-sdk-go/service/sts/stsiface"

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
		expected    *api.CredentialProofAWSSTS
	}{
		"success": {
			encryptRequest: defaultRequest,
			signingRegion:  defaultRegion,

			expected: &api.CredentialProofAWSSTS{
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

			sc := ServiceCreator{
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

				proof, ok := req.Proof.(*api.CredentialProofAWSSTS)
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

			sc := ServiceCreator{
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

type stsMock struct {
	stsiface.STSAPI
	resp *sts.GetCallerIdentityOutput
	err  error
}

func (m stsMock) GetCallerIdentity(*sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
	return m.resp, m.err
}

func Test_parseRole(t *testing.T) {
	defaultAccountID := "1234567890"
	defaultARN := fmt.Sprintf("arn:aws:iam::%s:role/RoleName", defaultAccountID)
	errTest := errors.New("test")

	cases := map[string]struct {
		role        string
		accountID   string
		err         error
		expected    string
		expectedErr error
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
		"GetCallerIdentity error": {
			role:        "RoleName",
			accountID:   "1234567890",
			err:         errTest,
			expectedErr: errTest,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m := stsMock{
				resp: &sts.GetCallerIdentityOutput{
					Account: &tc.accountID,
				},
				err: tc.err,
			}

			actual, err := parseRole(tc.role, m)
			assert.Equal(t, actual, tc.expected)
			assert.Equal(t, err, tc.expectedErr)
		})
	}
}