package api

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/secrethub/secrethub-go/internals/api/uuid"

	"github.com/secrethub/secrethub-go/internals/assert"
)

func TestEncryptedData(t *testing.T) {
	encryptedDataRSAAccountKey := NewEncryptedDataRSAOAEP([]byte("rsa-ciphertext"), HashingAlgorithmSHA256, NewEncryptionKeyAccountKey(4096, *uuid.New()))

	cases := map[string]struct {
		in          *EncryptedData
		expectedErr error
		validateErr error
	}{
		"aes with rsa account key": {
			in: NewEncryptedDataAESGCM([]byte("ciphertext"), []byte("nonce"), 96, NewEncryptionKeyEncrypted(256, encryptedDataRSAAccountKey)),
		},
		"aes with rsa local key": {
			in: NewEncryptedDataAESGCM([]byte("ciphertext"), []byte("nonce"), 96, NewEncryptionKeyLocal(256)),
		},
		"aes with secret key": {
			in: NewEncryptedDataAESGCM([]byte("ciphertext"), []byte("nonce"), 96, NewEncryptionKeySecretKey(256, *uuid.New())),
		},
		"rsa account key": {
			in: encryptedDataRSAAccountKey,
		},
		"aws kms": {
			in: NewEncryptedDataAWSKMS([]byte("ciphertext"), NewEncryptionKeyAWS("arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab")),
		},
		"aes with scrypt": {
			in:          NewEncryptedDataAESGCM([]byte("ciphertext"), []byte("nonce"), 96, NewEncryptionKeyDerivedScrypt(256, 1, 2, 3, []byte("just-a-salt"))),
			expectedErr: errors.New("derived key type not yet supported"),
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			bytes, err := json.Marshal(tc.in)
			assert.OK(t, err)

			var res EncryptedData
			err = json.Unmarshal(bytes, &res)

			assert.Equal(t, err, tc.expectedErr)
			if tc.expectedErr == nil {
				assert.Equal(t, res, tc.in)
				assert.Equal(t, res.Validate(), tc.validateErr)
			}
		})
	}
}
