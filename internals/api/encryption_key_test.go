package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/secrethub/secrethub-go/internals/assert"
)

func TestEncryptionKeyDerived_UnmarshalJSON(t *testing.T) {
	salt := []byte(strings.Repeat("1", 96))
	parameters := KeyDerivationParametersScrypt{
		P: 1,
		N: 1,
		R: 1,
	}
	metadata := KeyDerivationMetadataScrypt{
		Salt: salt,
	}

	cases := map[string]struct {
		in          *EncryptionKeyDerived
		expectedErr error
		validateErr error
	}{
		"success": {
			in: NewEncryptionKeyDerivedScrypt(128, 1, 1, 1, salt),
		},
		"missing-parameters": {
			in: &EncryptionKeyDerived{
				EncryptionKey: EncryptionKey{
					Type: KeyTypeDerived,
				},
				Length:     128,
				Algorithm:  KeyDerivationAlgorithmScrypt,
				Parameters: nil,
				Metadata:   metadata,
			},
			validateErr: ErrMissingField("parameters"),
		},
		"missing-metadata": {
			in: &EncryptionKeyDerived{
				EncryptionKey: EncryptionKey{
					Type: KeyTypeDerived,
				},
				Length:     128,
				Algorithm:  KeyDerivationAlgorithmScrypt,
				Parameters: parameters,
				Metadata:   nil,
			},
			validateErr: ErrMissingField("metadata"),
		},
		"invalid-algorithm": {
			in: &EncryptionKeyDerived{
				EncryptionKey: EncryptionKey{
					Type: KeyTypeDerived,
				},
				Length:     128,
				Algorithm:  KeyDerivationAlgorithm("invalid"),
				Parameters: parameters,
				Metadata:   metadata,
			},
			expectedErr: ErrInvalidKeyDerivationAlgorithm,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			bytes, err := json.Marshal(tc.in)
			assert.OK(t, err)

			fmt.Println(string(bytes))

			var res EncryptionKeyDerived
			err = json.Unmarshal(bytes, &res)

			assert.Equal(t, err, tc.expectedErr)
			if tc.expectedErr == nil {
				assert.Equal(t, res.Validate(), tc.validateErr)
				if tc.validateErr == nil {
					assert.Equal(t, res, tc.in)
				}
			}
		})
	}
}
