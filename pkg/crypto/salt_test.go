package crypto

import (
	"bytes"
	"testing"

	"github.com/keylockerbv/secrethub/testutil"
)

func TestSaltAlgoUniqueness(t *testing.T) {
	testutil.Unit(t)

	// When creating a new purpose, add it here.
	all := map[SaltAlgo]bool{
		SaltAlgoNone:      true,
		SaltAlgoAES128GCM: true,
		SaltAlgoAES196GCM: true,
		SaltAlgoAES256GCM: true,
	}

	t.Logf("Each algorithm in the map is unique: %v", all)
}

func TestSaltOperationUniqueness(t *testing.T) {
	testutil.Unit(t)

	// When creating a new purpose, add it here.
	all := map[SaltOperation]bool{
		SaltOperationNone:                      true,
		SaltOperationLocalCredentialEncryption: true,
		SaltOperationHTTPAuthentication:        true,
	}

	t.Logf("Each operation in the map is unique: %v", all)
}

func TestSaltAlgoValidate(t *testing.T) {
	testutil.Unit(t)

	// Arrange
	cases := map[string]struct {
		algo     SaltAlgo
		expected error
	}{
		"none": {
			algo:     SaltAlgoNone,
			expected: ErrInvalidSaltAlgo,
		},
		"128": {
			algo:     SaltAlgoAES128GCM,
			expected: nil,
		},
		"196": {
			algo:     SaltAlgoAES196GCM,
			expected: nil,
		},
		"256": {
			algo:     SaltAlgoAES256GCM,
			expected: nil,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			err := tc.algo.Validate()

			// Assert
			testutil.Compare(t, err, tc.expected)
		})
	}
}

func TestSaltOperationValidate(t *testing.T) {
	testutil.Unit(t)

	// Arrange
	cases := map[string]struct {
		operation SaltOperation
		expected  error
	}{
		"none": {
			operation: SaltOperationNone,
			expected:  ErrInvalidSaltOperation,
		},
		"encryption": {
			operation: SaltOperationLocalCredentialEncryption,
			expected:  nil,
		},
		"message_authentication": {
			operation: SaltOperationHTTPAuthentication,
			expected:  nil,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			err := tc.operation.Validate()

			// Assert
			testutil.Compare(t, err, tc.expected)
		})
	}
}

func TestSaltPurposeValidate(t *testing.T) {
	testutil.Unit(t)

	// Arrange
	cases := map[string]struct {
		purpose  SaltPurpose
		expected error
	}{
		"valid": {
			purpose: SaltPurpose{
				Algo:      SaltAlgoAES128GCM,
				Operation: SaltOperationLocalCredentialEncryption,
			},
			expected: nil,
		},
		"invalid_algo": {
			purpose: SaltPurpose{
				Algo:      0x00,
				Operation: SaltOperationLocalCredentialEncryption,
			},
			expected: ErrInvalidSaltAlgo,
		},
		"invalid_operation": {
			purpose: SaltPurpose{
				Algo:      SaltAlgoAES128GCM,
				Operation: 0x00,
			},
			expected: ErrInvalidSaltOperation,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			err := tc.purpose.Validate()

			// Assert
			testutil.Compare(t, err, tc.expected)
		})
	}
}

func TestGenerateSaltValidatesPurposeParams(t *testing.T) {
	testutil.Component(t)

	// Arrange
	cases := map[string]struct {
		l         int
		algo      SaltAlgo
		operation SaltOperation
		err       error
	}{
		"valid": {
			l:         32,
			algo:      SaltAlgoAES256GCM,
			operation: SaltOperationLocalCredentialEncryption,
			err:       nil,
		},
		"invalid_length": {
			l:         0,
			algo:      SaltAlgoAES256GCM,
			operation: SaltOperationLocalCredentialEncryption,
			err:       ErrInvalidSalt,
		},
		"invalid_purpose_param": {
			l:         32,
			algo:      0x00,
			operation: SaltOperationLocalCredentialEncryption,
			err:       ErrInvalidSaltAlgo,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			_, err := generateSalt(tc.l, tc.algo, tc.operation)

			// Assert
			testutil.Compare(t, err, tc.err)
		})
	}
}

func TestGenerateSaltDiff(t *testing.T) {
	testutil.Unit(t)

	n := 10
	generated := make([]Salt, n)

	for i := 0; i < n; i++ {
		salt, err := generateSalt(8, SaltAlgoAES128GCM, SaltOperationLocalCredentialEncryption)
		testutil.OK(t, err)

		generated[i] = salt
	}

	for i, salt := range generated {
		for j, other := range generated {
			if i == j {
				continue
			}

			if bytes.Equal(salt, other) {
				t.Errorf(
					"unexpected salt is equal to other generated salt: %v (%d) == %v (%d)",
					salt,
					i,
					other,
					j,
				)
			}
		}
	}
}

func TestValidateSalt(t *testing.T) {
	testutil.Unit(t)

	// Arrange
	cases := map[string]struct {
		salt []byte
		err  error
	}{
		"valid_aes128gcm": {
			salt: []byte{SaltAlgoAES128GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			err:  nil,
		},
		"valid_aes196gcm": {
			salt: []byte{SaltAlgoAES196GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			err:  nil,
		},
		"valid_aes256gcm": {
			salt: []byte{SaltAlgoAES256GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			err:  nil,
		},
		"too_short": {
			salt: []byte{SaltAlgoAES256GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6},
			err:  ErrInvalidSalt,
		},
		"invalid_algo": {
			salt: []byte{0x00, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			err:  ErrInvalidSaltAlgo,
		},
		"invalid_operation": {
			salt: []byte{SaltAlgoAES128GCM, 0x00, 0, 1, 2, 3, 4, 5, 6, 7},
			err:  ErrInvalidSaltOperation,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			err := Salt(tc.salt).Validate()

			// Assert
			testutil.Compare(t, err, tc.err)
		})
	}
}

func TestVerifySaltPurpose(t *testing.T) {
	testutil.Unit(t)

	// Arrange
	cases := map[string]struct {
		purpose   SaltPurpose
		keyLen    int
		algo      string
		operation SaltOperation
		err       error
	}{
		"valid": {
			purpose: SaltPurpose{
				Algo:      SaltAlgoAES256GCM,
				Operation: SaltOperationLocalCredentialEncryption,
			},
			keyLen:    32,
			algo:      "aesgcm",
			operation: SaltOperationLocalCredentialEncryption,
			err:       nil,
		},
		"invalid_purpose": {
			purpose: SaltPurpose{
				Algo:      SaltAlgoNone,
				Operation: SaltOperationLocalCredentialEncryption,
			},
			keyLen:    32,
			algo:      "aesgcm",
			operation: SaltOperationLocalCredentialEncryption,
			err:       ErrInvalidSaltAlgo,
		},
		"mismatched_keylen": {
			purpose: SaltPurpose{
				Algo:      SaltAlgoAES256GCM,
				Operation: SaltOperationLocalCredentialEncryption,
			},
			keyLen:    16,
			algo:      "aesgcm",
			operation: SaltOperationLocalCredentialEncryption,
			err:       ErrInvalidSaltAlgo,
		},
		"mismatched_algo": {
			purpose: SaltPurpose{
				Algo:      SaltAlgoAES256GCM,
				Operation: SaltOperationLocalCredentialEncryption,
			},
			keyLen:    32,
			algo:      "invalid_algo",
			operation: SaltOperationLocalCredentialEncryption,
			err:       ErrInvalidSaltAlgo,
		},
		"mismatched_operation": {
			purpose: SaltPurpose{
				Algo:      SaltAlgoAES256GCM,
				Operation: SaltOperationLocalCredentialEncryption,
			},
			keyLen:    32,
			algo:      "aesgcm",
			operation: SaltOperationHTTPAuthentication,
			err:       ErrInvalidSaltOperation,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			err := tc.purpose.Verify(tc.keyLen, tc.algo, tc.operation)

			// Assert
			testutil.Compare(t, err, tc.err)
		})
	}
}
