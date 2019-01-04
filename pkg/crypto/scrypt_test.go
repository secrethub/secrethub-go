package crypto

import (
	"crypto/rand"
	"fmt"
	"testing"

	"golang.org/x/crypto/scrypt"

	"github.com/keylockerbv/secrethub-go/internal/testutil"
)

func TestValidateScryptKey(t *testing.T) {

	cases := map[string]struct {
		keyLen int
		salt   []byte
		N      int
		r      int
		p      int
		err    error
	}{
		"valid": {
			keyLen: 16,
			salt:   []byte{SaltAlgoAES128GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:      1 << 15,
			r:      8,
			p:      1,
			err:    nil,
		},
		"on_point_klen_24": {
			keyLen: 24,
			salt:   []byte{SaltAlgoAES196GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:      1 << 15,
			r:      8,
			p:      1,
			err:    nil,
		},
		"on_point_klen_32": {
			keyLen: 32,
			salt:   []byte{SaltAlgoAES256GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:      1 << 15,
			r:      8,
			p:      1,
			err:    nil,
		},
		"salt_too_short": {
			keyLen: 32,
			salt:   []byte{SaltAlgoAES256GCM, SaltOperationLocalCredentialEncryption, 1, 2, 3, 4, 5, 6, 7},
			N:      1 << 15,
			r:      8,
			p:      1,
			err:    ErrInvalidSalt,
		},
		"mismatched_keylen_16": {
			keyLen: 16,
			salt:   []byte{SaltAlgoAES196GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:      1 << 15,
			r:      8,
			p:      1,
			err:    ErrInvalidSaltAlgo,
		},
		"mismatched_keylen_24": {
			keyLen: 24,
			salt:   []byte{SaltAlgoAES128GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:      1 << 15,
			r:      8,
			p:      1,
			err:    ErrInvalidSaltAlgo,
		},
		"mismatched_keylen_32": {
			keyLen: 32,
			salt:   []byte{SaltAlgoAES128GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:      1 << 15,
			r:      8,
			p:      1,
			err:    ErrInvalidSaltAlgo,
		},
		"N_too_small": {
			keyLen: 16,
			salt:   []byte{SaltAlgoAES128GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:      (1 << 15) - 1,
			r:      8,
			p:      1,
			err:    ErrInvalidN,
		},
		"invalid_r": {
			keyLen: 16,
			salt:   []byte{SaltAlgoAES128GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:      1 << 15,
			r:      7,
			p:      1,
			err:    ErrInvalidR,
		},
		"invalid_p": {
			keyLen: 16,
			salt:   []byte{SaltAlgoAES128GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:      1 << 15,
			r:      8,
			p:      0,
			err:    ErrInvalidP,
		},
		"off_point_keylen_15": {
			keyLen: 15,
			salt:   []byte{SaltAlgoAES128GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:      1 << 15,
			r:      8,
			p:      1,
			err:    ErrInvalidKeyLength,
		},
		"off_point_keylen_17": {
			keyLen: 17,
			salt:   []byte{SaltAlgoAES128GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:      1 << 15,
			r:      8,
			p:      1,
			err:    ErrInvalidKeyLength,
		},
		"off_point_keylen_23": {
			keyLen: 23,
			salt:   []byte{SaltAlgoAES128GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:      1 << 15,
			r:      8,
			p:      1,
			err:    ErrInvalidKeyLength,
		},
		"off_point_keylen_25": {
			keyLen: 25,
			salt:   []byte{SaltAlgoAES128GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:      1 << 15,
			r:      8,
			p:      1,
			err:    ErrInvalidKeyLength,
		},
		"off_point_keylen_31": {
			keyLen: 31,
			salt:   []byte{SaltAlgoAES128GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:      1 << 15,
			r:      8,
			p:      1,
			err:    ErrInvalidKeyLength,
		},
		"off_point_keylen_33": {
			keyLen: 33,
			salt:   []byte{SaltAlgoAES128GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:      1 << 15,
			r:      8,
			p:      1,
			err:    ErrInvalidKeyLength,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			key := &ScryptKey{
				KeyLen: tc.keyLen,
				Salt:   tc.salt,
				N:      tc.N,
				R:      tc.r,
				P:      tc.p,
			}

			// Act
			err := key.Validate()

			// Assert
			testutil.Compare(t, err, tc.err)
		})
	}
}

func TestGenerateScryptKey(t *testing.T) {

	// Arrange
	cases := map[string]struct {
		passphrase string
		err        error
	}{
		"valid": {
			passphrase: "foo",
			err:        nil,
		},
		"empty_passphrase": {
			passphrase: "",
			err:        ErrEmptyPassphrase,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			key, err := GenerateScryptKey([]byte(tc.passphrase))

			// Assert
			testutil.Compare(t, err, tc.err)
			if tc.err == nil && key == nil {
				t.Errorf("unexpected key after initialization:\n%+v", key)
			}
		})
	}

}

func TestDeriveScryptKey(t *testing.T) {

	// Arrange
	cases := map[string]struct {
		passphrase string
		keyLen     int
		salt       []byte
		N          int
		r          int
		p          int
		err        error
	}{
		"valid": {
			passphrase: "foo",
			keyLen:     32,
			salt:       []byte{SaltAlgoAES256GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:          1 << 15,
			r:          8,
			p:          1,
			err:        nil,
		},
		"empty_passphrase": {
			passphrase: "",
			keyLen:     32,
			salt:       []byte{SaltAlgoAES256GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:          1 << 15,
			r:          8,
			p:          1,
			err:        ErrEmptyPassphrase,
		},
		"one_invalid_param": {
			passphrase: "foo",
			keyLen:     0,
			salt:       []byte{SaltAlgoAES256GCM, SaltOperationLocalCredentialEncryption, 0, 1, 2, 3, 4, 5, 6, 7},
			N:          0,
			r:          8,
			p:          1,
			err:        ErrInvalidKeyLength,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			key, err := DeriveScryptKey([]byte(tc.passphrase), tc.salt, tc.N, tc.r, tc.p, tc.keyLen)

			// Assert
			testutil.Compare(t, err, tc.err)
			if tc.err == nil && key == nil {
				t.Errorf("unexpected key after initialization:\n%+v", key)
			}
		})
	}

}

func TestIsPowerOfTwo(t *testing.T) {

	// Arrange
	cases := []struct {
		n        int
		expected bool
	}{
		{
			n:        0,
			expected: false,
		},
		{
			n:        1,
			expected: true,
		},
		{
			n:        2,
			expected: true,
		},
		{
			n:        4,
			expected: true,
		},
		{
			n:        -1,
			expected: false,
		},
		{
			n:        -2,
			expected: false,
		},
		{
			n:        -4,
			expected: false,
		},
		{
			n:        3,
			expected: false,
		},
		{
			n:        -3,
			expected: false,
		},
		{
			n:        5,
			expected: false,
		},
		{
			n:        -5,
			expected: false,
		},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d", tc.n), func(t *testing.T) {
			// Act
			actual := isPowerOf2(tc.n)

			// Assert
			testutil.Compare(t, actual, tc.expected)
		})
	}
}

// Below we test the assumption that increasing the salt lenght does
// not significantly increase the execution time of key derivation
// function. The output of the benchmarks is documented below:
//
// BenchmarkScryptSaltLength16-4   	      10	 104853686 ns/op
// BenchmarkScryptSaltLength32-4   	      10	 105053118 ns/op
// BenchmarkScryptSaltLength64-4   	      10	 107446760 ns/op

func BenchmarkScryptSaltLength16(b *testing.B) { benchmarkScryptKey(b, 16, 1<<15, 8, 1, 32) }
func BenchmarkScryptSaltLength32(b *testing.B) { benchmarkScryptKey(b, 32, 1<<15, 8, 1, 32) }
func BenchmarkScryptSaltLength64(b *testing.B) { benchmarkScryptKey(b, 64, 1<<15, 8, 1, 32) }

func benchmarkScryptKey(b *testing.B, saltLen, N, r, p, keyLen int) {
	salt := make([]byte, saltLen)
	_, err := rand.Reader.Read(salt)
	if err != nil {
		b.Fatal(err)
	}

	for n := 0; n < b.N; n++ {
		_, err := scrypt.Key([]byte("some_complex_123456_passphrase"), salt, N, r, p, keyLen)
		testutil.OK(b, err)
	}
}
