package crypto

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/secrethub/secrethub-go/internals/assert"
)

func TestAESKey_Encrypt_Decrypt_Secret(t *testing.T) {
	encryptionKey, err := GenerateSymmetricKey()
	assert.Equal(t, err, nil)

	testData := []byte("testdata")

	ciphertext, err := encryptionKey.Encrypt(testData)
	if err != nil {
		t.Error(err)
	}

	decryptedData, err := encryptionKey.Decrypt(ciphertext)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(testData, decryptedData) {
		t.Fail()
	}
}

func TestSymmetricKey_HMAC(t *testing.T) {
	// Setup
	indexKey, err := GenerateSymmetricKey()
	assert.OK(t, err)
	testData := []byte("testDataString")

	// Act
	result, err := indexKey.HMAC(testData)
	assert.OK(t, err)

	// Assert
	if bytes.Equal(result, testData) {
		t.Fail()
	}

	// Hash should not be appended.
	if len(result) > len(testData) {
		if bytes.Equal(result[:len(testData)], testData) {
			t.Fatal("Hash is appended")
		}
	}
}

func TestCiphertextAES_MarshalJSON(t *testing.T) {
	cases := map[string]struct {
		ciphertext CiphertextAES
		expected   string
	}{
		"success": {
			ciphertext: CiphertextAES{
				Data:  []byte("aes_data"),
				Nonce: []byte("nonce_data"),
			},
			expected: "AES-GCM$YWVzX2RhdGE=$nonce=bm9uY2VfZGF0YQ==",
		},
	}

	for name, tc := range cases {
		t.Run(name+" encoded", func(t *testing.T) {
			// Act
			actual := tc.ciphertext.EncodeToString()

			// Assert
			assert.Equal(t, actual, tc.expected)
		})

		t.Run(name+" json", func(t *testing.T) {
			// Act
			actual, err := tc.ciphertext.MarshalJSON()
			assert.OK(t, err)
			expected, err := json.Marshal(tc.expected)
			assert.OK(t, err)

			// Assert
			assert.Equal(t, actual, expected)
		})
	}
}

func TestCiphertextRSAAES_MarshalJSON(t *testing.T) {
	cases := map[string]struct {
		ciphertext CiphertextRSAAES
		expected   string
	}{
		"success": {
			ciphertext: CiphertextRSAAES{
				AES: CiphertextAES{
					Data:  []byte("aes_data"),
					Nonce: []byte("nonce_data"),
				},
				RSA: CiphertextRSA{
					Data: []byte("rsa_data"),
				},
			},
			expected: "RSA-OAEP+AES-GCM$YWVzX2RhdGE=$key=cnNhX2RhdGE=,nonce=bm9uY2VfZGF0YQ==",
		},
	}

	for name, tc := range cases {
		t.Run(name+" encoded", func(t *testing.T) {
			// Act
			actual := tc.ciphertext.EncodeToString()

			// Assert
			assert.Equal(t, actual, tc.expected)
		})

		t.Run(name+" json", func(t *testing.T) {
			// Act
			actual, err := tc.ciphertext.MarshalJSON()
			assert.OK(t, err)
			expected, err := json.Marshal(tc.expected)
			assert.OK(t, err)

			// Assert
			assert.Equal(t, actual, expected)
		})
	}
}

func Test_generateNonce(t *testing.T) {
	//  act
	nonce1, err := generateNonce(32)
	if err != nil {
		t.Error(err)
	}
	nonce2, err := generateNonce(32)
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(nonce1, nonce2) {
		t.Fatal("Same Salt generated.")
	}
}
