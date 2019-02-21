package crypto

import (
	"bytes"
	"testing"

	"github.com/keylockerbv/secrethub-go/pkg/testutil"
)

func TestAESKey_Encrypt_Decrypt_Secret(t *testing.T) {
	encryptionKey, err := GenerateAESKey()
	testutil.Compare(t, err, nil)

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
	indexKey, err := GenerateAESKey()
	testutil.OK(t, err)
	testData := []byte("testDataString")

	// Act
	result, err := indexKey.HMAC(testData)
	testutil.OK(t, err)

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

func TestCiphertextAES_Encode(t *testing.T) {
	cases := map[string]struct {
		ciphertext ciphertextAES
		expected   EncodedCiphertextAES
	}{
		"success": {
			ciphertext: ciphertextAES{
				Data:  []byte("aes_data"),
				Nonce: []byte("nonce_data"),
			},
			expected: EncodedCiphertextAES("AES-GCM$YWVzX2RhdGE=$nonce=bm9uY2VfZGF0YQ=="),
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			actual := tc.ciphertext.Encode()

			// Assert
			testutil.Compare(t, actual, tc.expected)
		})
	}
}

func TestCiphertextRSAAES_Encode(t *testing.T) {
	cases := map[string]struct {
		ciphertext ciphertextRSAAES
		expected   EncodedCiphertextRSAAES
	}{
		"success": {
			ciphertext: ciphertextRSAAES{
				ciphertextAES: &ciphertextAES{
					Data:  []byte("aes_data"),
					Nonce: []byte("nonce_data"),
				},
				ciphertextRSA: &ciphertextRSA{
					Data: []byte("rsa_data"),
				},
			},
			expected: EncodedCiphertextRSAAES("RSA-OAEP+AES-GCM$YWVzX2RhdGE=$key=cnNhX2RhdGE=,nonce=bm9uY2VfZGF0YQ=="),
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			actual := tc.ciphertext.Encode()

			// Assert
			testutil.Compare(t, actual, tc.expected)
		})
	}
}
