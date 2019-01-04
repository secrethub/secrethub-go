package crypto_test

import (
	"bytes"
	"testing"

	"github.com/keylockerbv/secrethub-go/internal/testutil"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
)

func TestAESKey_Encrypt_Decrypt_Secret(t *testing.T) {
	encryptionKey, err := crypto.GenerateAESKey()
	testutil.Compare(t, err, nil)

	testData := []byte("testdata")

	encData, metaData, err := encryptionKey.Encrypt(testData)
	if err != nil {
		t.Error(err)
	}

	decryptedData, err := encryptionKey.Decrypt(encData, metaData)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(testData, decryptedData) {
		t.Fail()
	}
}

func TestSymmetricKey_HMAC(t *testing.T) {
	// Setup
	indexKey, err := crypto.GenerateAESKey()
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
