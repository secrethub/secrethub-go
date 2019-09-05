package api

import (
	"testing"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/crypto"
)

func TestCreateSecretVersionRequest_Validate_MaxSize(t *testing.T) {

	tests := []struct {
		dataSize      int
		expectSuccess bool
	}{
		{
			10,
			true,
		},
		{
			512 * 1024,
			true,
		},
		{
			550 * 1024,
			false,
		},
	}

	aesKey, err := crypto.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {

		slice := make([]byte, test.dataSize)
		for i := range slice {
			slice[i] = 0x1
		}

		ciphertext, err := aesKey.Encrypt(slice)
		if err != nil {
			t.Fatal(err)
		}

		id := uuid.New()
		r := CreateSecretVersionRequest{
			SecretKeyID:   &id,
			EncryptedData: ciphertext,
		}

		err = r.Validate()
		success := err == nil
		if success != test.expectSuccess {
			t.Errorf("success (%v) != expectSuccess (%v)", success, test.expectSuccess)
		}
	}
}
