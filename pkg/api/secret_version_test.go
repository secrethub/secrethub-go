package api

import (
	"testing"

	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
)

func TestCreateSecretVersionRequest_Validate(t *testing.T) {

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

	rsaKey, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {

		slice := make([]byte, test.dataSize)
		for i := range slice {
			slice[i] = 0x1
		}

		cipherText, err := crypto.EncryptRSAAES(slice, rsaKey.RSAPublicKey)
		if err != nil {
			t.Fatal(err)
		}

		encCipherText, err := EncodeCiphertext(cipherText)
		if err != nil {
			t.Fatal(err)
		}

		r := CreateSecretVersionRequest{
			SecretKeyID:   uuid.New(),
			EncryptedData: encCipherText,
		}

		err = r.Validate()
		success := err == nil
		if success != test.expectSuccess {
			t.Errorf("success (%v) != expectSuccess (%v)", success, test.expectSuccess)
		}
	}
}
