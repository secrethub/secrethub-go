package crypto_test

import (
	"bytes"
	"testing"

	"github.com/keylockerbv/secrethub-go/pkg/crypto"
)

func TestGenerateNonce(t *testing.T) {
	//  act
	nonce1, err := crypto.GenerateNonce(32)
	if err != nil {
		t.Error(err)
	}
	nonce2, err := crypto.GenerateNonce(32)
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(*nonce1, *nonce2) {
		t.Fatal("Same Salt generated.")
	}
}
