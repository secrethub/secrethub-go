package auth_test

import (
	"net/http"
	"testing"

	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"

	"github.com/secrethub/secrethub-go/internals/assert"
	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/internals/crypto"
)

func TestSignRequest_CheckHeadersAreSet(t *testing.T) {
	// Arrange
	clientKey, err := crypto.GenerateRSAPrivateKey(1024)
	if err != nil {
		panic(err)
	}

	signer := auth.NewHTTPSigner(credentials.RSACredential{RSAPrivateKey: clientKey})

	req, err := http.NewRequest("GET", "https://api.secrethub.io/repos/jdoe/catpictures", nil)
	assert.OK(t, err)

	// Act
	err = signer.Authenticate(req)
	assert.OK(t, err)

	// Assert
	if req.Header.Get("Date") == "" {
		t.Error("Date header not set.")
	}

	if req.Header.Get("Authorization") == "" {
		t.Error("Authorization header not set.")
	}
}
