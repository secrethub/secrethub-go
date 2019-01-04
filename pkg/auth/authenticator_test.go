package auth_test

import (
	"net/http"
	"testing"

	"github.com/keylockerbv/secrethub-go/pkg/api"

	"github.com/keylockerbv/secrethub-go/internal/testutil"
	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
	"github.com/keylockerbv/secrethub-go/pkg/auth"
)

func TestVerifyMultipleMethods(t *testing.T) {
	// TODO: Check whether this test still adds value, as it no longer uses multiple methods.

	// Arrange
	key := clientKey
	authID, err := key.GetIdentifier()
	testutil.OK(t, err)
	pub, err := key.ExportPublicKey()
	testutil.OK(t, err)

	fakeCredentialGetter := fakeCredentialGetter{
		GetFunc: func(arg string) (*api.Credential, error) {
			return &api.Credential{
				AccountID:   uuid.New(),
				Fingerprint: authID,
				Verifier:    pub,
			}, nil
		},
	}

	cases := map[string]struct {
		Credential auth.Credential
		Expected   string
	}{
		"success": {
			Credential: auth.NewCredentialSignature(key),
			Expected:   authID,
		},
	}

	authenticator := auth.NewAuthenticator(
		auth.NewMethodSignature(fakeCredentialGetter),
	)

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Arrange
			req, err := http.NewRequest("POST", "https://api.secrethub.io/repos/jdoe/catpictures", nil)
			testutil.OK(t, err)

			err = tc.Credential.AddAuthentication(req)
			testutil.OK(t, err)

			// Act
			actual, err := authenticator.Verify(req)

			// Assert
			testutil.OK(t, err)

			testutil.Compare(t, actual.AuthID, tc.Expected)
		})
	}
}
