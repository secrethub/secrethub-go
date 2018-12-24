package auth_test

import "github.com/keylockerbv/secrethub-go/pkg/api"

type fakeCredentialGetter struct {
	GetFunc func(fingerprint string) (*api.Credential, error)
}

func (g fakeCredentialGetter) GetCredential(fingerprint string) (*api.Credential, error) {
	return g.GetFunc(fingerprint)
}
