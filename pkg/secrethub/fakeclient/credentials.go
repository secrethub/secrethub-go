package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"
	"github.com/secrethub/secrethub-go/pkg/secrethub/iterator"
)

type CredentialService struct {
	CreateFunc  func(credentials.Creator, string) (*api.Credential, error)
	DisableFunc func(fingerprint string) error
	ListFunc    func(_ *secrethub.CredentialListParams) secrethub.CredentialIterator
}

func (c *CredentialService) Create(creator credentials.Creator, description string) (*api.Credential, error) {
	return c.CreateFunc(creator, description)
}

func (c *CredentialService) Disable(fingerprint string) error {
	return c.DisableFunc(fingerprint)
}

func (c *CredentialService) List(credentialListParams *secrethub.CredentialListParams) secrethub.CredentialIterator {
	return c.ListFunc(credentialListParams)
}

type CredentialIterator struct {
	Credentials  []*api.Credential
	CurrentIndex int
	Err          error
}

func (c *CredentialIterator) Next() (api.Credential, error) {
	if c.Err != nil {
		return api.Credential{}, c.Err
	}

	currentIndex := c.CurrentIndex
	if currentIndex >= len(c.Credentials) {
		return api.Credential{}, iterator.Done
	}
	c.CurrentIndex++
	return *c.Credentials[currentIndex], nil
}
