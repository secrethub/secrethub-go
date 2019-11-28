package secrethub

import (
	"github.com/secrethub/secrethub-go/pkg/secrethub/iterator"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"
)

// CredentialService handles operations on credentials on SecretHub.
type CredentialService interface {
	// Create a new credential from the credentials.Creator for an existing account.
	Create(credentials.Creator) error
	// List lists all credentials of the currently authenticated account.
	List(_ *CredentialListParams) CredentialIterator
	// Disable an existing credential.
	Disable(fingerprint string) error
}

func newCredentialService(client *Client) CredentialService {
	return credentialService{
		client: client,
	}
}

type credentialService struct {
	client *Client
}

// Create a new credential from the credentials.Creator for an existing account.
// This includes a re-encrypted copy the the account key.
func (s credentialService) Create(creator credentials.Creator) error {
	accountKey, err := s.client.getAccountKey()
	if err != nil {
		return err
	}

	err = creator.Create()
	if err != nil {
		return err
	}

	verifier := creator.Verifier()
	bytes, fingerprint, err := verifier.Export()
	if err != nil {
		return err
	}

	accountKeyRequest, err := s.client.createAccountKeyRequest(creator.Encrypter(), *accountKey)
	if err != nil {
		return err
	}

	req := api.CreateCredentialRequest{
		Fingerprint: fingerprint,
		Verifier:    bytes,
		Type:        verifier.Type(),
		Metadata:    creator.Metadata(),
		AccountKey:  accountKeyRequest,
	}
	err = verifier.AddProof(&req)
	if err != nil {
		return err
	}

	err = req.Validate()
	if err != nil {
		return err
	}

	_, err = s.client.httpClient.CreateCredential(&req)
	if err != nil {
		return err
	}
	return nil
}

// CredentialListParams are the parameters that configure credential listing.
type CredentialListParams struct{}

// CredentialIterator can be used to iterate over a list of credentials.
type CredentialIterator interface {
	Next() (api.Credential, error)
}

type credentialIterator struct {
	credentials  []*api.Credential
	currentIndex int
	err          error
}

func (c *credentialIterator) Next() (api.Credential, error) {
	if c.err != nil {
		return api.Credential{}, c.err
	}

	currentIndex := c.currentIndex
	if currentIndex >= len(c.credentials) {
		return api.Credential{}, iterator.Done
	}
	c.currentIndex++
	return *c.credentials[currentIndex], nil
}

// List returns an iterator that lists all credentials of the currently authenticated account.
func (s credentialService) List(_ *CredentialListParams) CredentialIterator {
	creds, err := s.client.httpClient.ListMyCredentials()
	return &credentialIterator{
		credentials: creds,
		err:         err,
	}
}

// Disable an existing credential.
func (s credentialService) Disable(fingerprint string) error {
	err := api.ValidateShortCredentialFingerprint(fingerprint)
	if err != nil {
		return err
	}

	f := false
	req := &api.UpdateCredentialRequest{
		Enabled: &f,
	}
	err = req.Validate()
	if err != nil {
		return err
	}

	return s.client.httpClient.UpdateCredential(fingerprint, req)
}
