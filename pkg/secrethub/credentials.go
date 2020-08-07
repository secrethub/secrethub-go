package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/pkg/secrethub/iterator"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"
)

// CredentialService handles operations on credentials on SecretHub.
type CredentialService interface {
	// Create a new credential from the credentials.Creator for an existing account.
	Create(credentials.Creator, string) (*api.Credential, error)
	// Disable an existing credential.
	Disable(fingerprint string) error
	// List lists all credentials of the currently authenticated account.
	List(_ *CredentialListParams) CredentialIterator
}

func newCredentialService(client *Client, isAuthenticated func() bool, isKeyed func() bool) CredentialService {
	return credentialService{
		client:          client,
		isAuthenticated: isAuthenticated,
		isKeyed:         isKeyed,
	}
}

type credentialService struct {
	client          *Client
	isAuthenticated func() bool
	isKeyed         func() bool
}

// Create a new credential from the credentials.Creator for an existing account.
// If the account is already keyed, the key is re-encrypted for the new credential.
// If the account is not yet keyed, a new account key is also created.
// Description is optional and can be left empty.
func (s credentialService) Create(creator credentials.Creator, description string) (*api.Credential, error) {
	if !s.isAuthenticated() {
		return nil, ErrNoDecryptionKey
	}

	var accountKey crypto.RSAPrivateKey
	var err error
	if !s.isKeyed() {
		accountKey, err = generateAccountKey()
	} else {
		key, err := s.client.getAccountKey()
		if err != nil {
			return nil, err
		}
		accountKey = *key
	}

	err = creator.Create()
	if err != nil {
		return nil, err
	}

	verifier := creator.Verifier()
	bytes, fingerprint, err := verifier.Export()
	if err != nil {
		return nil, err
	}

	accountKeyRequest, err := s.client.createAccountKeyRequest(creator.Encrypter(), accountKey)
	if err != nil {
		return nil, err
	}

	var reqDescription *string
	if description != "" {
		reqDescription = &description
	}

	req := api.CreateCredentialRequest{
		Fingerprint: fingerprint,
		Verifier:    bytes,
		Description: reqDescription,
		Type:        verifier.Type(),
		Metadata:    creator.Metadata(),
		AccountKey:  accountKeyRequest,
	}
	err = verifier.AddProof(&req)
	if err != nil {
		return nil, err
	}

	err = req.Validate()
	if err != nil {
		return nil, err
	}

	return s.client.httpClient.CreateCredential(&req)
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

	_, err = s.client.httpClient.UpdateCredential(fingerprint, req)
	return err
}
