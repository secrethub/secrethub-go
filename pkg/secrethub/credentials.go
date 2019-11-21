package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"
)

// CredentialService handles operations on credentials on SecretHub.
type CredentialService interface {
	// Create a new credential from the credentials.Creator for an existing account.
	Create(credentials.Creator) error
	// ListMine lists all credentials of the currently authenticated account.
	ListMine() ([]*api.Credential, error)
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

// ListMine lists all credentials of the currently authenticated account.
func (s credentialService) ListMine() ([]*api.Credential, error) {
	return s.client.httpClient.ListMyCredentials()
}
