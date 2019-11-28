package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"
)

// CredentialService handles operations on credentials on SecretHub.
type CredentialService interface {
	// Create a new credential from the credentials.Creator for an existing account.
	Create(credentials.Creator) error
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
