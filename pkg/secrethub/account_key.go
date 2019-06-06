package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/crypto"
)

// DefaultAccountKeyLength defines the default bit size for account keys.
const DefaultAccountKeyLength = 4096

func generateAccountKey() (crypto.RSAPrivateKey, error) {
	return crypto.GenerateRSAPrivateKey(DefaultAccountKeyLength)
}

// AccountKeyService handles operations on SecretHub account keys.
type AccountKeyService interface {
	// Create creates an account key for the client's credential.
	Create(encrypter Encrypter) (*api.EncryptedAccountKey, error)
	// Exists returns whether an account key exists for the client's credential.
	Exists() (bool, error)
}

type accountKeyService struct {
	client client
}

// newAccountKeyService creates a new accountKeyService
func newAccountKeyService(client client) accountKeyService {
	return accountKeyService{
		client: client,
	}
}

// Create creates an account key for the clients credential.
func (s accountKeyService) Create(encrypter Encrypter) (*api.EncryptedAccountKey, error) {
	key, err := generateAccountKey()
	if err != nil {
		return nil, err
	}
	return s.client.createAccountKey(key, encrypter)
}

// Exists returns whether an account key exists for the client's credential.
func (s accountKeyService) Exists() (bool, error) {
	_, err := s.client.getAccountKey()
	if err == api.ErrAccountKeyNotFound || err == api.ErrCredentialNotKeyed {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
