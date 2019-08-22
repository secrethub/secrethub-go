package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"
)

// UserService handles operations on users from SecretHub.
type UserService interface {
	// Me gets the account's user if it exists.
	Me() (*api.User, error)
	// Create creates a new user at SecretHub.
	Create(username, email, fullName string, credential credentials.Creator) (*api.User, error)
	// Get a user by their username.
	Get(username string) (*api.User, error)
}

func newUserService(client *Client) UserService {
	return userService{
		client: client,
	}
}

type userService struct {
	client *Client
}

// Me gets the account's user if it exists.
func (s userService) Me() (*api.User, error) {
	return s.client.httpClient.GetMyUser()
}

// Create creates a new user at SecretHub.
func (s userService) Create(username, email, fullName string, credentialCreator credentials.Creator) (*api.User, error) {
	err := api.ValidateUsername(username)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = api.ValidateEmail(email)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = api.ValidateFullName(fullName)
	if err != nil {
		return nil, errio.Error(err)
	}

	credential, err := credentialCreator.Create()
	if err != nil {
		return nil, err
	}

	accountKey, err := generateAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.create(username, email, fullName, accountKey, credential, credential)
}

func (s userService) create(username, email, fullName string, accountKey crypto.RSAPrivateKey, verifier credentials.Verifier, encrypter credentials.Encrypter) (*api.User, error) {
	credentialRequest, err := s.client.createCredentialRequest(verifier)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = credentialRequest.Validate()
	if err != nil {
		return nil, err
	}

	userRequest := &api.CreateUserRequest{
		Username:   username,
		Email:      email,
		FullName:   fullName,
		Credential: credentialRequest,
	}

	user, err := s.client.httpClient.SignupUser(userRequest)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKeyResponse, err := s.client.createAccountKey(credentialRequest.Fingerprint, accountKey, encrypter)
	if err != nil {
		return nil, err
	}

	user.PublicKey = accountKeyResponse.PublicKey

	return user, nil
}

// Get retrieves the user with the given username from SecretHub.
func (s userService) Get(username string) (*api.User, error) {
	err := api.ValidateUsername(username)
	if err != nil {
		return nil, errio.Error(err)
	}

	user, err := s.client.httpClient.GetUser(username)
	if err != nil {
		return nil, errio.Error(err)
	}

	return user, nil
}

// createAccountKey adds the account key for the clients credential.
func (c *Client) createAccountKey(credentialFingerprint string, accountKey crypto.RSAPrivateKey, encrypter credentials.Encrypter) (*api.EncryptedAccountKey, error) {
	accountKeyRequest, err := c.createAccountKeyRequest(encrypter, accountKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = accountKeyRequest.Validate()
	if err != nil {
		return nil, err
	}

	result, err := c.httpClient.CreateAccountKey(accountKeyRequest, credentialFingerprint)
	if err != nil {
		return nil, errio.Error(err)
	}
	return result, nil
}
