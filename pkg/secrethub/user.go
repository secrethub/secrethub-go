package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

// UserService handles operations on users from SecretHub.
type UserService interface {
	// Me gets the account's user if it exists.
	Me() (*api.User, error)
	// Create creates a new user at SecretHub.
	Create(username, email, fullName string) (*api.User, error)
	// Get a user by their username.
	Get(username string) (*api.User, error)
}

type userService struct {
	client client
}

// Me gets the account's user if it exists.
func (s userService) Me() (*api.User, error) {
	return s.client.GetMyUser()
}

// Create creates a new user at SecretHub.
func (s userService) Create(username, email, fullName string) (*api.User, error) {
	accountKey, err := generateAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.SignupUser(username, email, fullName, accountKey)
}

// Get retrieves the user with the given username from SecretHub.
func (s userService) Get(username string) (*api.User, error) {
	return s.client.GetUser(username)
}

// SignupUser creates a new user at SecretHub
func (c *client) SignupUser(username, email, fullName string, accountKey *crypto.RSAKey) (*api.User, error) {
	credentialRequest, err := c.createCredentialRequest(c.credential)
	if err != nil {
		return nil, errio.Error(err)
	}

	userRequest := &api.CreateUserRequest{
		Username:   username,
		Email:      email,
		FullName:   fullName,
		Credential: credentialRequest,
	}

	err = userRequest.Validate()
	if err != nil {
		return nil, errio.Error(err)
	}

	user, err := c.httpClient.SignupUser(userRequest)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKeyResponse, err := c.CreateAccountKey(accountKey)
	if err != nil {
		return nil, err
	}

	user.PublicKey = accountKeyResponse.PublicKey

	return user, nil
}

// CreateAccountKey adds the account key for the clients credential.
func (c *client) CreateAccountKey(accountKey *crypto.RSAKey) (*api.EncryptedAccountKey, error) {
	accountKeyRequest, err := c.createAccountKeyRequest(c.credential, accountKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = accountKeyRequest.Validate()
	if err != nil {
		return nil, err
	}

	fingerprint, err := c.credential.AuthID()
	if err != nil {
		return nil, err
	}

	result, err := c.httpClient.CreateAccountKey(accountKeyRequest, fingerprint)
	if err != nil {
		return nil, errio.Error(err)
	}
	return result, nil
}

// GetUser retrieves a user at SecretHub
func (c *client) GetUser(username string) (*api.User, error) {
	err := api.ValidateUsername(username)
	if err != nil {
		return nil, errio.Error(err)
	}

	user, err := c.httpClient.GetUser(username)
	if err != nil {
		return nil, errio.Error(err)
	}

	return user, nil
}

// GetMyUser gets the account's user if it exists.
func (c *client) GetMyUser() (*api.User, error) {
	return c.httpClient.GetMyUser()
}
