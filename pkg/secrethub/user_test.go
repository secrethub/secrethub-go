package secrethub

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/api/uuid"

	"github.com/secrethub/secrethub-go/internals/assert"
	"github.com/secrethub/secrethub-go/internals/crypto"
)

const (
	username = "dev1"
	fullName = "Developer Uno"
	email    = "dev1@testing.com"
)

func TestSignup(t *testing.T) {

	// Arrange
	router, opts, cleanup := setup()
	defer cleanup()

	userService := userService{
		client: Must(NewClient(opts...)),
	}

	accountKey, err := crypto.GenerateRSAPrivateKey(512)
	assert.OK(t, err)

	publicAccountKey, err := accountKey.Public().Encode()
	assert.OK(t, err)

	expectedCreateUserRequest := api.CreateUserRequest{
		Username: username,
		FullName: fullName,
		Email:    email,
		Credential: &api.CreateCredentialRequest{
			Type:        api.CredentialTypeKey,
			Fingerprint: cred1Fingerprint,
			Verifier:    cred1Verifier,
			Proof:       &api.CredentialProofKey{},
			AccountKey: &api.CreateAccountKeyRequest{
				PublicKey: publicAccountKey,
			},
		},
	}

	now := time.Now().UTC()
	expectedResponse := &api.User{
		AccountID:   uuid.New(),
		PublicKey:   publicAccountKey,
		Username:    username,
		FullName:    fullName,
		Email:       email,
		CreatedAt:   &now,
		LastLoginAt: &now,
	}
	router.Post("/users", func(w http.ResponseWriter, r *http.Request) {
		// Assert
		req := new(api.CreateUserRequest)
		err := json.NewDecoder(r.Body).Decode(&req)
		assert.OK(t, err)

		assert.OK(t, req.Validate())

		// We cannot predict the output of the encrypted key, therefore we do not test it here.
		req.Credential.AccountKey.EncryptedPrivateKey = nil
		assert.Equal(t, req, expectedCreateUserRequest)

		// Respond
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(expectedResponse)
	})

	// Act
	actual, err := userService.create(username, email, fullName, accountKey, cred1, cred1, nil, cred1)

	// Assert
	assert.OK(t, err)
	assert.Equal(t, actual, expectedResponse)
}

func TestSignup_AlreadyExists(t *testing.T) {

	// Arrange
	router, opts, cleanup := setup()
	defer cleanup()

	userService := userService{
		client: Must(NewClient(opts...)),
	}

	expected := api.ErrUserEmailAlreadyExists

	router.Post("/users", func(w http.ResponseWriter, r *http.Request) {
		// Respond
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(expected.StatusCode)
		_ = json.NewEncoder(w).Encode(expected)
	})

	key, err := crypto.GenerateRSAPrivateKey(512)
	assert.OK(t, err)

	// Act
	_, err = userService.create("dev1", "dev1@testing.com", "Developer Uno", key, cred1, cred1, nil, cred1)

	// Assert
	assert.Equal(t, err, expected)
}

func TestSignup_InvalidArgument(t *testing.T) {

	// Arrange
	_, opts, cleanup := setup()
	defer cleanup()

	userService := userService{
		client: Must(NewClient(opts...)),
	}

	key, err := crypto.GenerateRSAPrivateKey(512)
	assert.OK(t, err)

	// Act
	_, err = userService.create("invalidname$#@%%", "dev1@testing.com", "Developer Uno", key, cred1, cred1, nil, cred1)

	// Assert
	assert.Equal(t, err, api.ErrInvalidUsername)
}

func TestGetUser(t *testing.T) {

	// Arrange
	router, opts, cleanup := setup()
	defer cleanup()

	userService := newUserService(
		Must(NewClient(opts...)),
	)

	now := time.Now().UTC()
	expectedResponse := &api.User{
		AccountID:   uuid.New(),
		Username:    username,
		FullName:    fullName,
		Email:       email,
		CreatedAt:   &now,
		LastLoginAt: &now,
	}

	router.Get("/users/{username}", func(w http.ResponseWriter, r *http.Request) {
		// Assert
		usernameParam := chi.URLParam(r, "username")
		assert.Equal(t, usernameParam, username)

		// Respond
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(expectedResponse)
	})

	// Act
	actual, err := userService.Get(username)

	// Assert
	assert.OK(t, err)
	assert.Equal(t, actual, expectedResponse)
}

func TestGetUser_NotFound(t *testing.T) {

	// Arrange
	router, opts, cleanup := setup()
	defer cleanup()

	userService := newUserService(
		Must(NewClient(opts...)),
	)

	expected := api.ErrUserNotFound

	router.Get("/users/{username}", func(w http.ResponseWriter, r *http.Request) {
		// Respond
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(expected.StatusCode)
		_ = json.NewEncoder(w).Encode(expected)
	})

	// Act
	_, err := userService.Get("dev1")

	// Assert
	assert.Equal(t, err, expected)
}

func TestGetUser_InvalidArgument(t *testing.T) {

	// Arrange
	_, opts, cleanup := setup()
	defer cleanup()

	userService := newUserService(
		Must(NewClient(opts...)),
	)

	// Act
	_, err := userService.Get("invalidname$#@%%")

	// Assert
	assert.Equal(t, err, api.ErrInvalidUsername)
}

func TestGetMyUser(t *testing.T) {

	// Arrange
	router, opts, cleanup := setup()
	defer cleanup()

	userService := newUserService(
		Must(NewClient(opts...)),
	)

	now := time.Now().UTC()
	expected := &api.User{
		AccountID:   uuid.New(),
		Username:    username,
		FullName:    fullName,
		Email:       email,
		CreatedAt:   &now,
		LastLoginAt: &now,
	}

	router.Get("/me/user", func(w http.ResponseWriter, r *http.Request) {
		// Respond
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(expected)
	})

	// Act
	actual, err := userService.Me()

	// Assert
	assert.OK(t, err)
	assert.Equal(t, actual, expected)
}

func TestGetMyUser_NotFound(t *testing.T) {

	// Arrange
	router, opts, cleanup := setup()
	defer cleanup()

	userService := newUserService(
		Must(NewClient(opts...)),
	)

	expected := api.ErrRequestNotAuthenticated

	router.Get("/me/user", func(w http.ResponseWriter, r *http.Request) {
		// Respond
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(expected.StatusCode)
		_ = json.NewEncoder(w).Encode(expected)
	})

	// Act
	_, err := userService.Me()

	// Assert
	assert.Equal(t, err, expected)
}
