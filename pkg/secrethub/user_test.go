package secrethub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
	routing "github.com/keylockerbv/secrethub/core/router"

	"github.com/keylockerbv/secrethub-go/pkg/crypto"
	"github.com/keylockerbv/secrethub/testutil"
)

func TestSignup(t *testing.T) {
	testutil.Component(t)

	// Arrange
	router, opts, cleanup := setup()
	defer cleanup()

	client, err := NewClient(cred1, opts)
	testutil.OK(t, err)

	username := "dev1"
	fullName := "Developer Uno"
	email := "dev1@testing.com"

	expectedCreateUserRequest := api.CreateUserRequest{
		Username: username,
		FullName: fullName,
		Email:    email,
		Credential: &api.CreateCredentialRequest{
			Type:        api.CredentialTypeRSA,
			Fingerprint: cred1AuthID,
			Verifier:    cred1AuthData,
		},
	}

	now := time.Now().UTC()
	expectedResponse := &api.User{
		AccountID:   uuid.New(),
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
		testutil.OK(t, err)

		testutil.OK(t, req.Validate())

		testutil.Compare(t, req, expectedCreateUserRequest)

		// Respond
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(expectedResponse)
	})

	accountKey, err := crypto.GenerateRSAKey(512)
	testutil.OK(t, err)

	publicAccountKey, err := accountKey.ExportPublicKey()
	testutil.OK(t, err)

	router.Post(fmt.Sprintf("/me/credentials/%s/key", cred1AuthID), func(w http.ResponseWriter, r *http.Request) {
		// Assert
		req := new(api.CreateAccountKeyRequest)
		err := json.NewDecoder(r.Body).Decode(&req)
		testutil.OK(t, err)

		testutil.OK(t, req.Validate())

		// We cannot predict the output of the encrypted key, therefore we do not test it here.
		testutil.Compare(t, req.PublicKey, publicAccountKey)

		// Respond
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(expectedResponse)
	})

	// Act
	actual, err := client.SignupUser(username, email, fullName, accountKey)

	// Assert
	testutil.OK(t, err)
	testutil.Compare(t, actual, expectedResponse)
}

func TestSignup_AlreadyExists(t *testing.T) {
	testutil.Component(t)

	// Arrange
	router, opts, cleanup := setup()
	defer cleanup()

	client, err := NewClient(cred1, opts)
	testutil.OK(t, err)

	expected := api.ErrUserEmailAlreadyExists

	router.Post("/users", func(w http.ResponseWriter, r *http.Request) {
		// Respond
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(expected.StatusCode)
		_ = json.NewEncoder(w).Encode(expected)
	})

	key, err := crypto.GenerateRSAKey(512)
	testutil.OK(t, err)

	// Act
	_, err = client.SignupUser("dev1", "dev1@testing.com", "Developer Uno", key)

	// Assert
	testutil.Compare(t, err, expected)
}

func TestSignup_InvalidArgument(t *testing.T) {
	testutil.Component(t)

	// Arrange
	_, opts, cleanup := setup()
	defer cleanup()

	client, err := NewClient(cred1, opts)
	testutil.OK(t, err)

	key, err := crypto.GenerateRSAKey(512)
	testutil.OK(t, err)

	// Act
	_, err = client.SignupUser("invalidname$#@%%", "dev1@testing.com", "Developer Uno", key)

	// Assert
	testutil.Compare(t, err, api.ErrInvalidUsername)
}

func TestGetUser(t *testing.T) {
	testutil.Component(t)

	// Arrange
	router, opts, cleanup := setup()
	defer cleanup()

	client, err := NewClient(cred1, opts)
	testutil.OK(t, err)

	username := "dev1"
	fullName := "Developer Uno"
	email := "dev1@testing.com"

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
		usernameParam := routing.URLParam(r, "username")
		testutil.Compare(t, usernameParam, username)

		// Respond
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(expectedResponse)
	})

	// Act
	actual, err := client.GetUser(username)

	// Assert
	testutil.OK(t, err)
	testutil.Compare(t, actual, expectedResponse)
}

func TestGetUser_NotFound(t *testing.T) {
	testutil.Component(t)

	// Arrange
	router, opts, cleanup := setup()
	defer cleanup()

	client, err := NewClient(cred1, opts)
	testutil.OK(t, err)

	expected := api.ErrUserNotFound

	router.Get("/users/{username}", func(w http.ResponseWriter, r *http.Request) {
		// Respond
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(expected.StatusCode)
		_ = json.NewEncoder(w).Encode(expected)
	})

	// Act
	_, err = client.GetUser("dev1")

	// Assert
	testutil.Compare(t, err, expected)
}

func TestGetUser_InvalidArgument(t *testing.T) {
	testutil.Component(t)

	// Arrange
	_, opts, cleanup := setup()
	defer cleanup()

	client, err := NewClient(cred1, opts)
	testutil.OK(t, err)

	// Act
	_, err = client.GetUser("invalidname$#@%%")

	// Assert
	testutil.Compare(t, err, api.ErrInvalidUsername)
}

func TestGetMyUser(t *testing.T) {
	testutil.Component(t)

	// Arrange
	router, opts, cleanup := setup()
	defer cleanup()

	client, err := NewClient(cred1, opts)
	testutil.OK(t, err)

	username := "dev1"
	fullName := "Developer Uno"
	email := "dev1@testing.com"

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
	actual, err := client.GetMyUser()

	// Assert
	testutil.OK(t, err)
	testutil.Compare(t, actual, expected)
}

func TestGetMyUser_NotFound(t *testing.T) {
	testutil.Component(t)

	// Arrange
	router, opts, cleanup := setup()
	defer cleanup()

	client, err := NewClient(cred1, opts)
	testutil.OK(t, err)

	expected := api.ErrRequestNotAuthenticated

	router.Get("/me/user", func(w http.ResponseWriter, r *http.Request) {
		// Respond
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(expected.StatusCode)
		_ = json.NewEncoder(w).Encode(expected)
	})

	// Act
	_, err = client.GetMyUser()

	// Assert
	testutil.Compare(t, err, expected)
}
