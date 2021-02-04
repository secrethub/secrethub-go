package api

import (
	"net/http"
	"strings"
	"time"

	"bitbucket.org/zombiezen/cardcpx/natsort"
	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
)

// Errors
var (
	ErrInvalidSecretName = errAPI.Code("invalid_secret_name").StatusError(
		"secret names must be between 1 and 32 characters and "+
			"may only contain letters, numbers, dashes (-), underscores (_), and dots (.)",
		http.StatusBadRequest,
	)

	ErrInvalidSecretVersion = errAPI.Code("invalid_secret_version").StatusError(
		"secret version can only be positive numbers or latest",
		http.StatusBadRequest,
	)

	ErrInvalidNodeID              = errAPI.Code("invalid_node_id").StatusError("the node id is invalid", http.StatusBadRequest)
	ErrInvalidEncryptedSecretName = errAPI.Code("invalid_encrypted_secret_name").StatusError("invalid ciphertext for encrypted secret name", http.StatusBadRequest)
	ErrInvalidSecretBlindName     = errAPI.Code("invalid_secret_blind_name").StatusError("secret blind name is invalid", http.StatusBadRequest)
	ErrInvalidSecretBlob          = errAPI.Code("invalid_secret_blob").StatusError("secret blob is invalid", http.StatusBadRequest)
	ErrNoSecretMembers            = errAPI.Code("no_secret_members").StatusError("no secret members added to write request", http.StatusBadRequest)

	ErrInvalidSecretKeyID              = errAPI.Code("invalid_secret_key_id").StatusError("secret_key_id is invalid", http.StatusBadRequest)
	ErrNotEncryptedForAccounts         = errAPI.Code("not_encrypted_for_accounts").StatusError("missing data encrypted for accounts. This can occur when access rules are simultaneously created with resources controlled by the access rule. You may try again.", http.StatusConflict)
	ErrNotUniquelyEncryptedForAccounts = errAPI.Code("not_uniquely_encrypted_for_accounts").StatusError("not uniquely encrypted for accounts", http.StatusBadRequest)

	ErrCannotDeleteLastSecretVersion = errAPI.Code("cannot_delete_last_version").StatusError("Cannot delete the last version of a secret", http.StatusForbidden)
)

// EncryptedSecret represents an encrypted Secret
// It does not contain the encrypted data. Only the encrypted name.
type EncryptedSecret struct {
	SecretID      uuid.UUID            `json:"secret_id"`
	DirID         uuid.UUID            `json:"dir_id"`
	RepoID        uuid.UUID            `json:"repo_id"`
	EncryptedName crypto.CiphertextRSA `json:"encrypted_name"`
	BlindName     string               `json:"blind_name"`
	VersionCount  int                  `json:"version_count"`
	LatestVersion int                  `json:"latest_version"`
	Status        string               `json:"status"`
	CreatedAt     time.Time            `json:"created_at"`
}

// Decrypt decrypts an EncryptedSecret into a Secret.
func (es *EncryptedSecret) Decrypt(accountKey *crypto.RSAPrivateKey) (*Secret, error) {
	name, err := accountKey.Unwrap(es.EncryptedName)
	if err != nil {
		return nil, errio.Error(err)
	}

	return &Secret{
		SecretID:      es.SecretID,
		DirID:         es.DirID,
		RepoID:        es.RepoID,
		BlindName:     es.BlindName,
		Name:          string(name),
		VersionCount:  es.VersionCount,
		LatestVersion: es.LatestVersion,
		Status:        es.Status,
		CreatedAt:     es.CreatedAt,
	}, nil
}

// Secret represents a decrypted secret in SecretHub.
type Secret struct {
	SecretID      uuid.UUID `json:"secret_id"`
	DirID         uuid.UUID `json:"dir_id"`
	RepoID        uuid.UUID `json:"repo_id"`
	Name          string    `json:"name"`
	BlindName     string    `json:"blind_name"`
	VersionCount  int       `json:"version_count"`
	LatestVersion int       `json:"latest_version"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
}

// HasName returns true when the secret version has the exact name.
func (s *Secret) HasName(name string) bool {
	return strings.EqualFold(s.Name, name)
}

// CreateSecretRequest contains the request fields for creating a new secret,
// together with its first version, encrypted for accounts that need access.
type CreateSecretRequest struct {
	BlindName     string               `json:"blind_name"`
	EncryptedData crypto.CiphertextAES `json:"encrypted_data"`

	EncryptedNames []EncryptedNameRequest `json:"encrypted_names"`
	EncryptedKeys  []EncryptedKeyRequest  `json:"encrypted_keys"`
}

// Validate validates the request fields.
func (csr *CreateSecretRequest) Validate() error {
	err := ValidateBlindName(csr.BlindName)
	if err != nil {
		return ErrInvalidSecretBlindName
	}

	if len(csr.EncryptedNames) < 1 {
		return ErrNotEncryptedForAccounts
	}

	// Used to check if every account has an EncryptedName and an EncryptedKey and is Unique
	accounts := make(map[uuid.UUID]int)
	unique := make(map[uuid.UUID]int)
	for _, encryptedName := range csr.EncryptedNames {
		err = encryptedName.Validate()
		if err != nil {
			return err
		}

		accounts[encryptedName.AccountID]++
		unique[encryptedName.AccountID]++
	}

	for _, count := range unique {
		if count != 1 {
			return ErrNotUniquelyEncryptedForAccounts
		}
	}

	if len(csr.EncryptedKeys) < 1 {
		return ErrNotEncryptedForAccounts
	}

	unique = make(map[uuid.UUID]int)
	for _, encryptedKey := range csr.EncryptedKeys {
		err = encryptedKey.Validate()
		if err != nil {
			return err
		}

		accounts[encryptedKey.AccountID]--
		unique[encryptedKey.AccountID]++
	}

	for _, count := range unique {
		if count != 1 {
			return ErrNotUniquelyEncryptedForAccounts
		}
	}

	for _, count := range accounts {
		if count != 0 {
			return ErrNotEncryptedForAccounts
		}
	}

	return nil
}

// SortSecretByName makes a list of Secret sortable.
type SortSecretByName []*Secret

func (s SortSecretByName) Len() int {
	return len(s)
}
func (s SortSecretByName) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s SortSecretByName) Less(i, j int) bool {
	return natsort.Less(s[i].Name, s[j].Name)
}

// SecretAccessRequest contains the request fields to grant an account access to a secret.
type SecretAccessRequest struct {
	Name EncryptedNameForNodeRequest `json:"name_member"`
	Keys []SecretKeyMemberRequest    `json:"keys"`
}

// Validate validates the request fields.
func (r *SecretAccessRequest) Validate() error {
	err := r.Name.Validate()
	if err != nil {
		return errio.Error(err)
	}

	for _, key := range r.Keys {
		err := key.Validate()
		if err != nil {
			return err
		}
	}

	accountID := r.Name.AccountID
	for _, key := range r.Keys {
		if !uuid.Equal(key.AccountID, accountID) {
			return ErrInvalidAccountID
		}
	}

	return nil
}

// SecretKeyMemberRequest contains the request fields to grant access to a secret key.
type SecretKeyMemberRequest struct {
	AccountID    uuid.UUID            `json:"account_id"`
	SecretKeyID  uuid.UUID            `json:"secret_key_id"`
	EncryptedKey crypto.CiphertextRSA `json:"encrypted_key"`
}

// Validate validates the request fields.
func (skmr *SecretKeyMemberRequest) Validate() error {
	if skmr.AccountID.IsZero() {
		return ErrInvalidAccountID
	}

	if skmr.SecretKeyID.IsZero() {
		return ErrInvalidKeyID
	}

	return nil
}
