package api

import (
	"net/http"
	"time"

	"bitbucket.org/zombiezen/cardcpx/natsort"
	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
)

// Errors
var (
	ErrInvalidSecretID         = errAPI.Code("invalid_secret_id").StatusError("invalid secret id", http.StatusBadRequest)
	ErrInvalidDirID            = errAPI.Code("invalid_dir_id").StatusError("invalid directory id", http.StatusBadRequest)
	ErrAccessRuleAlreadyExists = errAPI.Code("access_rule_already_exists").StatusError("access rule already exists", http.StatusConflict)
	ErrAccessRuleNotFound      = errAPI.Code("access_rule_not_found").StatusError("access rule not found", http.StatusNotFound)
)

// AccessRule defines the permission of an account on
// a directory and its children.
type AccessRule struct {
	Account       *Account   `json:"account"`
	AccountID     *uuid.UUID `json:"account_id"`
	DirID         *uuid.UUID `json:"dir_id"`
	RepoID        *uuid.UUID `json:"repo_id"`
	Permission    Permission `json:"permission"`
	CreatedAt     time.Time  `json:"created_at"`
	LastChangedAt time.Time  `json:"last_changed_at"`
}

// CreateAccessRuleRequest contains the request fields for creating
// an AccessRule.
type CreateAccessRuleRequest struct {
	Permission       Permission                    `json:"permission"`
	EncryptedDirs    []EncryptedNameForNodeRequest `json:"encrypted_dirs"`
	EncryptedSecrets []SecretAccessRequest         `json:"encrypted_secrets"`
}

// Validate validates the request fields.
func (car *CreateAccessRuleRequest) Validate() error {
	for _, encryptedDir := range car.EncryptedDirs {
		err := encryptedDir.Validate()
		if err != nil {
			return err
		}
	}

	for _, encryptedSecret := range car.EncryptedSecrets {
		err := encryptedSecret.Validate()
		if err != nil {
			return err
		}
	}

	return nil
}

// AccessLevel defines the permissions of an account on a directory and is the
// effect of one or more access rules on the directory itself or its parent(s).
type AccessLevel struct {
	Account    *Account   `json:"account"`
	AccountID  *uuid.UUID `json:"account_id"`
	DirID      *uuid.UUID `json:"dir_id"`
	Permission Permission `json:"permission"`
}

// UpdateAccessRuleRequest contains the request fields for updating
// an AccessRule.
type UpdateAccessRuleRequest struct {
	Permission Permission `json:"permission"`
}

// Validate validates the request fields.
func (uar *UpdateAccessRuleRequest) Validate() error {
	return nil
}

// SortAccessLevels sorts a list of AccessLevels first by the permission and then by the account name.
type SortAccessLevels []*AccessLevel

func (s SortAccessLevels) Len() int {
	return len(s)
}
func (s SortAccessLevels) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s SortAccessLevels) Less(i, j int) bool {
	if s[i].Permission > s[j].Permission {
		return true
	}

	if s[i].Permission < s[j].Permission {
		return false
	}

	return natsort.Less(string(s[i].Account.Name), string(s[j].Account.Name))
}

// SortAccessRules makes a list of AccessRules sortable.
// Sort order: Permission (high to low), AccountName (natural)
type SortAccessRules []*AccessRule

func (s SortAccessRules) Len() int {
	return len(s)
}

func (s SortAccessRules) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s SortAccessRules) Less(i, j int) bool {
	if s[i].Permission > s[j].Permission {
		return true
	}
	if s[i].Permission < s[j].Permission {
		return false
	}
	return natsort.Less(string(s[i].Account.Name), string(s[j].Account.Name))
}
