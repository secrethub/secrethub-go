package api

import (
	"time"

	"strings"

	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
)

// Errors
var (
	ErrInvalidAccountName = errAPI.Code("invalid_account_name").Error("An account name either needs to be an username or a servicename")
	ErrInvalidKeyID       = errAPI.Code("invalid_key_id").Error("id of the provided account key is invalid")
	ErrInvalidMetadata    = errAPI.Code("invalid_metadata").Error("metadata of encrypted key is invalid")

	ServiceNamePrefix = "s-"
)

// Account represents an account on SecretHub.
type Account struct {
	AccountID   *uuid.UUID  `json:"account_id"`
	Name        AccountName `json:"name"`
	PublicKey   []byte      `json:"public_key"`
	AccountType string      `json:"account_type"`
	CreatedAt   time.Time   `json:"created_at"`
}

// AccountName represents the name of either a user or a service.
type AccountName string

// NewAccountName validates an accounts name and returns it as a typed AccountName when valid.
func NewAccountName(name string) (AccountName, error) {
	err := ValidateAccountName(name)
	if err != nil {
		return "", err
	}
	return AccountName(name), err
}

// IsService returns true if the AccountName contains the name of a service.
func (n AccountName) IsService() bool {
	return strings.HasPrefix(strings.ToLower(string(n)), ServiceNamePrefix)
}

// IsUser returns true if the AccountName contains the name of a user.
func (n AccountName) IsUser() bool {
	return !n.IsService()
}

// Validate checks whether an AccountName is valid.
func (n AccountName) Validate() error {
	return ValidateAccountName(string(n))
}

// Set sets the AccountName to the value.
func (n *AccountName) Set(value string) error {
	accountName, err := NewAccountName(value)
	if err != nil {
		return err
	}
	*n = accountName
	return nil
}

// String returns the AccountName as a string.
func (n AccountName) String() string {
	return string(n)
}
