package api

import (
	"fmt"
	"time"

	"net/http"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/errio"
)

// Errors
var (
	errAPI = errio.Namespace("api")

	ErrInvalidUsername = errAPI.Code("invalid_username").StatusError(
		"usernames must be between 3 and 32 characters long and "+
			"may only contain letters, numbers, dashes (-), underscores (_), and dots (.)",
		http.StatusBadRequest,
	)
	ErrUsernameMustContainAlphanumeric = errAPI.Code("username_must_contain_alphanumeric").StatusError(
		"usernames must contain at least one alphanumeric character ",
		http.StatusBadRequest,
	)
	ErrUsernameIsService = errAPI.Code("username_is_service").StatusError(
		"usernames cannot start with s- as that prefix is reserved for service accounts",
		http.StatusBadRequest,
	)
	ErrInvalidPublicKey = errAPI.Code("invalid_public_key").StatusError("public key is invalid", http.StatusBadRequest)
	ErrInvalidEmail     = errAPI.Code("invalid_email").StatusError("email address is invalid", http.StatusBadRequest)
	ErrInvalidFullName  = errAPI.Code("invalid_full_name").StatusError(
		"full names may be at most 128 characters long and "+
			"may only contain (special) letters, apostrophes ('), spaces and dashes (-)",
		http.StatusBadRequest,
	)
	ErrNoPasswordNorCredential     = errAPI.Code("no_password_nor_credential").StatusError("either a password or a credential should be supplied", http.StatusBadRequest)
	ErrTooManyVerificationRequests = errAPI.Code("too_many_verification_requests").StatusError("another verification email was requested recently, please wait a few minutes before trying again", http.StatusTooManyRequests)
)

// User represents a SecretHub user.
type User struct {
	AccountID     uuid.UUID  `json:"account_id"`
	PublicKey     []byte     `json:"public_key"`
	Username      string     `json:"username"`
	FullName      string     `json:"full_name"`
	Email         string     `json:"user_email,omitempty"`     // Optional, private information is only returned for yourself
	EmailVerified bool       `json:"email_verified,omitempty"` // Optional, private information is only returned for yourself
	CreatedAt     *time.Time `json:"created_at,omitempty"`     // Optional, private information is only returned for yourself
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`  // Optional, private information is only returned for yourself
}

// PrettyName returns a printable string with the username and full name.
func (u User) PrettyName() string {
	if u.FullName == "" {
		return u.Username
	}
	return fmt.Sprintf("%s (%s)", u.Username, u.FullName)
}

// Trim removes all non-essential fields from User for output
func (u User) Trim() *User {
	return &User{
		AccountID: u.AccountID,
		Username:  u.Username,
		FullName:  u.FullName,
		PublicKey: u.PublicKey,
	}
}

// ToAuditSubject converts a User to an AuditSubject
func (u User) ToAuditSubject() *AuditSubject {
	return &AuditSubject{
		SubjectID: u.AccountID,
		Type:      AuditSubjectUser,
		User:      u.Trim(),
	}
}

// ToAuditActor converts a User to an AuditActor
func (u User) ToAuditActor() *AuditActor {
	return &AuditActor{
		ActorID: u.AccountID,
		Type:    "user",
		User:    u.Trim(),
	}
}
